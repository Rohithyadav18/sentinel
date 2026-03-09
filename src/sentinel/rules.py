"""Concrete detection rules — one (or more) per planted attack scenario, each
citing a real MITRE ATT&CK technique.

Every rule reads ONLY real event fields (never ``scenario`` / ``technique_id``)
and relies on the windowing / IP primitives in :mod:`sentinel.detect`.
"""

from datetime import timedelta

from sentinel.detect import (
    Alert,
    Rule,
    group_by,
    is_external_ip,
    session_windows,
    tactic_for,
)
from sentinel.events import Event, EventType

# Command-line substrings that mark encoded / hidden / download-and-run
# PowerShell — classic living-off-the-land execution.
_SUSPICIOUS_CMDLINE = (
    "-enc",
    "-encodedcommand",
    "-e ",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-noprofile",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "-bypass",
    "executionpolicy bypass",
)

# Interactive shells worth scrutinizing.
_SUSPICIOUS_SHELLS = ("powershell.exe", "powershell", "pwsh.exe", "pwsh")

# Office / scripting hosts that should almost never spawn a shell.
_OFFICE_PARENTS = (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
)

# Account / host / domain reconnaissance commands (ATT&CK discovery tactic).
_RECON_MARKERS = (
    "whoami",
    "net user",
    "net group",
    "net localgroup",
    "net accounts",
    "net view",
    "nltest",
    "dsquery",
    "systeminfo",
    "ipconfig /all",
    "arp -a",
    "quser",
    "klist",
)


def _cmdline_is_suspicious(command_line: str) -> bool:
    cl = command_line.lower()
    return any(marker in cl for marker in _SUSPICIOUS_CMDLINE)


def _is_recon(command_line: str) -> bool:
    cl = command_line.lower()
    return any(marker in cl for marker in _RECON_MARKERS)


class BruteForceRule:
    """T1110 Brute Force: many failed logins for one (user, source_ip) inside a
    window; escalates to critical if a success lands in the same burst."""

    id = "R-BRUTE-FORCE"
    title = "Password brute-force against a single account"
    severity = "high"
    technique_id = "T1110"

    def __init__(self, min_failures: int = 10, window: timedelta = timedelta(minutes=5)) -> None:
        self.min_failures = min_failures
        self.window = window

    def detect(self, events: list[Event]) -> list[Alert]:
        auth = [
            e
            for e in events
            if e.event_type is EventType.AUTH and e.action in ("login_failure", "login_success")
        ]
        alerts: list[Alert] = []
        for (user, src), group in group_by(auth, lambda e: (e.user, e.source_ip)).items():
            for window in session_windows(group, self.window):
                failures = [e for e in window if e.action == "login_failure"]
                if len(failures) < self.min_failures:
                    continue
                success = next((e for e in window if e.action == "login_success"), None)
                triggering = failures + ([success] if success is not None else [])
                triggering.sort(key=lambda e: e.ts)
                alerts.append(
                    Alert(
                        ts=triggering[0].ts,
                        rule_id=self.id,
                        title=self.title,
                        severity="critical" if success is not None else self.severity,
                        technique_id=self.technique_id,
                        tactic=tactic_for(self.technique_id),
                        entity=f"{user}@{src}",
                        events=triggering,
                    )
                )
        return alerts


class LateralMovementRule:
    """T1021 Remote Services: one user authenticating successfully to many
    distinct hosts inside a short window."""

    id = "R-LATERAL-MOVEMENT"
    title = "User authenticating to many hosts in a short window"
    severity = "high"
    technique_id = "T1021"

    def __init__(self, min_hosts: int = 5, window: timedelta = timedelta(minutes=5)) -> None:
        self.min_hosts = min_hosts
        self.window = window

    def detect(self, events: list[Event]) -> list[Alert]:
        successes = [
            e
            for e in events
            if e.event_type is EventType.AUTH and e.action == "login_success"
        ]
        alerts: list[Alert] = []
        for user, group in group_by(successes, lambda e: e.user).items():
            for window in session_windows(group, self.window):
                hosts = {e.host for e in window}
                if len(hosts) < self.min_hosts:
                    continue
                ordered = sorted(window, key=lambda e: e.ts)
                alerts.append(
                    Alert(
                        ts=ordered[0].ts,
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        technique_id=self.technique_id,
                        tactic=tactic_for(self.technique_id),
                        entity=str(user),
                        events=ordered,
                    )
                )
        return alerts


class SuspiciousProcessRule:
    """T1059.001 PowerShell: an interactive shell launched with encoded / hidden
    flags, or any shell spawned by an office / scripting host."""

    id = "R-SUSPICIOUS-PROCESS"
    title = "Encoded/hidden PowerShell or office-app-spawned shell"
    severity = "high"
    technique_id = "T1059.001"

    def detect(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for e in events:
            if e.event_type is not EventType.PROCESS:
                continue
            proc = e.process.lower()
            parent = e.parent_process.lower()
            shell_encoded = proc in _SUSPICIOUS_SHELLS and _cmdline_is_suspicious(e.command_line)
            office_spawned = parent in _OFFICE_PARENTS and proc not in _OFFICE_PARENTS
            if not (shell_encoded or office_spawned):
                continue
            alerts.append(
                Alert(
                    ts=e.ts,
                    rule_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    technique_id=self.technique_id,
                    tactic=tactic_for(self.technique_id),
                    entity=f"{e.user}@{e.host}",
                    events=[e],
                )
            )
        return alerts


class DiscoveryRule:
    """T1087 Account Discovery: a burst of account / host recon commands on one
    host inside a window."""

    id = "R-DISCOVERY"
    title = "Reconnaissance command burst on a single host"
    severity = "medium"
    technique_id = "T1087"

    def __init__(self, min_commands: int = 3, window: timedelta = timedelta(minutes=5)) -> None:
        self.min_commands = min_commands
        self.window = window

    def detect(self, events: list[Event]) -> list[Alert]:
        recon = [
            e
            for e in events
            if e.event_type is EventType.PROCESS and _is_recon(e.command_line)
        ]
        alerts: list[Alert] = []
        for host, group in group_by(recon, lambda e: e.host).items():
            for window in session_windows(group, self.window):
                if len(window) < self.min_commands:
                    continue
                ordered = sorted(window, key=lambda e: e.ts)
                users = {e.user for e in ordered}
                entity = f"{next(iter(users))}@{host}" if len(users) == 1 else str(host)
                alerts.append(
                    Alert(
                        ts=ordered[0].ts,
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        technique_id=self.technique_id,
                        tactic=tactic_for(self.technique_id),
                        entity=entity,
                        events=ordered,
                    )
                )
        return alerts


class ExfiltrationRule:
    """T1048 Exfiltration Over Alternative Protocol: large outbound volume to an
    EXTERNAL destination, summed per (host, dest_ip) inside a window."""

    id = "R-EXFILTRATION"
    title = "Large outbound transfer to an external destination"
    severity = "high"
    technique_id = "T1048"

    def __init__(
        self, min_bytes: int = 10_000_000, window: timedelta = timedelta(minutes=10)
    ) -> None:
        self.min_bytes = min_bytes
        self.window = window

    def detect(self, events: list[Event]) -> list[Alert]:
        outbound = [
            e
            for e in events
            if e.event_type is EventType.NETWORK and is_external_ip(e.dest_ip)
        ]
        alerts: list[Alert] = []
        for (host, dst), group in group_by(outbound, lambda e: (e.host, e.dest_ip)).items():
            for window in session_windows(group, self.window):
                total = sum(e.bytes_out for e in window)
                if total < self.min_bytes:
                    continue
                ordered = sorted(window, key=lambda e: e.ts)
                alerts.append(
                    Alert(
                        ts=ordered[0].ts,
                        rule_id=self.id,
                        title=self.title,
                        severity="critical" if total >= 100_000_000 else self.severity,
                        technique_id=self.technique_id,
                        tactic=tactic_for(self.technique_id),
                        entity=f"{host}->{dst}",
                        events=ordered,
                    )
                )
        return alerts


RULES: list[Rule] = [
    BruteForceRule(),
    LateralMovementRule(),
    SuspiciousProcessRule(),
    DiscoveryRule(),
    ExfiltrationRule(),
]
