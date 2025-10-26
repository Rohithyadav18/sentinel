"""Deterministic synthetic security-log generator with planted attack scenarios.

Honest about being synthetic: it produces a realistic mix of benign auth /
process / network events plus a handful of labeled attack scenarios, each mapped
to a real MITRE ATT&CK technique. Because every malicious event is labeled
(``scenario`` / ``technique_id``), detection quality can be *measured* against
ground truth rather than asserted. Detectors must ignore those label fields.
"""

import random
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sentinel.events import Event, EventType

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
HOSTS = ["ws-01", "ws-02", "ws-03", "srv-app", "srv-db", "srv-dc"]
INTERNAL_PREFIX = "10.0.0."
BENIGN_PROCESSES = ["explorer.exe", "chrome.exe", "code.exe", "outlook.exe", "python.exe"]


@dataclass
class GenConfig:
    days: int = 3
    seed: int = 0
    benign_per_hour: int = 40


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _benign(rng: random.Random, ts: datetime) -> Event:
    kind = rng.choices(
        [EventType.AUTH, EventType.PROCESS, EventType.NETWORK], weights=[3, 3, 2]
    )[0]
    user = rng.choice(USERS)
    host = rng.choice(HOSTS)
    if kind is EventType.AUTH:
        # Mostly successful; the occasional benign typo failure.
        action = "login_success" if rng.random() > 0.08 else "login_failure"
        return Event(
            ts=ts, event_type=kind, host=host, user=user,
            source_ip=f"{INTERNAL_PREFIX}{rng.randint(10, 60)}", action=action,
        )
    if kind is EventType.PROCESS:
        proc = rng.choice(BENIGN_PROCESSES)
        return Event(
            ts=ts, event_type=kind, host=host, user=user,
            process=proc, parent_process="explorer.exe",
            command_line=proc,
        )
    return Event(
        ts=ts, event_type=kind, host=host, user=user,
        dest_ip=f"{INTERNAL_PREFIX}{rng.randint(10, 60)}", dest_port=rng.choice([80, 443, 445]),
        bytes_out=rng.randint(200, 50_000),
    )


def _brute_force(rng: random.Random, ts: datetime) -> list[Event]:
    """T1110: many rapid failures from one external IP, then a success."""
    ip = f"203.0.113.{rng.randint(2, 254)}"
    target = rng.choice(USERS)
    host = "srv-dc"
    evs = []
    for i in range(rng.randint(20, 40)):
        evs.append(Event(
            ts=ts + timedelta(seconds=i * 3), event_type=EventType.AUTH, host=host,
            user=target, source_ip=ip, action="login_failure",
            scenario="brute_force", technique_id="T1110",
        ))
    evs.append(Event(
        ts=ts + timedelta(seconds=len(evs) * 3), event_type=EventType.AUTH, host=host,
        user=target, source_ip=ip, action="login_success",
        scenario="brute_force", technique_id="T1110",
    ))
    return evs


def _lateral_movement(rng: random.Random, ts: datetime) -> list[Event]:
    """T1021: one user authenticating to many hosts via remote services fast."""
    user = rng.choice(USERS)
    ip = f"{INTERNAL_PREFIX}{rng.randint(10, 60)}"
    evs = []
    for i, host in enumerate(rng.sample(HOSTS, k=5)):
        evs.append(Event(
            ts=ts + timedelta(seconds=i * 20), event_type=EventType.AUTH, host=host,
            user=user, source_ip=ip, action="login_success",
            scenario="lateral_movement", technique_id="T1021",
        ))
    return evs


def _suspicious_process(rng: random.Random, ts: datetime) -> list[Event]:
    """T1059: encoded PowerShell spawned by an office app (living-off-the-land)."""
    user = rng.choice(USERS)
    host = rng.choice(HOSTS)
    return [Event(
        ts=ts, event_type=EventType.PROCESS, host=host, user=user,
        process="powershell.exe", parent_process="winword.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKA==",
        scenario="suspicious_process", technique_id="T1059.001",
    )]


def _discovery(rng: random.Random, ts: datetime) -> list[Event]:
    """T1087/T1018: a burst of recon commands on one host."""
    user = rng.choice(USERS)
    host = rng.choice(HOSTS)
    cmds = [
        "whoami /all",
        "net user /domain",
        'net group "domain admins" /domain',
        "nltest /dclist:",
    ]
    return [Event(
        ts=ts + timedelta(seconds=i * 5), event_type=EventType.PROCESS, host=host, user=user,
        process="cmd.exe", parent_process="cmd.exe", command_line=c,
        scenario="discovery", technique_id="T1087",
    ) for i, c in enumerate(cmds)]


def _exfiltration(rng: random.Random, ts: datetime) -> list[Event]:
    """T1048: a large outbound transfer to an external IP."""
    user = rng.choice(USERS)
    host = rng.choice(HOSTS)
    ext_ip = f"198.51.100.{rng.randint(2, 254)}"
    return [Event(
        ts=ts + timedelta(seconds=i * 2), event_type=EventType.NETWORK, host=host, user=user,
        dest_ip=ext_ip, dest_port=443, bytes_out=rng.randint(50_000_000, 200_000_000),
        scenario="exfiltration", technique_id="T1048",
    ) for i in range(rng.randint(3, 6))]


_SCENARIOS = [_brute_force, _lateral_movement, _suspicious_process, _discovery, _exfiltration]


def generate(config: GenConfig) -> list[Event]:
    """Generate a labeled event stream: benign background + planted attacks."""
    rng = _rng(config.seed)
    start = datetime(2024, 6, 1, tzinfo=UTC)
    events: list[Event] = []

    total_hours = config.days * 24
    for hour in range(total_hours):
        base = start + timedelta(hours=hour)
        for _ in range(config.benign_per_hour):
            offset = timedelta(seconds=rng.randint(0, 3599))
            events.append(_benign(rng, base + offset))

    # Inject each scenario a few times at random hours (business-ish hours).
    for scenario in _SCENARIOS:
        for _ in range(rng.randint(2, 4)):
            hour = rng.randint(0, total_hours - 1)
            at = start + timedelta(hours=hour, seconds=rng.randint(0, 3599))
            events.extend(scenario(rng, at))

    events.sort(key=lambda e: e.ts)
    return events


def iter_benign_and_attack(events: list[Event]) -> Iterator[tuple[bool, Event]]:
    for e in events:
        yield (bool(e.scenario), e)
