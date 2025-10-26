"""Rule-based detection engine: the ``Alert`` record, the ``Rule`` protocol, the
``run_rules`` driver, and the shared primitives (IP classification + windowing)
that concrete rules build on.

Everything here reads ONLY real event fields. The ground-truth label fields
(``scenario`` / ``technique_id`` on :class:`~sentinel.events.Event`) are never
consulted — that separation is enforced by convention and is the whole point of
the project. Only the evaluation module is allowed to read those labels.
"""

from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from sentinel.attack import get_technique
from sentinel.events import Event

# ---------------------------------------------------------------------------
# IP classification (RFC 1918 private ranges are "internal", everything else
# routable is "external").
# ---------------------------------------------------------------------------


def is_internal_ip(ip: str) -> bool:
    """True for RFC 1918 private addresses: 10/8, 172.16/12, 192.168/16."""
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def is_external_ip(ip: str) -> bool:
    """True for a non-empty address that is not in an RFC 1918 private range."""
    return bool(ip) and not is_internal_ip(ip)


# ---------------------------------------------------------------------------
# Alert record.
# ---------------------------------------------------------------------------


@dataclass
class Alert:
    """A single detection: which rule fired, on what entity, over which events."""

    ts: datetime
    rule_id: str
    title: str
    severity: str  # low | medium | high | critical
    technique_id: str
    tactic: str  # get_technique(technique_id).tactics[0]
    entity: str  # the user / host / ip the alert is about
    events: list[Event] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """JSON-safe view that also resolves the real ATT&CK technique name.

        Triggering events are summarized without their label fields so that a
        serialized alert never carries ground truth.
        """
        technique = get_technique(self.technique_id)
        return {
            "ts": self.ts.isoformat(),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "technique_id": self.technique_id,
            "technique_name": technique.name,
            "technique_url": technique.url,
            "tactic": self.tactic,
            "entity": self.entity,
            "event_count": len(self.events),
            "first_ts": self.events[0].ts.isoformat() if self.events else self.ts.isoformat(),
            "last_ts": self.events[-1].ts.isoformat() if self.events else self.ts.isoformat(),
            "events": [_event_summary(e) for e in self.events],
        }


def _event_summary(e: Event) -> dict[str, object]:
    """Compact, label-free view of a triggering event for JSON output."""
    return {
        "ts": e.ts.isoformat(),
        "event_type": str(e.event_type),
        "host": e.host,
        "user": e.user,
        "source_ip": e.source_ip,
        "action": e.action,
        "process": e.process,
        "command_line": e.command_line,
        "parent_process": e.parent_process,
        "dest_ip": e.dest_ip,
        "dest_port": e.dest_port,
        "bytes_out": e.bytes_out,
    }


# ---------------------------------------------------------------------------
# Rule protocol + driver.
# ---------------------------------------------------------------------------


@runtime_checkable
class Rule(Protocol):
    """A detection rule: identity metadata plus a pure ``detect`` function."""

    id: str
    title: str
    severity: str
    technique_id: str

    def detect(self, events: list[Event]) -> list[Alert]: ...


def run_rules(events: list[Event], rules: list[Rule] | None = None) -> list[Alert]:
    """Run every rule over ``events`` and return all alerts, sorted by time.

    ``rules`` defaults to :data:`sentinel.rules.RULES` (imported lazily to avoid
    a circular import, since rules depend on this module's primitives).
    """
    if rules is None:
        from sentinel.rules import RULES

        rules = RULES
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(rule.detect(events))
    alerts.sort(key=lambda a: a.ts)
    return alerts


# ---------------------------------------------------------------------------
# Windowing / grouping primitives used by rules.
# ---------------------------------------------------------------------------


def tactic_for(technique_id: str) -> str:
    """The primary ATT&CK tactic for a technique (empty if it has none)."""
    tactics = get_technique(technique_id).tactics
    return tactics[0] if tactics else ""


def group_by[K: Hashable](events: list[Event], key: Callable[[Event], K]) -> dict[K, list[Event]]:
    """Bucket events by an arbitrary key, preserving input order within a bucket."""
    groups: dict[K, list[Event]] = {}
    for e in events:
        groups.setdefault(key(e), []).append(e)
    return groups


def session_windows(events: list[Event], max_gap: timedelta) -> Iterator[list[Event]]:
    """Split time-sorted events into session windows.

    A gap larger than ``max_gap`` between two consecutive events starts a new
    window. This is the standard SIEM "session window" — it groups a burst of
    related activity (a flurry of failed logins, a recon spray) while keeping
    unrelated background activity in separate windows.
    """
    ordered = sorted(events, key=lambda e: e.ts)
    window: list[Event] = []
    for e in ordered:
        if window and e.ts - window[-1].ts > max_gap:
            yield window
            window = []
        window.append(e)
    if window:
        yield window
