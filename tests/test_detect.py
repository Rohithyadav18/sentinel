"""Tests for the rule-based detection engine and the concrete rules.

These verify: IP classification, windowing, the Alert record, that each rule
fires on its own scenario, that a purely benign stream stays quiet, and that
alerts carry a resolvable ATT&CK technique + tactic. Rules never read the label
fields, so tests build inputs from real event fields only.
"""

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.attack import get_technique
from sentinel.detect import (
    Alert,
    Rule,
    is_external_ip,
    is_internal_ip,
    run_rules,
    session_windows,
    tactic_for,
)
from sentinel.events import Event, EventType
from sentinel.generator import GenConfig, generate
from sentinel.rules import (
    RULES,
    BruteForceRule,
    DiscoveryRule,
    ExfiltrationRule,
    LateralMovementRule,
    SuspiciousProcessRule,
)

BASE = datetime(2024, 6, 1, 9, 0, tzinfo=UTC)


def at(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# IP classification.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.5", "10.255.1.1", "192.168.1.10", "172.16.0.1", "172.31.255.254", "172.20.5.5"],
)
def test_internal_ips(ip: str) -> None:
    assert is_internal_ip(ip)
    assert not is_external_ip(ip)


@pytest.mark.parametrize(
    "ip",
    ["203.0.113.7", "198.51.100.4", "8.8.8.8", "172.15.0.1", "172.32.0.1", "11.0.0.1"],
)
def test_external_ips(ip: str) -> None:
    assert is_external_ip(ip)
    assert not is_internal_ip(ip)


def test_empty_ip_is_neither() -> None:
    assert not is_internal_ip("")
    assert not is_external_ip("")


# ---------------------------------------------------------------------------
# Windowing.
# ---------------------------------------------------------------------------


def test_session_windows_splits_on_gap() -> None:
    events = [
        Event(ts=at(0), event_type=EventType.AUTH, host="h", user="u"),
        Event(ts=at(10), event_type=EventType.AUTH, host="h", user="u"),
        # gap of 10 minutes -> new window
        Event(ts=at(700), event_type=EventType.AUTH, host="h", user="u"),
    ]
    windows = list(session_windows(events, timedelta(minutes=5)))
    assert [len(w) for w in windows] == [2, 1]


def test_session_windows_orders_unsorted_input() -> None:
    events = [
        Event(ts=at(20), event_type=EventType.AUTH, host="h", user="u"),
        Event(ts=at(0), event_type=EventType.AUTH, host="h", user="u"),
    ]
    windows = list(session_windows(events, timedelta(minutes=5)))
    assert len(windows) == 1
    assert [e.ts for e in windows[0]] == [at(0), at(20)]


# ---------------------------------------------------------------------------
# Alert record.
# ---------------------------------------------------------------------------


def test_alert_to_dict_resolves_technique_and_is_label_free() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.AUTH,
        host="srv-dc",
        user="alice",
        source_ip="203.0.113.9",
        action="login_failure",
        scenario="brute_force",  # label present on the source event...
        technique_id="T1110",
    )
    alert = Alert(
        ts=at(0),
        rule_id="R-BRUTE-FORCE",
        title="t",
        severity="high",
        technique_id="T1110",
        tactic="credential-access",
        entity="alice@203.0.113.9",
        events=[ev],
    )
    d = alert.to_dict()
    assert d["technique_name"] == get_technique("T1110").name
    assert d["tactic"] == "credential-access"
    assert d["event_count"] == 1
    # ...but the serialized event must not leak ground-truth labels.
    serialized_events = d["events"]
    assert isinstance(serialized_events, list)
    first_event = serialized_events[0]
    assert "scenario" not in first_event
    assert "technique_id" not in first_event


# ---------------------------------------------------------------------------
# Per-rule: fires on its scenario, silent on benign, correct technique/tactic.
# ---------------------------------------------------------------------------


def _brute_force_events(user: str = "bob", ip: str = "203.0.113.7") -> list[Event]:
    evs = [
        Event(
            ts=at(i * 3),
            event_type=EventType.AUTH,
            host="srv-dc",
            user=user,
            source_ip=ip,
            action="login_failure",
        )
        for i in range(15)
    ]
    evs.append(
        Event(
            ts=at(15 * 3),
            event_type=EventType.AUTH,
            host="srv-dc",
            user=user,
            source_ip=ip,
            action="login_success",
        )
    )
    return evs


def test_brute_force_fires_and_escalates_on_success() -> None:
    alerts = BruteForceRule().detect(_brute_force_events())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.technique_id == "T1110"
    assert a.severity == "critical"  # trailing success escalates
    assert a.entity == "bob@203.0.113.7"


def test_brute_force_below_threshold_is_quiet() -> None:
    evs = [
        Event(
            ts=at(i * 3),
            event_type=EventType.AUTH,
            host="srv-dc",
            user="bob",
            source_ip="203.0.113.7",
            action="login_failure",
        )
        for i in range(5)
    ]
    assert BruteForceRule().detect(evs) == []


def test_brute_force_spread_across_ips_does_not_fire() -> None:
    # Same user, 15 failures but each from a different source IP -> not a burst.
    evs = [
        Event(
            ts=at(i * 3),
            event_type=EventType.AUTH,
            host="srv-dc",
            user="bob",
            source_ip=f"203.0.113.{i}",
            action="login_failure",
        )
        for i in range(15)
    ]
    assert BruteForceRule().detect(evs) == []


def test_lateral_movement_fires_on_five_hosts() -> None:
    evs = [
        Event(
            ts=at(i * 20),
            event_type=EventType.AUTH,
            host=h,
            user="carol",
            source_ip="10.0.0.20",
            action="login_success",
        )
        for i, h in enumerate(["ws-01", "ws-02", "ws-03", "srv-app", "srv-db"])
    ]
    alerts = LateralMovementRule().detect(evs)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1021"
    assert alerts[0].entity == "carol"


def test_lateral_movement_repeat_host_logins_do_not_fire() -> None:
    # Many logins but only two distinct hosts.
    evs = [
        Event(
            ts=at(i * 20),
            event_type=EventType.AUTH,
            host="ws-01" if i % 2 else "ws-02",
            user="carol",
            source_ip="10.0.0.20",
            action="login_success",
        )
        for i in range(10)
    ]
    assert LateralMovementRule().detect(evs) == []


def test_suspicious_process_encoded_powershell() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.PROCESS,
        host="ws-01",
        user="dave",
        process="powershell.exe",
        parent_process="winword.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKA==",
    )
    alerts = SuspiciousProcessRule().detect([ev])
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1059.001"
    assert alerts[0].entity == "dave@ws-01"


def test_suspicious_process_office_spawned_shell() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.PROCESS,
        host="ws-01",
        user="dave",
        process="cmd.exe",
        parent_process="excel.exe",
        command_line="cmd.exe /c dir",
    )
    assert len(SuspiciousProcessRule().detect([ev])) == 1


def test_suspicious_process_benign_is_quiet() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.PROCESS,
        host="ws-01",
        user="dave",
        process="chrome.exe",
        parent_process="explorer.exe",
        command_line="chrome.exe",
    )
    assert SuspiciousProcessRule().detect([ev]) == []


def test_discovery_recon_burst_fires() -> None:
    cmds = [
        "whoami /all",
        "net user /domain",
        'net group "domain admins" /domain',
        "nltest /dclist:",
    ]
    evs = [
        Event(
            ts=at(i * 5),
            event_type=EventType.PROCESS,
            host="ws-02",
            user="erin",
            process="cmd.exe",
            parent_process="cmd.exe",
            command_line=c,
        )
        for i, c in enumerate(cmds)
    ]
    alerts = DiscoveryRule().detect(evs)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1087"
    assert alerts[0].entity == "erin@ws-02"


def test_discovery_single_command_is_quiet() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.PROCESS,
        host="ws-02",
        user="erin",
        process="cmd.exe",
        parent_process="cmd.exe",
        command_line="whoami",
    )
    assert DiscoveryRule().detect([ev]) == []


def test_exfiltration_external_large_transfer_fires() -> None:
    evs = [
        Event(
            ts=at(i * 2),
            event_type=EventType.NETWORK,
            host="srv-db",
            user="frank",
            dest_ip="198.51.100.5",
            dest_port=443,
            bytes_out=60_000_000,
        )
        for i in range(3)
    ]
    alerts = ExfiltrationRule().detect(evs)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1048"
    assert alerts[0].severity == "critical"  # >= 100MB summed
    assert alerts[0].entity == "srv-db->198.51.100.5"


def test_exfiltration_internal_destination_is_quiet() -> None:
    # Same large volume but to an INTERNAL host -> not exfiltration.
    evs = [
        Event(
            ts=at(i * 2),
            event_type=EventType.NETWORK,
            host="srv-db",
            user="frank",
            dest_ip="10.0.0.30",
            dest_port=443,
            bytes_out=60_000_000,
        )
        for i in range(3)
    ]
    assert ExfiltrationRule().detect(evs) == []


def test_exfiltration_small_external_transfer_is_quiet() -> None:
    ev = Event(
        ts=at(0),
        event_type=EventType.NETWORK,
        host="srv-db",
        user="frank",
        dest_ip="198.51.100.5",
        dest_port=443,
        bytes_out=1000,
    )
    assert ExfiltrationRule().detect([ev]) == []


# ---------------------------------------------------------------------------
# Contract-level guarantees.
# ---------------------------------------------------------------------------


def test_every_rule_matches_protocol_and_resolves_technique() -> None:
    for rule in RULES:
        assert isinstance(rule, Rule)
        assert rule.severity in ("low", "medium", "high", "critical")
        # citing a real ATT&CK id that resolves to a real tactic
        assert get_technique(rule.technique_id).name
        assert tactic_for(rule.technique_id)


def test_run_rules_default_registry_detects_every_scenario() -> None:
    events = generate(GenConfig(days=3, seed=0))
    alerts = run_rules(events)
    assert len(alerts) > 0
    assert alerts == sorted(alerts, key=lambda a: a.ts)  # returned time-sorted

    detected = set()
    for a in alerts:
        detected |= {e.scenario for e in a.events if e.scenario}
    assert detected == {
        "brute_force",
        "lateral_movement",
        "suspicious_process",
        "discovery",
        "exfiltration",
    }
    # Every alert carries a resolvable technique + tactic.
    for a in alerts:
        assert a.tactic == tactic_for(a.technique_id)
        assert get_technique(a.technique_id).name


def test_benign_only_stream_yields_no_alerts() -> None:
    events = generate(GenConfig(days=3, seed=0))
    benign_only = [e for e in events if not e.scenario]
    assert run_rules(benign_only) == []


def test_run_rules_accepts_custom_rule_list() -> None:
    events = generate(GenConfig(days=3, seed=0))
    only_exfil = run_rules(events, [ExfiltrationRule()])
    assert only_exfil
    assert {a.rule_id for a in only_exfil} == {"R-EXFILTRATION"}
