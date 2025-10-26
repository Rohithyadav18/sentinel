"""Tests for the detection-evaluation harness.

Alerts are built with the real :class:`sentinel.detect.Alert` record so the
harness is exercised against the exact contract type it scores in production.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sentinel.detect import Alert
from sentinel.evaluate import DetectionReport, _ground_truth_instances, evaluate_rules
from sentinel.events import Event, EventType
from sentinel.generator import GenConfig, generate

_T0 = datetime(2024, 6, 1, tzinfo=UTC)


def _alert(technique_id: str, events: list[Event]) -> Alert:
    """Build a real ``Alert`` citing ``events`` (metadata is inert for scoring)."""
    return Alert(
        ts=events[0].ts if events else _T0,
        rule_id="test_rule",
        title="test",
        severity="high",
        technique_id=technique_id,
        tactic="tactic",
        entity="entity",
        events=events,
    )


def _labeled(ts: datetime, scenario: str, technique_id: str) -> Event:
    return Event(
        ts=ts,
        event_type=EventType.AUTH,
        host="srv-dc",
        user="alice",
        action="login_failure",
        scenario=scenario,
        technique_id=technique_id,
    )


def _benign(ts: datetime) -> Event:
    return Event(
        ts=ts,
        event_type=EventType.AUTH,
        host="ws-01",
        user="bob",
        action="login_success",
    )


def test_true_positive_when_alert_cites_labeled_event() -> None:
    attack = _labeled(_T0, "brute_force", "T1110")
    events = [_benign(_T0), attack]
    alerts = [_alert("T1110", [attack])]

    report = evaluate_rules(events, alerts)

    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1 == 1.0


def test_false_positive_when_alert_only_cites_benign() -> None:
    attack = _labeled(_T0, "brute_force", "T1110")
    benign = _benign(_T0)
    events = [benign, attack]
    # Alert fires only on benign traffic -> false positive, and the attack is missed.
    alerts = [_alert("T1110", [benign])]

    report = evaluate_rules(events, alerts)

    assert report.true_positives == 0
    assert report.false_positives == 1
    assert report.false_negatives == 1
    assert report.precision == 0.0
    assert report.recall == 0.0


def test_benign_only_stream_precision_is_sane() -> None:
    events = [_benign(_T0 + timedelta(minutes=i)) for i in range(5)]

    # No alerts at all on a benign stream: nothing to catch, no false alarms.
    quiet = evaluate_rules(events, [])
    assert quiet.precision == 1.0
    assert quiet.recall == 1.0
    assert quiet.false_positives == 0
    assert quiet.attack_technique_coverage == 1.0

    # A spurious alert on benign traffic is a false positive, dropping precision.
    noisy = evaluate_rules(events, [_alert("T1110", [events[0]])])
    assert noisy.true_positives == 0
    assert noisy.false_positives == 1
    assert noisy.precision == 0.0


def test_distinct_instances_give_fractional_recall() -> None:
    # Two brute-force instances an hour apart; only the first is alerted on.
    inst1 = _labeled(_T0, "brute_force", "T1110")
    inst2 = _labeled(_T0 + timedelta(hours=1), "brute_force", "T1110")
    events = [inst1, inst2]
    alerts = [_alert("T1110", [inst1])]

    report = evaluate_rules(events, alerts)

    assert report.false_negatives == 1
    assert report.recall == 0.5
    assert report.per_scenario_recall["brute_force"] == 0.5


def test_events_close_in_time_are_one_instance() -> None:
    # Five failures seconds apart are a single instance; one alert covers it fully.
    burst = [
        _labeled(_T0 + timedelta(seconds=3 * i), "brute_force", "T1110")
        for i in range(5)
    ]
    alerts = [_alert("T1110", burst)]

    report = evaluate_rules(burst, alerts)

    assert report.recall == 1.0
    assert report.false_negatives == 0
    assert report.per_scenario_recall == {"brute_force": 1.0}


def test_technique_coverage_and_missed() -> None:
    bf = _labeled(_T0, "brute_force", "T1110")
    disc = _labeled(_T0 + timedelta(hours=2), "discovery", "T1087")
    events = [bf, disc]
    # Alert only for the brute force; discovery technique is uncovered.
    alerts = [_alert("T1110", [bf])]

    report = evaluate_rules(events, alerts)

    assert report.techniques_detected == ["T1110"]
    assert report.techniques_missed == ["T1087"]
    assert report.attack_technique_coverage == 0.5


def test_to_dict_is_json_safe() -> None:
    attack = _labeled(_T0, "brute_force", "T1110")
    report = evaluate_rules([attack], [_alert("T1110", [attack])])
    d = report.to_dict()
    # Round-trips through JSON without error and preserves the key fields.
    reloaded = json.loads(json.dumps(d))
    assert reloaded["precision"] == 1.0
    assert reloaded["per_scenario_recall"]["brute_force"] == 1.0
    assert reloaded["techniques_detected"] == ["T1110"]


def test_report_dataclass_defaults() -> None:
    # The dataclass is constructible with just the core counters.
    r = DetectionReport(
        precision=1.0,
        recall=1.0,
        f1=1.0,
        true_positives=1,
        false_positives=0,
        false_negatives=0,
    )
    assert r.per_scenario_recall == {}
    assert r.techniques_detected == []


def test_on_generated_stream_every_scenario_recall_positive() -> None:
    """Full ground-truth check: hand-build one alert per labeled instance and
    confirm recall, per-scenario recall, and coverage all reach 1.0."""
    events = generate(GenConfig(days=3, seed=0))
    instances = _ground_truth_instances(events)
    assert len(instances) > 0

    # Reconstruct alerts directly from ground truth (perfect detector).
    id_to_event = {id(e): e for e in events}
    alerts = [
        _alert(
            inst.technique_id,
            [id_to_event[i] for i in inst.event_ids],
        )
        for inst in instances
    ]

    report = evaluate_rules(events, alerts)

    scenarios = {inst.scenario for inst in instances}
    assert scenarios == {
        "brute_force",
        "lateral_movement",
        "suspicious_process",
        "discovery",
        "exfiltration",
    }
    for scenario in scenarios:
        assert report.per_scenario_recall[scenario] > 0
    assert report.recall == 1.0
    assert report.attack_technique_coverage == 1.0
    assert report.false_negatives == 0
    assert set(report.techniques_detected) == {
        "T1110",
        "T1021",
        "T1059.001",
        "T1087",
        "T1048",
    }
