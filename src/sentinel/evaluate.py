"""Detection-quality evaluation harness — the *only* module that reads labels.

Every module upstream of this one (rules, features, the ML detector) is
forbidden from reading the ground-truth label fields ``scenario`` /
``technique_id``. This module is where those labels are finally consulted, to
score how well the rule engine's alerts recover the planted attacks.

Scoring model
-------------
* **Alert-level precision.** An alert is a *true positive* iff any of its
  triggering events is labeled (``scenario != ""``); otherwise it is a *false
  positive*. ``precision = TP / (TP + FP)``.
* **Instance-level recall.** The labeled events are clustered into distinct
  *attack instances* (a scenario injected at a point in time). Recall counts how
  many of those ground-truth instances were caught by at least one alert.
  ``recall = detected_instances / total_instances`` and a false negative is an
  undetected instance.
* **Per-scenario recall** applies the same instance accounting per scenario name.
* **ATT&CK technique coverage** is the fraction of technique ids actually present
  in the data that a detected instance recovers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from itertools import groupby
from typing import TYPE_CHECKING, Any

from sentinel.events import Event

if TYPE_CHECKING:  # pragma: no cover - typing only; detect.py owns the concrete class
    from sentinel.detect import Alert

# Two labeled events farther apart than this belong to different attack
# instances. Every generator scenario emits its events seconds apart, while
# separate injections land hours apart, so this cleanly separates instances.
_INSTANCE_GAP = timedelta(minutes=10)


@dataclass(frozen=True)
class _Instance:
    """One ground-truth attack occurrence: a time-local cluster of labeled events."""

    scenario: str
    technique_id: str
    event_ids: frozenset[int]


@dataclass
class DetectionReport:
    """Measured detection quality of a set of alerts against ground-truth labels."""

    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    per_scenario_recall: dict[str, float] = field(default_factory=dict)
    attack_technique_coverage: float = 0.0
    techniques_detected: list[str] = field(default_factory=list)
    techniques_missed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary of the report."""
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "per_scenario_recall": dict(self.per_scenario_recall),
            "attack_technique_coverage": self.attack_technique_coverage,
            "techniques_detected": list(self.techniques_detected),
            "techniques_missed": list(self.techniques_missed),
        }


def _ground_truth_instances(
    events: list[Event], gap: timedelta = _INSTANCE_GAP
) -> list[_Instance]:
    """Cluster labeled events into distinct attack instances.

    Events are grouped by scenario, then split into a new instance whenever
    consecutive events of that scenario are more than ``gap`` apart in time.
    """
    labeled = sorted(
        (e for e in events if e.scenario),
        key=lambda e: (e.scenario, e.ts),
    )
    instances: list[_Instance] = []
    for scenario, group in groupby(labeled, key=lambda e: e.scenario):
        current: list[Event] = []
        prev_ts = None
        for e in group:
            if prev_ts is not None and e.ts - prev_ts > gap:
                instances.append(_make_instance(scenario, current))
                current = []
            current.append(e)
            prev_ts = e.ts
        if current:
            instances.append(_make_instance(scenario, current))
    return instances


def _make_instance(scenario: str, events: list[Event]) -> _Instance:
    # All events in a single injected instance share one technique id.
    technique_id = events[0].technique_id
    return _Instance(
        scenario=scenario,
        technique_id=technique_id,
        event_ids=frozenset(id(e) for e in events),
    )


def _is_true_positive(alert: Alert) -> bool:
    """An alert is a true positive iff any triggering event is labeled."""
    return any(e.scenario for e in alert.events)


def evaluate_rules(events: list[Event], alerts: list[Alert]) -> DetectionReport:
    """Score ``alerts`` against the ground-truth labels carried by ``events``.

    This is the single place where the ``scenario`` / ``technique_id`` label
    fields are read. Alerts are matched to ground-truth attack instances by the
    identity of the labeled events they cite, so the ``Event`` objects an alert
    carries must be the same objects present in ``events``.
    """
    instances = _ground_truth_instances(events)

    # Precision side: classify each alert as TP or FP by whether it cites a label.
    true_positives = 0
    false_positives = 0
    detected_ids: set[int] = set()
    for alert in alerts:
        if _is_true_positive(alert):
            true_positives += 1
            detected_ids.update(id(e) for e in alert.events if e.scenario)
        else:
            false_positives += 1

    # Recall side: an instance is detected if any TP alert cited one of its events.
    detected_instances = [
        inst for inst in instances if inst.event_ids & detected_ids
    ]
    total = len(instances)
    detected = len(detected_instances)
    false_negatives = total - detected

    precision = true_positives / (true_positives + false_positives) if alerts else 1.0
    recall = detected / total if total else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    per_scenario_recall = _per_scenario_recall(instances, detected_instances)
    coverage, detected_tech, missed_tech = _technique_coverage(
        instances, detected_instances
    )

    return DetectionReport(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        per_scenario_recall=per_scenario_recall,
        attack_technique_coverage=coverage,
        techniques_detected=detected_tech,
        techniques_missed=missed_tech,
    )


def _per_scenario_recall(
    instances: list[_Instance], detected: list[_Instance]
) -> dict[str, float]:
    totals: dict[str, int] = {}
    hits: dict[str, int] = {}
    for inst in instances:
        totals[inst.scenario] = totals.get(inst.scenario, 0) + 1
        hits.setdefault(inst.scenario, 0)
    for inst in detected:
        hits[inst.scenario] += 1
    return {scenario: hits[scenario] / totals[scenario] for scenario in sorted(totals)}


def _technique_coverage(
    instances: list[_Instance], detected: list[_Instance]
) -> tuple[float, list[str], list[str]]:
    present = {inst.technique_id for inst in instances}
    covered = {inst.technique_id for inst in detected}
    detected_tech = sorted(present & covered)
    missed_tech = sorted(present - covered)
    coverage = len(detected_tech) / len(present) if present else 1.0
    return coverage, detected_tech, missed_tech
