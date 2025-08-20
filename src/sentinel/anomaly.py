"""Unsupervised behavioral anomaly detection over normalized security events.

This is the ML complement to the rule engine. It builds per-``(user, hour)``
behavioral feature vectors from **real event fields only** (never the ground-truth
``scenario`` / ``technique_id`` labels) and fits an IsolationForest to flag
windows whose behavior deviates from the population — catching attack activity
without hand-written signatures.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import pandas as pd
from sklearn.ensemble import IsolationForest

from sentinel.events import Event

# Feature columns produced by ``build_features``, in stable order.
FEATURE_COLUMNS: list[str] = [
    "event_count",
    "auth_failures",
    "auth_failure_ratio",
    "distinct_hosts",
    "distinct_dest_ips",
    "total_bytes_out",
    "process_count",
    "rare_process_count",
    "off_hours",
]

# A process is "rare" if it accounts for less than this fraction of all
# observed process events across the whole stream.
_RARE_PROCESS_FRACTION = 0.05

# Off-hours: activity before 06:00 or after 20:00 (event-timestamp hour).
_OFF_HOURS_EARLY = 6
_OFF_HOURS_LATE = 20


@dataclass
class _Window:
    """Mutable per-``(user, hour)`` accumulator built from real fields only."""

    off_hours: int
    event_count: int = 0
    auth_events: int = 0
    auth_failures: int = 0
    process_count: int = 0
    rare_process_count: int = 0
    total_bytes_out: int = 0
    hosts: set[str] = field(default_factory=set)
    dest_ips: set[str] = field(default_factory=set)

    def add(self, event: Event, rare: set[str]) -> None:
        self.event_count += 1
        if event.host:
            self.hosts.add(event.host)
        if event.event_type == "auth":
            self.auth_events += 1
            if event.action == "login_failure":
                self.auth_failures += 1
        elif event.event_type == "process":
            self.process_count += 1
            if event.process in rare:
                self.rare_process_count += 1
        elif event.event_type == "network":
            if event.dest_ip:
                self.dest_ips.add(event.dest_ip)
            self.total_bytes_out += event.bytes_out

    def features(self) -> dict[str, float]:
        ratio = self.auth_failures / self.auth_events if self.auth_events else 0.0
        return {
            "event_count": float(self.event_count),
            "auth_failures": float(self.auth_failures),
            "auth_failure_ratio": ratio,
            "distinct_hosts": float(len(self.hosts)),
            "distinct_dest_ips": float(len(self.dest_ips)),
            "total_bytes_out": float(self.total_bytes_out),
            "process_count": float(self.process_count),
            "rare_process_count": float(self.rare_process_count),
            "off_hours": float(self.off_hours),
        }


def _rare_processes(events: list[Event]) -> set[str]:
    """Return the set of globally-rare process names (real field only)."""
    counts: Counter[str] = Counter(
        e.process for e in events if e.event_type == "process" and e.process
    )
    total = sum(counts.values())
    if total == 0:
        return set()
    threshold = total * _RARE_PROCESS_FRACTION
    return {proc for proc, n in counts.items() if n < threshold}


def build_features(events: list[Event]) -> pd.DataFrame:
    """Aggregate events into per-``(user, hour)`` behavioral feature vectors.

    Reads only real event fields. The returned frame has a ``MultiIndex`` of
    ``(user, hour)`` where ``hour`` is the event timestamp floored to the hour,
    and one column per entry in :data:`FEATURE_COLUMNS`.
    """
    rare = _rare_processes(events)
    windows: dict[tuple[str, pd.Timestamp], _Window] = {}

    for e in events:
        hour = pd.Timestamp(e.ts).floor("h")
        key = (e.user, hour)
        window = windows.get(key)
        if window is None:
            off = 1 if (hour.hour < _OFF_HOURS_EARLY or hour.hour > _OFF_HOURS_LATE) else 0
            window = _Window(off_hours=off)
            windows[key] = window
        window.add(e, rare)

    index = pd.MultiIndex.from_tuples(windows.keys(), names=["user", "hour"])
    records = [w.features() for w in windows.values()]
    frame = pd.DataFrame(records, index=index, columns=FEATURE_COLUMNS)
    return frame.sort_index()


@dataclass
class AnomalyDetector:
    """IsolationForest wrapper for per-``(user, hour)`` window scoring."""

    contamination: float = 0.02
    random_state: int = 0
    _model: IsolationForest | None = field(default=None, init=False, repr=False)

    def fit(self, features: pd.DataFrame) -> AnomalyDetector:
        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=200,
        )
        model.fit(features[FEATURE_COLUMNS].to_numpy(dtype=float))
        self._model = model
        return self

    def _require_model(self) -> IsolationForest:
        if self._model is None:
            raise RuntimeError("AnomalyDetector.fit must be called before scoring")
        return self._model

    def score(self, features: pd.DataFrame) -> pd.Series:
        """Anomaly score per window; higher = more anomalous."""
        model = self._require_model()
        # decision_function: higher = more normal. Negate so higher = more anomalous.
        raw = -model.decision_function(features[FEATURE_COLUMNS].to_numpy(dtype=float))
        return pd.Series(raw, index=features.index, name="anomaly_score")

    def flag(self, features: pd.DataFrame) -> pd.DataFrame:
        """Rows predicted anomalous, with their anomaly score, most anomalous first."""
        model = self._require_model()
        preds = model.predict(features[FEATURE_COLUMNS].to_numpy(dtype=float))
        scores = self.score(features)
        flagged = features.loc[preds == -1].copy()
        flagged["anomaly_score"] = scores.loc[preds == -1]
        return flagged.sort_values("anomaly_score", ascending=False)
