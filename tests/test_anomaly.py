"""Tests for the unsupervised anomaly detector (Agent M)."""

from __future__ import annotations

from datetime import UTC, datetime

import pandas as pd
import pytest

from sentinel.anomaly import FEATURE_COLUMNS, AnomalyDetector, build_features
from sentinel.events import Event, EventType
from sentinel.generator import GenConfig, generate


def _attack_windows(events: list[Event]) -> set[tuple[str, pd.Timestamp]]:
    """Ground-truth (user, hour) windows containing >=1 labeled attack event.

    Reads the ``scenario`` label — legitimate here because this is evaluation
    of the detector, not the detector itself.
    """
    windows: set[tuple[str, pd.Timestamp]] = set()
    for e in events:
        if e.scenario:
            windows.add((e.user, pd.Timestamp(e.ts).floor("h")))
    return windows


def test_build_features_shape_and_columns() -> None:
    events = generate(GenConfig(days=2, seed=1))
    feats = build_features(events)
    assert list(feats.columns) == FEATURE_COLUMNS
    assert feats.index.names == ["user", "hour"]
    assert len(feats) > 0
    # No missing values; features are numeric.
    assert not feats.isna().any().any()
    assert all(pd.api.types.is_numeric_dtype(feats[c]) for c in FEATURE_COLUMNS)


def test_build_features_uses_no_label_fields() -> None:
    """Two streams identical on real fields but differing labels must yield equal features."""
    ts = datetime(2024, 6, 1, 3, 0, tzinfo=UTC)
    labeled = [Event(
        ts=ts, event_type=EventType.AUTH, host="srv-dc", user="alice",
        action="login_failure", scenario="brute_force", technique_id="T1110",
    )]
    unlabeled = [Event(
        ts=ts, event_type=EventType.AUTH, host="srv-dc", user="alice", action="login_failure",
    )]
    a = build_features(labeled)
    b = build_features(unlabeled)
    pd.testing.assert_frame_equal(a, b)


def test_features_reflect_real_behavior() -> None:
    ts = datetime(2024, 6, 1, 2, 0, tzinfo=UTC)  # off-hours
    events = [
        Event(ts=ts, event_type=EventType.AUTH, host="srv-dc", user="mallory",
              action="login_failure"),
        Event(ts=ts, event_type=EventType.AUTH, host="srv-dc", user="mallory",
              action="login_failure"),
        Event(ts=ts, event_type=EventType.AUTH, host="srv-dc", user="mallory",
              action="login_success"),
        Event(ts=ts, event_type=EventType.NETWORK, host="srv-dc", user="mallory",
              dest_ip="198.51.100.5", bytes_out=1000),
    ]
    feats = build_features(events)
    row = feats.loc[("mallory", pd.Timestamp(ts).floor("h"))]
    assert row["auth_failures"] == 2
    assert row["auth_failure_ratio"] == pytest.approx(2 / 3)
    assert row["distinct_dest_ips"] == 1
    assert row["total_bytes_out"] == 1000
    assert row["off_hours"] == 1


def test_detector_fit_score_flag_roundtrip() -> None:
    events = generate(GenConfig(days=3, seed=0))
    feats = build_features(events)
    det = AnomalyDetector().fit(feats)
    scores = det.score(feats)
    assert scores.shape[0] == len(feats)
    assert scores.index.equals(feats.index)
    flagged = det.flag(feats)
    assert "anomaly_score" in flagged.columns
    assert 0 < len(flagged) < len(feats)
    # flag() output is sorted most-anomalous-first.
    assert flagged["anomaly_score"].is_monotonic_decreasing


def test_score_before_fit_raises() -> None:
    feats = build_features(generate(GenConfig(days=1, seed=2)))
    with pytest.raises(RuntimeError):
        AnomalyDetector().score(feats)


def test_flagged_windows_beat_chance() -> None:
    """Flagged windows must overlap attack windows materially better than chance."""
    events = generate(GenConfig(days=3, seed=0))
    feats = build_features(events)
    det = AnomalyDetector(contamination=0.05).fit(feats)
    flagged = det.flag(feats)

    attack = _attack_windows(events)
    flagged_idx = set(flagged.index)

    base_rate = len(attack) / len(feats)  # P(window is attack) at random
    hits = len(flagged_idx & attack)
    precision = hits / len(flagged_idx)
    lift = precision / base_rate

    assert hits > 0
    assert lift > 2.0, f"lift={lift:.2f} precision={precision:.3f} base_rate={base_rate:.4f}"
