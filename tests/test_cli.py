"""Tests for the sentinel CLI and the import-safe dashboard helpers."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel import cli, dashboard


# --------------------------------------------------------------------------- #
# generate subcommand
# --------------------------------------------------------------------------- #
def test_generate_writes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    rc = cli.main(["generate", "--days", "1", "--seed", "3", "--out", str(out)])
    assert rc == 0
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0
    first = json.loads(lines[0])
    # Real event fields are present and JSON round-trips.
    assert "event_type" in first
    assert "host" in first


# --------------------------------------------------------------------------- #
# detect subcommand — the numbers the README quotes
# --------------------------------------------------------------------------- #
def test_detect_writes_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "artifacts"
    rc = cli.main(["detect", "--days", "3", "--seed", "0", "--out", str(out)])
    assert rc == 0

    alerts_path = out / "alerts.json"
    report_path = out / "report.json"
    assert alerts_path.exists()
    assert report_path.exists()

    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert isinstance(alerts, list) and len(alerts) > 0
    # Alerts are serialized without ground-truth label fields.
    for alert in alerts:
        assert "scenario" not in alert
        for ev in alert.get("events", []):
            assert "scenario" not in ev
            assert "technique_id" not in ev

    evaluation = report["evaluation"]
    # On the deterministic seed-0 stream every planted scenario is recovered.
    assert evaluation["recall"] == 1.0
    assert evaluation["attack_technique_coverage"] == 1.0
    for scenario_recall in evaluation["per_scenario_recall"].values():
        assert scenario_recall == 1.0

    # Anomaly + entity sections are populated for the dashboard.
    assert report["anomaly"]["flagged_windows"] > 0
    assert len(report["anomaly"]["timeline"]) > 0
    assert len(report["entities"]) > 0
    assert report["meta"]["total_events"] > 0


def test_detect_is_deterministic(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    cli.main(["detect", "--days", "2", "--seed", "1", "--out", str(a)])
    cli.main(["detect", "--days", "2", "--seed", "1", "--out", str(b)])
    ra = json.loads((a / "report.json").read_text())["evaluation"]
    rb = json.loads((b / "report.json").read_text())["evaluation"]
    assert ra == rb


# --------------------------------------------------------------------------- #
# parser structure
# --------------------------------------------------------------------------- #
def test_parser_has_subcommands() -> None:
    parser = cli.build_parser()
    ns = parser.parse_args(["generate"])
    assert ns.command == "generate"
    ns = parser.parse_args(["detect", "--seed", "5"])
    assert ns.command == "detect"
    assert ns.seed == 5
    ns = parser.parse_args(["dashboard", "--artifacts", "foo"])
    assert ns.command == "dashboard"
    assert ns.artifacts == "foo"


# --------------------------------------------------------------------------- #
# dashboard import safety + pure helpers
# --------------------------------------------------------------------------- #
def test_dashboard_import_is_side_effect_free() -> None:
    # Importing the module must not require or invoke Streamlit. The helpers
    # below are callable without a Streamlit runtime.
    assert hasattr(dashboard, "render")
    assert hasattr(dashboard, "load_artifacts")


def test_dashboard_load_artifacts_missing(tmp_path: Path) -> None:
    alerts, report = dashboard.load_artifacts(tmp_path)
    assert alerts == []
    assert report == {}


def test_dashboard_helpers_over_real_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "artifacts"
    cli.main(["detect", "--days", "3", "--seed", "0", "--out", str(out)])
    alerts, report = dashboard.load_artifacts(out)

    assert len(alerts) > 0
    # enrich_alert resolves the real ATT&CK technique name + a severity color.
    enriched = dashboard.enrich_alert(alerts[0])
    assert enriched["technique_name"]
    assert enriched["severity_color"].startswith("#")
    assert enriched["tactic"]

    # sort_alerts orders by severity (critical first).
    ordered = dashboard.sort_alerts(alerts)
    sev_rank = dashboard.SEVERITY_ORDER
    ranks = [sev_rank.get(a["severity"], 0) for a in ordered]
    assert ranks == sorted(ranks, reverse=True)

    # coverage view has one row per fired technique, each resolvable.
    cov = dashboard.coverage_rows(alerts)
    assert len(cov) > 0
    for row in cov:
        assert row["technique_id"].startswith("T")
        assert row["technique_name"]

    # top entities are ranked by alert count.
    entities = dashboard.top_entities(report, alerts)
    counts = [e["alert_count"] for e in entities]
    assert counts == sorted(counts, reverse=True)

    # anomaly timeline is present and each row has a numeric score.
    timeline = dashboard.anomaly_timeline(report)
    assert len(timeline) > 0
    assert all(isinstance(row["score"], float) for row in timeline)


def test_dashboard_parse_args_default() -> None:
    args = dashboard.parse_args([])
    assert args.artifacts == "artifacts"
    args = dashboard.parse_args(["--artifacts", "xyz"])
    assert args.artifacts == "xyz"
