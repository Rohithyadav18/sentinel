"""Command-line entry point for the sentinel defensive SOC pipeline.

Subcommands:

* ``sentinel generate`` — write a labeled synthetic event stream to JSONL.
* ``sentinel detect``   — generate → rule detection + ML anomaly scoring →
  evaluate against ground truth → persist ``artifacts/alerts.json`` and
  ``artifacts/report.json`` and print a summary table.
* ``sentinel dashboard`` — launch the Streamlit SOC console over the artifacts.

This is strictly a blue-team / detective tool: it detects, correlates, scores
and reports. It contains no offensive capability. Heavy sibling modules
(``detect``/``anomaly``/``evaluate``) are imported lazily inside the command
handlers so that importing this module (and its argument parser) stays cheap
and side-effect free.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel.generator import GenConfig, generate

DEFAULT_DAYS = 3
DEFAULT_SEED = 0
DEFAULT_ARTIFACTS = "artifacts"
DEFAULT_EVENTS_OUT = "events.jsonl"


# --------------------------------------------------------------------------- #
# generate
# --------------------------------------------------------------------------- #
def cmd_generate(args: argparse.Namespace) -> int:
    """Generate a labeled event stream and write it as JSON lines."""
    events = generate(GenConfig(days=args.days, seed=args.seed))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.model_dump_json())
            fh.write("\n")
    malicious = sum(1 for e in events if e.scenario)
    print(f"wrote {len(events)} events ({malicious} labeled malicious) -> {out}")
    return 0


# --------------------------------------------------------------------------- #
# detect
# --------------------------------------------------------------------------- #
def _anomaly_section(events: list[Any]) -> dict[str, Any]:
    """Run the ML anomaly detector and summarize it for the artifacts.

    Returns a JSON-safe dict with a per-(user, hour) timeline of anomaly
    scores and the windows flagged anomalous. Reads only real event fields.
    """
    from sentinel.anomaly import AnomalyDetector, build_features

    features = build_features(events)
    detector = AnomalyDetector().fit(features)
    scores = detector.score(features)
    flagged = detector.flag(features)

    timeline: list[dict[str, Any]] = []
    flagged_index = set(flagged.index)
    for idx in features.index:
        window = list(idx) if isinstance(idx, tuple) else [idx]
        timeline.append(
            {
                "window": [str(part) for part in window],
                "label": " / ".join(str(part) for part in window),
                "score": float(scores.loc[idx]),
                "anomalous": bool(idx in flagged_index),
            }
        )
    timeline.sort(key=lambda row: row["score"], reverse=True)
    return {
        "total_windows": len(features),
        "flagged_windows": len(flagged),
        "contamination": 0.02,
        "timeline": timeline,
    }


def _entity_summary(alert_dicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate alerts by the entity they concern (top offenders first)."""
    by_entity: dict[str, dict[str, Any]] = {}
    for alert in alert_dicts:
        entity = str(alert.get("entity", ""))
        bucket = by_entity.setdefault(
            entity,
            {"entity": entity, "alert_count": 0, "techniques": set(), "max_severity": "low"},
        )
        bucket["alert_count"] += 1
        bucket["techniques"].add(str(alert.get("technique_id", "")))
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current = str(alert.get("severity", "low"))
        if order.get(current, 0) > order.get(bucket["max_severity"], 0):
            bucket["max_severity"] = current
    rows = []
    for bucket in by_entity.values():
        rows.append(
            {
                "entity": bucket["entity"],
                "alert_count": bucket["alert_count"],
                "techniques": sorted(bucket["techniques"]),
                "max_severity": bucket["max_severity"],
            }
        )
    rows.sort(key=lambda r: r["alert_count"], reverse=True)
    return rows


def cmd_detect(args: argparse.Namespace) -> int:
    """Run the full detect → evaluate pipeline and persist artifacts."""
    from sentinel.detect import run_rules
    from sentinel.evaluate import evaluate_rules

    events = generate(GenConfig(days=args.days, seed=args.seed))
    alerts = run_rules(events)
    report = evaluate_rules(events, alerts)

    alert_dicts = [a.to_dict() for a in alerts]
    report_dict = report.to_dict()

    anomaly = _anomaly_section(events)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    alerts_path = out_dir / "alerts.json"
    report_path = out_dir / "report.json"

    combined: dict[str, Any] = {
        "meta": {
            "days": args.days,
            "seed": args.seed,
            "total_events": len(events),
            "labeled_malicious_events": sum(1 for e in events if e.scenario),
            "generated_at": datetime.now(UTC).isoformat(),
        },
        "evaluation": report_dict,
        "anomaly": anomaly,
        "entities": _entity_summary(alert_dicts),
    }

    alerts_path.write_text(json.dumps(alert_dicts, indent=2), encoding="utf-8")
    report_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    _print_summary(len(events), alert_dicts, report_dict, anomaly)
    print(f"\nwrote {alerts_path}")
    print(f"wrote {report_path}")
    return 0


def _print_summary(
    total_events: int,
    alert_dicts: list[dict[str, Any]],
    report_dict: dict[str, Any],
    anomaly: dict[str, Any],
) -> None:
    """Print the human-readable summary table detect emits (README numbers)."""
    line = "=" * 60
    print(line)
    print("SENTINEL — defensive SOC detection summary")
    print(line)
    print(f"{'events analyzed':<28}{total_events:>10}")
    print(f"{'rule alerts raised':<28}{len(alert_dicts):>10}")
    print(f"{'anomaly windows flagged':<28}{anomaly['flagged_windows']:>10}")
    print("-" * 60)
    for key in ("precision", "recall", "f1", "attack_technique_coverage"):
        if key in report_dict:
            print(f"{key:<28}{report_dict[key]:>10.3f}")
    for key in ("true_positives", "false_positives", "false_negatives"):
        if key in report_dict:
            print(f"{key:<28}{report_dict[key]:>10}")
    print("-" * 60)
    per_scenario = report_dict.get("per_scenario_recall", {})
    if per_scenario:
        print("per-scenario recall:")
        for name, value in sorted(per_scenario.items()):
            print(f"  {name:<26}{value:>10.3f}")
    detected = report_dict.get("techniques_detected", [])
    missed = report_dict.get("techniques_missed", [])
    if detected or missed:
        print("-" * 60)
        print(f"techniques detected: {', '.join(detected) if detected else '(none)'}")
        print(f"techniques missed:   {', '.join(missed) if missed else '(none)'}")
    print(line)


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
def cmd_dashboard(args: argparse.Namespace) -> int:
    """Launch the Streamlit SOC console pointed at the artifacts directory."""
    dashboard_path = Path(__file__).parent / "dashboard.py"
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard_path),
        "--server.headless",
        "true",
    ]
    if args.artifacts:
        cmd += ["--", "--artifacts", args.artifacts]
    print(f"launching SOC console: {' '.join(cmd)}")
    return subprocess.call(cmd)


# --------------------------------------------------------------------------- #
# parser / main
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the sentinel CLI."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Defensive SOC log-analytics pipeline (detective / blue-team only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate a labeled synthetic event stream (JSONL)")
    g.add_argument("--days", type=int, default=DEFAULT_DAYS)
    g.add_argument("--seed", type=int, default=DEFAULT_SEED)
    g.add_argument("--out", type=str, default=DEFAULT_EVENTS_OUT)
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("detect", help="generate → detect → evaluate → write artifacts")
    d.add_argument("--days", type=int, default=DEFAULT_DAYS)
    d.add_argument("--seed", type=int, default=DEFAULT_SEED)
    d.add_argument("--out", type=str, default=DEFAULT_ARTIFACTS)
    d.set_defaults(func=cmd_detect)

    b = sub.add_parser("dashboard", help="launch the Streamlit SOC console")
    b.add_argument("--artifacts", type=str, default=DEFAULT_ARTIFACTS)
    b.set_defaults(func=cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the selected subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    result: int = func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
