"""Streamlit SOC console for the sentinel defensive pipeline.

Reads the artifacts written by ``sentinel detect`` (``alerts.json`` and
``report.json``) and renders a blue-team analyst console:

* a severity-colored **alert feed** annotated with the real MITRE ATT&CK
  technique name + tactic,
* a **MITRE ATT&CK coverage view** (techniques/tactics that fired vs. missed),
* an **anomaly-score timeline** over per-(user, hour) behavioral windows,
* the **top offending entities** by alert volume.

This module is import-safe: it performs no Streamlit calls at import time. The
console is rendered only when the file is executed (``streamlit run
dashboard.py`` sets ``__name__ == "__main__"``). All rendering data is prepared
by small pure helpers that are unit-tested without Streamlit.

Strictly detective: it visualizes detections. It has no offensive capability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sentinel.attack import get_technique

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
}
SEVERITY_ORDER: dict[str, int] = {"critical": 3, "high": 2, "medium": 1, "low": 0}


# --------------------------------------------------------------------------- #
# pure data helpers (unit-tested; no Streamlit)
# --------------------------------------------------------------------------- #
def load_artifacts(artifacts_dir: str | Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load ``alerts.json`` (list) and ``report.json`` (dict) from a directory.

    Missing files yield empty structures so the console degrades gracefully
    before the first ``sentinel detect`` run.
    """
    base = Path(artifacts_dir)
    alerts_path = base / "alerts.json"
    report_path = base / "report.json"
    alerts: list[dict[str, Any]] = []
    report: dict[str, Any] = {}
    if alerts_path.exists():
        loaded = json.loads(alerts_path.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            alerts = loaded
    if report_path.exists():
        loaded_report = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(loaded_report, dict):
            report = loaded_report
    return alerts, report


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Attach the resolved ATT&CK technique name/tactic/url to an alert dict."""
    enriched = dict(alert)
    tid = str(alert.get("technique_id", ""))
    name = tid
    tactic = str(alert.get("tactic", ""))
    url = ""
    if tid:
        try:
            tech = get_technique(tid)
            name = tech.name
            url = tech.url
            if not tactic and tech.tactics:
                tactic = tech.tactics[0]
        except KeyError:
            name = tid
    enriched["technique_name"] = name
    enriched["technique_url"] = url
    enriched["tactic"] = tactic
    enriched["severity_color"] = SEVERITY_COLORS.get(str(alert.get("severity", "low")), "#6b7280")
    return enriched


def sort_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order alerts by severity (critical first) then timestamp."""
    return sorted(
        alerts,
        key=lambda a: (
            -SEVERITY_ORDER.get(str(a.get("severity", "low")), 0),
            str(a.get("ts", "")),
        ),
    )


def coverage_rows(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a MITRE coverage table: one row per fired technique.

    Each row carries the technique id, resolved name, tactic, alert count and
    a representative rule title.
    """
    by_tid: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        tid = str(alert.get("technique_id", ""))
        if not tid:
            continue
        row = by_tid.get(tid)
        if row is None:
            name = tid
            tactic = str(alert.get("tactic", ""))
            try:
                tech = get_technique(tid)
                name = tech.name
                if not tactic and tech.tactics:
                    tactic = tech.tactics[0]
            except KeyError:
                pass
            row = {
                "technique_id": tid,
                "technique_name": name,
                "tactic": tactic,
                "alert_count": 0,
                "rules": set(),
            }
            by_tid[tid] = row
        row["alert_count"] += 1
        row["rules"].add(str(alert.get("rule_id", alert.get("title", ""))))
    rows = []
    for row in by_tid.values():
        rows.append(
            {
                "technique_id": row["technique_id"],
                "technique_name": row["technique_name"],
                "tactic": row["tactic"],
                "alert_count": row["alert_count"],
                "rules": sorted(r for r in row["rules"] if r),
            }
        )
    rows.sort(key=lambda r: (r["tactic"], r["technique_id"]))
    return rows


def top_entities(report: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the top offending entities, preferring the precomputed report."""
    entities = report.get("entities")
    if isinstance(entities, list) and entities:
        return entities
    # Fallback: aggregate from alerts directly.
    counts: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        entity = str(alert.get("entity", ""))
        bucket = counts.setdefault(
            entity, {"entity": entity, "alert_count": 0, "techniques": set()}
        )
        bucket["alert_count"] += 1
        bucket["techniques"].add(str(alert.get("technique_id", "")))
    rows = [
        {
            "entity": b["entity"],
            "alert_count": b["alert_count"],
            "techniques": sorted(t for t in b["techniques"] if t),
        }
        for b in counts.values()
    ]
    rows.sort(key=lambda r: r["alert_count"], reverse=True)
    return rows


def anomaly_timeline(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the anomaly-score timeline rows from the report."""
    anomaly = report.get("anomaly", {})
    timeline = anomaly.get("timeline", []) if isinstance(anomaly, dict) else []
    return timeline if isinstance(timeline, list) else []


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse ``--artifacts`` from the trailing args Streamlit forwards."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--artifacts", type=str, default="artifacts")
    args, _ = parser.parse_known_args(argv)
    return args


# --------------------------------------------------------------------------- #
# Streamlit rendering (only invoked under `streamlit run`)
# --------------------------------------------------------------------------- #
def render(artifacts_dir: str | Path) -> None:  # pragma: no cover - UI glue
    """Render the full SOC console. Imports Streamlit lazily."""
    import pandas as pd
    import streamlit as st

    st.set_page_config(page_title="sentinel — SOC console", page_icon="🛡️", layout="wide")

    st.title("🛡️ sentinel — defensive SOC console")
    st.caption(
        "Blue-team / detective only. Rule + ML detections mapped to real MITRE "
        "ATT&CK techniques, scored against ground truth."
    )

    alerts, report = load_artifacts(artifacts_dir)
    if not alerts and not report:
        st.warning(
            f"No artifacts found in `{artifacts_dir}`. Run `sentinel detect "
            f"--out {artifacts_dir}` first."
        )
        return

    evaluation = report.get("evaluation", {})
    meta = report.get("meta", {})
    anomaly = report.get("anomaly", {})

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Events analyzed", meta.get("total_events", "—"))
    c2.metric("Rule alerts", len(alerts))
    c3.metric("Precision", f"{evaluation.get('precision', 0):.2f}")
    c4.metric("Recall", f"{evaluation.get('recall', 0):.2f}")
    c5.metric("ATT&CK coverage", f"{evaluation.get('attack_technique_coverage', 0):.2f}")

    tab_feed, tab_cov, tab_anom, tab_ent = st.tabs(
        ["Alert feed", "MITRE ATT&CK coverage", "Anomaly timeline", "Top entities"]
    )

    with tab_feed:
        st.subheader("Alert feed")
        for alert in sort_alerts(alerts):
            e = enrich_alert(alert)
            sev = str(e.get("severity", "low")).upper()
            st.markdown(
                f"<div style='border-left:6px solid {e['severity_color']};"
                f"padding:6px 12px;margin:6px 0;background:rgba(127,127,127,0.08);'>"
                f"<b>{e.get('title', '')}</b> "
                f"<span style='color:{e['severity_color']};font-weight:700'>[{sev}]</span><br>"
                f"<code>{e.get('technique_id', '')}</code> {e.get('technique_name', '')} "
                f"· tactic: <i>{e.get('tactic', '')}</i> · entity: <b>{e.get('entity', '')}</b>"
                f"<br><small>{e.get('ts', '')}</small></div>",
                unsafe_allow_html=True,
            )
        if not alerts:
            st.info("No alerts in the current artifacts.")

    with tab_cov:
        st.subheader("MITRE ATT&CK coverage")
        rows = coverage_rows(alerts)
        if rows:
            df = pd.DataFrame(
                [
                    {
                        "Tactic": r["tactic"],
                        "Technique": r["technique_id"],
                        "Name": r["technique_name"],
                        "Alerts": r["alert_count"],
                        "Rules": ", ".join(r["rules"]),
                    }
                    for r in rows
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)
        missed = evaluation.get("techniques_missed", [])
        if missed:
            st.warning(f"Techniques present but NOT alerted on: {', '.join(missed)}")
        else:
            st.success("All techniques present in the data were alerted on.")

    with tab_anom:
        st.subheader("Anomaly-score timeline")
        st.caption(
            f"IsolationForest over per-(user, hour) behavioral windows. "
            f"{anomaly.get('flagged_windows', 0)} of "
            f"{anomaly.get('total_windows', 0)} windows flagged anomalous."
        )
        timeline = anomaly_timeline(report)
        if timeline:
            df = pd.DataFrame(timeline)
            chart_df = df[["label", "score"]].set_index("label")
            st.bar_chart(chart_df)
            st.dataframe(
                df[["label", "score", "anomalous"]].rename(
                    columns={"label": "Window (user / hour)", "score": "Score",
                             "anomalous": "Flagged"}
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No anomaly timeline in the current artifacts.")

    with tab_ent:
        st.subheader("Top offending entities")
        rows = top_entities(report, alerts)
        if rows:
            df = pd.DataFrame(
                [
                    {
                        "Entity": r["entity"],
                        "Alerts": r["alert_count"],
                        "Techniques": ", ".join(r.get("techniques", [])),
                        "Max severity": r.get("max_severity", ""),
                    }
                    for r in rows
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No entities to display.")


def main() -> None:  # pragma: no cover - UI glue
    """Entry point used by ``streamlit run dashboard.py``."""
    args = parse_args()
    render(args.artifacts)


if __name__ == "__main__":
    main()
