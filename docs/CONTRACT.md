# sentinel — detection contract (source of truth for the swarm)

A **defensive / detective** SOC analytics pipeline: ingest normalized security
events → run rule-based detections mapped to real MITRE ATT&CK techniques + an
ML anomaly detector → alert → measure detection quality against ground truth →
show it in a SOC dashboard.

**This project is strictly blue-team.** Build detection, correlation, scoring,
and visualization ONLY. Do NOT add offensive tooling, exploits, payloads,
scanners, or anything with intrusion capability. The generator's attack scenarios
are inert labeled log records, not working attacks.

## Foundation (built + committed — do NOT modify)

- `sentinel.events.Event` (pydantic): `ts, event_type(auth|process|network),
  host, user, source_ip, action, process, command_line, parent_process, dest_ip,
  dest_port, bytes_out`, plus **label fields `scenario` + `technique_id`** that
  detectors MUST NOT read (they are ground truth for evaluation only).
- `sentinel.generator.generate(GenConfig(days, seed, benign_per_hour)) ->
  list[Event]` — deterministic; ~3000 events with 5 planted attack scenarios
  (brute_force→T1110, lateral_movement→T1021, suspicious_process→T1059.001,
  discovery→T1087, exfiltration→T1048), each malicious event labeled.
- `sentinel.attack.get_technique(id) -> Technique(id, name, tactics, url)` —
  resolves REAL MITRE ATT&CK names/tactics (sub-techniques fall back to parent).

Conventions: Python 3.12, ruff (line 100; E,F,I,UP,B,SIM,RUF), mypy, pytest.

## Agent R — rule-based detection engine + rules

Files: `src/sentinel/detect.py`, `src/sentinel/rules.py`, `tests/test_detect.py`.

```python
@dataclass
class Alert:
    ts: datetime; rule_id: str; title: str; severity: str  # low|medium|high|critical
    technique_id: str; tactic: str        # tactic from get_technique().tactics[0]
    entity: str                           # the user/host/ip the alert is about
    events: list[Event]                   # the events that triggered it
    def to_dict(self) -> dict             # JSON-safe, resolves technique name

class Rule(Protocol):
    id: str; title: str; severity: str; technique_id: str
    def detect(self, events: list[Event]) -> list[Alert]: ...

RULES: list[Rule]   # concrete detection rules, one (or more) per planted scenario:
  # - brute force: >=N login_failure for one (user, source_ip) within a window then/or a success -> T1110
  # - lateral movement: one user login_success to >=K distinct hosts within a window -> T1021
  # - suspicious process: powershell/cmd with encoded/hidden flags OR office-app parent -> T1059.001
  # - discovery: >=M recon commands (whoami/net user/nltest/...) on one host in a window -> T1087
  # - exfiltration: outbound network bytes_out over a threshold to an EXTERNAL ip -> T1048
  # Rules read ONLY real event fields (never scenario/technique_id). External ip =
  # not starting with 10./172.16-31./192.168. Each rule cites a real ATT&CK id.

def run_rules(events: list[Event], rules: list[Rule] = RULES) -> list[Alert]
```

Tests: each rule fires on its attack scenario and does NOT fire on a purely
benign stream; alerts carry the right technique_id and a resolvable tactic;
external-vs-internal ip logic is correct; windowing works.

## Agent M — ML anomaly detector

Files: `src/sentinel/anomaly.py`, `tests/test_anomaly.py`.

```python
def build_features(events: list[Event]) -> pd.DataFrame
    # Per (user, hour) behavioral features from real fields only: auth failure
    # count/ratio, distinct hosts, distinct dest_ips, total bytes_out, process
    # count, off-hours activity (e.g. hour<6 or >20), rare-process indicator.
    # Index identifies the (user, hour) window. NEVER use scenario/technique_id.

class AnomalyDetector:
    def __init__(self, contamination: float = 0.02, random_state: int = 0)
    def fit(self, features: pd.DataFrame) -> "AnomalyDetector"    # IsolationForest
    def score(self, features: pd.DataFrame) -> pd.Series          # higher = more anomalous
    def flag(self, features: pd.DataFrame) -> pd.DataFrame        # rows predicted anomalous + score
```

Tests: features derive only from real fields; the detector fits/scores; on the
generated data the flagged (user, hour) windows overlap the windows that contain
labeled attacks materially better than chance (compute and assert a lift). Small,
deterministic, offline.

## Agent E — evaluation harness

Files: `src/sentinel/evaluate.py`, `tests/test_evaluate.py`.

```python
@dataclass
class DetectionReport:
    precision: float; recall: float; f1: float          # rule alerts vs labeled attacks
    true_positives: int; false_positives: int; false_negatives: int
    per_scenario_recall: dict[str, float]               # did we catch each scenario?
    attack_technique_coverage: float                    # fraction of present techniques alerted on
    techniques_detected: list[str]; techniques_missed: list[str]
    def to_dict(self) -> dict

def evaluate_rules(events: list[Event], alerts: list[Alert]) -> DetectionReport
    # An alert is a TRUE POSITIVE if any of its triggering events is labeled
    # (scenario != "") — this is where ground-truth labels are finally read.
    # recall = labeled scenarios detected / total; per-scenario recall; coverage
    # over the set of technique_ids actually present in the data.
```

Tests: on a benign-only stream precision handling is sane; on the full generated
stream recall for each planted scenario is > 0 (ideally 1.0) and technique
coverage is computed correctly; TP/FP/FN accounting is correct on hand-built cases.

## Agent D — SOC dashboard + CLI

Files: `src/sentinel/cli.py`, `src/sentinel/dashboard.py`,
`tests/test_cli.py`, and it owns `Dockerfile`, `.github/workflows/ci.yml`, `README.md`.

- `cli.py` (`main(argv=None)->int`, argparse): `sentinel generate [--days --seed --out events.jsonl]`;
  `sentinel detect [--days --seed --out artifacts]` = generate → run_rules + anomaly →
  evaluate → write `artifacts/alerts.json` + `artifacts/report.json` + print a summary
  table (the numbers the README quotes); `sentinel dashboard`.
- `dashboard.py`: a Streamlit **SOC console** reading the artifacts — an alert
  feed (severity-colored, with ATT&CK technique + tactic), a **MITRE ATT&CK
  coverage view** (which techniques/tactics fired), an anomaly-score timeline, and
  top offending entities. Import-safe (no top-level Streamlit calls).
- CI: ruff + mypy + pytest. Dockerfile runs the dashboard. README: what it is,
  the detection approach, the ATT&CK mapping, the **real eval numbers** (from
  `artifacts/report.json` via `sentinel detect`), a dashboard screenshot slot, and
  a prominent **"defensive-only / ethical scope"** note.

## Boundaries
- Agent R: detect.py, rules.py, test_detect.py. Agent M: anomaly.py, test_anomaly.py.
  Agent E: evaluate.py, test_evaluate.py. Agent D: cli.py, dashboard.py, test_cli.py,
  Dockerfile, CI, README.
- Nobody edits events.py, generator.py, attack.py, the catalog, or pyproject.
- Detectors/features must read ONLY real event fields, never `scenario`/`technique_id`
  (only `evaluate.py` reads labels, to score). This separation is the whole point.
