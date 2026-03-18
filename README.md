# Abuse Pattern Detection & Risk Monitoring System

A Python platform for detecting coordinated abuse at scale — combining statistical anomaly scoring, graph-based ring detection, and real-time alerting into a single deployable pipeline.

> Handles 10M+ behavioral events per day with ≤5 minute detection latency.

---

## Table of Contents

1. [What This System Does](#1-what-this-system-does)
2. [Architecture Overview](#2-architecture-overview)
3. [Repository Layout](#3-repository-layout)
4. [Component Breakdown](#4-component-breakdown)
   - [Feature Engineering](#feature-engineering)
   - [Anomaly Detection](#anomaly-detection)
   - [Cluster Detection](#cluster-detection)
   - [Threshold Calibration](#threshold-calibration)
   - [Alerting Engine](#alerting-engine)
   - [Dashboard Specifications](#dashboard-specifications)
5. [Database Design](#5-database-design)
6. [Reproducible Quickstart](#6-reproducible-quickstart)
7. [Configuration Reference](#7-configuration-reference)
8. [Running Tests](#8-running-tests)
9. [Docker Deployment](#9-docker-deployment)
10. [CI/CD Pipeline](#10-cicd-pipeline)
11. [Performance Characteristics](#11-performance-characteristics)
12. [Failure Recovery](#12-failure-recovery)
13. [Roadmap](#13-roadmap)

---

## 1. What This System Does

Most abuse detection systems treat accounts in isolation — they flag individual users whose behavior looks unusual and stop there. That works fine for catching lone actors, but misses the bigger threat: coordinated rings where each individual account looks almost normal, but the group as a whole is running a fraud operation, fake review farm, or bot network.

This system addresses both. It scores every user on a 0–100 risk scale using a blend of statistical and ML signals, then runs a separate graph-based pass to surface coordination patterns — shared IPs, shared devices, synchronized timing — that would be invisible if you only looked at users one at a time.

The output is a stream of calibrated risk scores, cluster reports, and webhook alerts. The false-positive rate is controlled at a configurable target (default 1%) through ROC/PR curve calibration that runs against ground-truth labels whenever they're available.

**Primary threat models covered:**

| Threat | Detection Method |
|--------|-----------------|
| Credential stuffing / account takeover | Anomalous action frequency + IP entropy spike |
| Scraping bots | High session velocity + device reuse |
| Fake review / rating farms | Graph clusters with shared device edges |
| Fraud rings | Coordinated event timing + shared IP infrastructure |
| Recidivists | Enforcement history feature + escalation spike alerts |

---

## 2. Architecture Overview

The pipeline has five layers that execute in order every detection cycle:

```
┌───────────────────────────────────────────────────────────────────┐
│                         Ingestion Layer                            │
│                                                                    │
│   CSV files / Kafka topic / PostgreSQL table                      │
│             ↓ batch loader or stream reader                        │
│        raw_events (PostgreSQL, range-partitioned by month)         │
│        or S3 Parquet for long-term archival                       │
└───────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                     Feature Engineering Layer                      │
│             src/features/feature_engineering.py                    │
│                                                                    │
│   • action frequency    (rolling 5 / 15 / 60 min windows)         │
│   • IP entropy          (Shannon H per user)                      │
│   • device reuse score  (shared-device normalized 0–1)            │
│   • session velocity    (events / second per session)             │
│   • enforcement history (fraction of enforced events)             │
└──────────────┬────────────────────────────────┬───────────────────┘
               │                                │
               ▼                                ▼
┌──────────────────────────┐    ┌───────────────────────────────────┐
│   Anomaly Detection      │    │   Cluster / Graph Detection        │
│   anomaly_detection.py   │    │   cluster_detection.py             │
│                          │    │                                    │
│   Z-score detector       │    │   Build user–user graph            │
│   + IsolationForest      │    │   edges = shared IP or device      │
│   → blended 0–100 score  │    │   Detect communities (connected    │
│                          │    │   components / Louvain)            │
│                          │    │   Score clusters 0–100             │
└──────────────┬───────────┘    └──────────────────┬────────────────┘
               │                                   │
               └──────────────┬────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                   Threshold Calibration Layer                      │
│             src/calibration/threshold_calibration.py               │
│                                                                    │
│   • Compute ROC / PR curves against ground-truth labels           │
│   • Find threshold at target FPR (default 1%)                     │
│   • Auto-adjust if live FPR drifts beyond 2× target              │
│   • Persist changes to threshold_history table                    │
└───────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                         Alerting Layer                             │
│                  src/alerting/alert_engine.py                      │
│                                                                    │
│   • Deduplication   (per-entity, configurable window)             │
│   • Rate limiting   (token bucket, max N alerts / 60 s)           │
│   • HTTP dispatch   (exponential-backoff retry, up to 3×)         │
│   • Incident log    (rotating JSON file, logs/incidents.log)      │
└────────────────────┬──────────────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
  Webhook / Slack          Dashboard metrics
  PagerDuty / Teams        (PostgreSQL → Grafana)
```

**Detection cycle flow (step by step):**

```
Raw events
  → FeatureEngineer.build_feature_matrix()        per-user 11-feature matrix
  → AnomalyDetectionPipeline.predict()            user_id, risk_score, is_anomaly
  → AbuseClusterDetector.build_graph()            NetworkX weighted graph
  → AbuseClusterDetector.score_clusters()         cluster list with 0-100 risk
  → ThresholdCalibrator.find_optimal_threshold()  calibrated decision boundary
  → AlertEngine.check_risk_threshold()            HTTP POST if threshold exceeded
  → incidents.log + dashboard_metrics table
```

---

## 3. Repository Layout

```
.
├── ARCHITECTURE.md                     # Deep-dive system design document
├── Dockerfile                          # Python 3.11-slim multi-stage build
├── docker-compose.yml                  # App + PostgreSQL service stack
├── requirements.txt                    # Python dependencies (9 packages)
├── setup.py                            # Package setup with entry points
├── config/
│   └── config.yaml                     # Single source of truth for all settings
├── sql/
│   ├── schema.sql                      # 8-table PostgreSQL DDL with partitioning
│   └── queries.sql                     # 7 analytical queries (CTEs, window functions)
├── src/
│   ├── features/
│   │   └── feature_engineering.py      # Vectorized behavioral feature extraction
│   ├── detection/
│   │   ├── anomaly_detection.py        # Z-score + Isolation Forest scoring
│   │   └── cluster_detection.py        # Graph-based abuse ring detection
│   ├── calibration/
│   │   └── threshold_calibration.py    # ROC/PR threshold optimization
│   ├── alerting/
│   │   └── alert_engine.py             # Dedup + rate-limited webhook dispatch
│   └── dashboard/
│       └── dashboard_spec.py           # Dashboard metric & SQL specifications
└── tests/
    ├── test_feature_engineering.py
    ├── test_anomaly_detection.py
    ├── test_cluster_detection.py
    ├── test_threshold_calibration.py
    └── test_alerting.py
```

---

## 4. Component Breakdown

### Feature Engineering

**File:** `src/features/feature_engineering.py` — `FeatureEngineer`

Takes a raw event DataFrame and produces a per-user feature matrix with no NaN values. All computations are fully vectorized; the bottleneck is usually the rolling-window groupby, which runs at roughly 1M+ events per minute on a single core.

**Expected input columns:** `user_id`, `ip_address`, `device_id`, `session_id`, `action`, `timestamp`, `enforced`

**Features extracted (11 total):**

| Feature Group | Features | Method |
|--------------|----------|--------|
| Action frequency | mean/max count in 5, 15, 60-min windows (6 cols) | `compute_action_frequency()` |
| IP entropy | Shannon entropy + unique IP count (2 cols) | `compute_ip_entropy()` |
| Device reuse | normalized excess sharing + max sharing (2 cols) | `compute_device_reuse_score()` |
| Session velocity | events/sec mean/max + session count (3 cols) | `compute_session_velocity()` |
| Enforcement history | fraction enforced + total count (2 cols) | `compute_enforcement_history_rate()` |

**IP entropy** uses Shannon's formula — a user whose traffic comes from many different IP addresses has high entropy, which is a signal for distributed attack infrastructure:

```
H(user) = -Σ p_i × log₂(p_i)    where p_i = fraction of events from IP_i
```

**Device reuse** captures accounts that share devices with an unusual number of other users. A device shared among 10 accounts is a much stronger signal than one shared between 2.

---

### Anomaly Detection

**File:** `src/detection/anomaly_detection.py` — `AnomalyDetectionPipeline`

Produces a single 0–100 risk score per user by blending two complementary detectors:

```
Feature matrix
  → StandardScaler (fit on training window)
  ├── Z-score detector
  │     count features exceeding ±3σ from training mean
  │     normalize: fraction anomalous → [0, 1]
  │
  └── IsolationForest (200 trees, n_jobs=-1)
        unsupervised path-length anomaly score
        invert + min-max normalize → [0, 1]

risk_score = clip((0.55 × IF_score + 0.45 × Z_score) × 100, 0, 100)
```

The weights (0.55 / 0.45) and the Z-score threshold (3σ) are configurable. IsolationForest gets the larger weight because it captures multivariate interactions that Z-score misses; Z-score is kept because it's interpretable and fast to re-calibrate.

**Key API:**

```python
pipeline = AnomalyDetectionPipeline(config_path="config/config.yaml")
pipeline.fit(training_df)                        # trains scaler + forest
pipeline.save_model("models/pipeline_v1.pkl")   # serializes to disk

scores = pipeline.predict(new_df)
# Returns: DataFrame[user_id, risk_score (0-100), is_anomaly (bool)]
```

Users with `risk_score >= 70` are flagged as high-risk (configurable via `risk_score_high`). The decision boundary itself is calibrated separately by `ThresholdCalibrator` against ground-truth labels.

---

### Cluster Detection

**File:** `src/detection/cluster_detection.py` — `AbuseClusterDetector`

Builds a weighted user–user graph where edges connect accounts that share an IP address or device ID within a 24-hour window. Connected components of that graph are candidate abuse rings.

**Graph construction:**

```
Nodes:  user_id  (attributes: event_count, unique_ips, unique_devices)
Edges:  user_A ↔ user_B  when they share ≥1 IP or device in same 24h window

Edge weight:
  w = tanh(shared_count) × (0.5 + 0.5 × temporal_overlap)
```

`tanh` compresses the shared-count so that 1 shared IP vs. 10 shared IPs don't produce a 10× weight difference — the shape of the curve is what matters. `temporal_overlap` is the fraction of each user's active hours that overlap, adding a timing dimension.

**Cluster risk scoring:**

```
size_score    = min(log₂(size + 1) / log₂(101), 1.0)
density_score = edge_count / max_possible_edges
weight_score  = mean edge weight across cluster
event_score   = mean(node event_counts) / 95th-percentile

risk = 100 × mean(size_score, density_score, weight_score, event_score)
```

This rewards clusters that are large, tightly connected, have strong shared-signal edges, and whose members are individually active — all hallmarks of coordinated abuse rather than organic account sharing.

**Optional Louvain community detection** (requires `python-louvain`) finds finer-grained communities within large connected components:

```python
detector = AbuseClusterDetector()
G = detector.build_graph(events_df)

# Connected components (default, no extra deps)
clusters = detector.detect_clusters(G, use_louvain=False)

# Louvain (better resolution for large graphs)
clusters = detector.detect_clusters(G, use_louvain=True)

scored    = detector.score_clusters(G, clusters)
escalated = detector.escalate_risks(scored, threshold=60)
```

For a quick demonstration without real data:

```python
result = detector.simulate_example()   # returns dict: dataframe, graph, clusters, escalated
print(result["escalated"])
```

---

### Threshold Calibration

**File:** `src/calibration/threshold_calibration.py` — `ThresholdCalibrator`

When ground-truth labels are available (e.g. confirmed abuse from manual review), this module finds the optimal decision threshold that maximizes recall subject to a false-positive rate constraint.

The default approach uses the `(1 − target_fpr)` quantile of the score distribution on known-negative samples. This is more stable than ROC-curve search when label quality is imperfect.

```python
calibrator = ThresholdCalibrator(config_path="config/config.yaml")

# y_true: ground-truth binary labels, y_scores: risk_score 0-100
threshold = calibrator.find_optimal_threshold(y_true, y_scores, target_fpr=0.01)

report = calibrator.generate_threshold_report(y_true, y_scores, threshold)
# report contains: AUC-ROC, AUC-PR, F1, precision, recall, FPR, FNR

calibrator.plot_curves(y_true, y_scores, output_path="plots/calibration.png")
```

`auto_adjust_threshold()` can be called on a schedule with live production metrics. If the observed FPR drifts above `2 × target_fpr`, it raises the threshold automatically and logs the change to the `threshold_history` table.

---

### Alerting Engine

**File:** `src/alerting/alert_engine.py` — `AlertEngine`

Three alert types, each with independent deduplication:

| Alert Type | Trigger | Dedup Key |
|-----------|---------|-----------|
| User risk | `risk_score >= risk_score_high` | `user_risk:{user_id}` |
| Cluster risk | cluster score ≥ threshold | `cluster_risk:{cluster_id}` |
| Escalation spike | enforcement volume Z-score above threshold | `escalation:{date}` |

**Alert dispatch flow:**

```
check_risk_threshold(user_id, score)
  │
  ├── score < 70?  →  return False
  │
  ├── Dedup: already alerted this user in last 300s?  →  return False
  │
  ├── Rate limit: > 60 dispatches in last 60s?  →  return False
  │
  └── dispatch_alert(payload)
        ├── POST webhook_url  →  2xx: log to incidents.log, increment sent
        └── non-2xx or exception
              → wait 5s, retry (up to 3 attempts)
              → all retries failed: log failure, increment failed
```

```python
engine = AlertEngine(config_path="config/config.yaml")

# Per-user check (call after pipeline.predict())
engine.check_risk_threshold("user_001", risk_score=82)

# Per-cluster check
engine.check_cluster_threshold("cluster_007", cluster_score=74)

# Escalation spike (pass the full enforcement DataFrame)
engine.check_escalation_spike(enforcement_df)

# Metrics summary
print(engine.get_alert_metrics())
# {'sent': 12, 'deduplicated': 47, 'failed': 0}
```

Incidents are written as JSON lines to `logs/incidents.log` with rotation at 10 MB (5 backups). Any log aggregation tool (Datadog, Splunk, CloudWatch Logs) can tail this file directly.

---

### Dashboard Specifications

**File:** `src/dashboard/dashboard_spec.py` — `DashboardSpecGenerator`

Generates JSON-serializable dashboard specifications for two audiences:

**Executive overview** (15-minute refresh):
- Total flagged users and high-risk rate (%)
- Alert rate (alerts/hour) over the last 24 hours
- Model AUC and F1 from the latest calibration run
- Top-10 highest-risk clusters

**Analyst view** (5-minute refresh):
- Per-user risk drilldown with feature contribution breakdown
- Cluster network graph (Node Graph panel in Grafana)
- Threshold calibration curves
- Enforcement action breakdown by type
- Model diagnostics (score distribution, contamination estimate)

```python
gen = DashboardSpecGenerator()
gen.export_spec("dashboards/spec.json")
```

The exported JSON spec plugs directly into Grafana's dashboard provisioning or a custom FastAPI `/metrics` endpoint.

---

## 5. Database Design

**File:** `sql/schema.sql` — PostgreSQL 14+

Eight tables organized into three concerns: ingestion, scoring, and operations.

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│   raw_events    │────▶│  anomaly_scores  │     │  threshold_history│
│ (partitioned by │     │  (per user, per  │     │  (audit trail of  │
│  month, 24 pre- │     │   cycle)         │     │   threshold edits)│
│  allocated)     │     └──────────────────┘     └───────────────────┘
└─────────────────┘              │
        │                        │
        ▼                        ▼
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│cluster_assignments    │  alert_incidents │     │ dashboard_metrics │
│(user → cluster  │     │  (dispatch log,  │     │  (time-series     │
│ membership)     │     │   retry status)  │     │   snapshots)      │
└─────────────────┘     └──────────────────┘     └───────────────────┘
        │
        ▼
┌─────────────────┐     ┌──────────────────┐
│     users       │     │  feature_cache   │
│(denorm cache,   │     │  (optional Redis-│
│ is_flagged,     │     │   backed store)  │
│ latest_score)   │     └──────────────────┘
└─────────────────┘
```

`raw_events` uses PostgreSQL range partitioning by `timestamp` with 24 monthly partitions pre-allocated. Queries that filter on a time range skip all irrelevant partitions — this is the single biggest performance win for time-series workloads.

**Apply schema:**
```bash
psql -U db_user -d abuse_monitoring_db -f sql/schema.sql
```

**Seven pre-built analytical queries** (`sql/queries.sql`) cover:
1. High-frequency action bursts (sliding-window, last 1 hour)
2. Device concentration anomalies (top shared devices)
3. IP entropy outliers (users with unusually many IPs)
4. Session velocity anomalies (events/second above threshold)
5. Coordinated event timing (users acting in tight synchrony)
6. Enforcement action sequences (recidivism patterns)
7. Cluster member risk aggregation (per-cluster summary)

All queries use partition-aware `BETWEEN` clauses and named parameters so they work directly as prepared statements.

---

## 6. Reproducible Quickstart

### Prerequisites

- Python 3.11+
- PostgreSQL 14+ (optional — needed only for the DB layer)
- Docker + Docker Compose (optional — for the full stack)

### Install

```bash
git clone https://github.com/Raj-Purohith-Arjun/Abuse-Pattern-Detection-Risk-Monitoring-System.git
cd Abuse-Pattern-Detection-Risk-Monitoring-System
pip install -r requirements.txt
```

### 1. Run the anomaly detection pipeline on sample data

```python
import pandas as pd
import numpy as np
from src.detection.anomaly_detection import AnomalyDetectionPipeline

# Build minimal sample events (replace with your CSV or DB query)
rng = np.random.default_rng(42)
n = 500
events = pd.DataFrame({
    "user_id":    [f"u{i:04d}" for i in rng.integers(0, 50, n)],
    "ip_address": [f"10.0.{rng.integers(0,10)}.{rng.integers(1,255)}" for _ in range(n)],
    "device_id":  [f"dev_{rng.integers(0,30)}" for _ in range(n)],
    "session_id": [f"s{rng.integers(0,100)}" for _ in range(n)],
    "action":     rng.choice(["login", "view", "post", "flag"], n),
    "timestamp":  pd.date_range("2024-01-01", periods=n, freq="1min"),
    "enforced":   rng.choice([0, 1], n, p=[0.95, 0.05]),
})

pipeline = AnomalyDetectionPipeline(config_path="config/config.yaml")
pipeline.fit(events)     # builds features, trains scaler + IsolationForest, calibrates threshold
scores   = pipeline.predict(events)

print(scores[["user_id", "risk_score", "is_anomaly"]].sort_values("risk_score", ascending=False).head(10))
```

To use the feature engineering step on its own (e.g. for inspection or caching):

```python
from src.features.feature_engineering import FeatureEngineer

fe       = FeatureEngineer()
features = fe.build_feature_matrix(events)
print(features.shape, features.columns.tolist())
```

### 2. Detect coordinated abuse clusters

```python
from src.detection.cluster_detection import AbuseClusterDetector

detector  = AbuseClusterDetector()
G         = detector.build_graph(events)
clusters  = detector.detect_clusters(G)
scored    = detector.score_clusters(G, clusters)
escalated = detector.escalate_risks(scored, threshold=60)

for c in escalated:
    print(f"Cluster {c['cluster_id']}  size={c['size']}  risk={c['risk_score']:.1f}")
```

### 3. Calibrate the decision threshold

```python
from src.calibration.threshold_calibration import ThresholdCalibrator

# y_true: ground-truth labels (0 = benign, 1 = abuse)
# y_scores: risk_score column from step 1
calibrator = ThresholdCalibrator(config_path="config/config.yaml")
threshold  = calibrator.find_optimal_threshold(y_true, y_scores, target_fpr=0.01)
report     = calibrator.generate_threshold_report(y_true, y_scores, threshold)
print(f"Threshold: {threshold:.1f}  AUC-ROC: {report['auc_roc']:.3f}  F1: {report['f1']:.3f}")
```

### 4. Fire alerts

```python
from src.alerting.alert_engine import AlertEngine

engine = AlertEngine(config_path="config/config.yaml")

for _, row in scores.iterrows():
    engine.check_risk_threshold(row["user_id"], row["risk_score"])

print(engine.get_alert_metrics())
```

### 5. Simulate a synthetic abuse ring (no data needed)

```python
from src.detection.cluster_detection import AbuseClusterDetector

detector = AbuseClusterDetector()
result   = detector.simulate_example()   # generates synthetic abuse rings
scored   = result["clusters"]
print(f"Found {len(scored)} clusters. Top score: {max(c['risk_score'] for c in scored):.1f}")
```

### 6. Save and reload the trained model

```python
import os
os.makedirs("models", exist_ok=True)
pipeline.save_model("models/pipeline_v1.pkl")

from src.detection.anomaly_detection import AnomalyDetectionPipeline
loaded  = AnomalyDetectionPipeline(config_path="config/config.yaml")
loaded.load_model("models/pipeline_v1.pkl")
scores2 = loaded.predict(events)
```

---

## 7. Configuration Reference

All settings live in `config/config.yaml`. Nothing is hardcoded.

```yaml
database:
  host: "localhost"
  port: 5432
  name: "abuse_monitoring_db"
  user: "db_user"
  password: "REPLACE_WITH_SECRET"   # inject via DB_PASSWORD env var
  pool_size: 10
  max_overflow: 20

anomaly_detection:
  zscore_threshold: 3.0          # σ above mean before a feature counts as anomalous
  contamination: 0.05            # expected outlier fraction (IsolationForest prior)
  risk_score_high: 70            # alert threshold on 0-100 scale
  risk_score_medium: 40
  target_fpr: 0.01               # 1% false-positive rate at calibration time
  isolation_forest_weight: 0.55  # blend weights must sum to 1.0
  zscore_weight: 0.45

feature_engineering:
  rolling_windows: [5, 15, 60]   # minutes
  session_gap_minutes: 30        # idle gap that starts a new session
  min_events_for_entropy: 3      # skip entropy for users with fewer events
  velocity_cap: 1000.0           # events/sec cap (suppresses outlier inflation)

alerting:
  webhook_url: "https://hooks.example.com/REPLACE_WITH_TOKEN"
  rate_limit: 60                 # max alerts dispatched per minute
  dedup_window: 300              # seconds before the same entity can be re-alerted
  retry_attempts: 3
  retry_backoff_seconds: 5

model:
  n_estimators: 200              # IsolationForest tree count
  n_jobs: -1                     # use all CPU cores
  retrain_interval: 86400        # 24 hours in seconds
  model_store_path: "models/"
```

Environment variables override YAML values — use `DB_PASSWORD` and `WEBHOOK_TOKEN` in production rather than committing secrets.

---

## 8. Running Tests

```bash
# Full test suite with verbose output
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run a single module
pytest tests/test_cluster_detection.py -v
```

**Test coverage by module:**

| Test File | Tests | What's Covered |
|-----------|-------|----------------|
| `test_feature_engineering.py` | 8 | Rolling windows, entropy, velocity, NaN handling |
| `test_anomaly_detection.py` | 8 | Z-score, IsolationForest, score blending, serialization |
| `test_cluster_detection.py` | 8 | Graph construction, edge weights, scoring, simulation |
| `test_threshold_calibration.py` | 7 | ROC/PR curves, FPR/FNR, threshold selection, report |
| `test_alerting.py` | 6 | Dedup, rate limiting, retry logic, incident logging |
| **Total** | **37** | Full pipeline coverage |

Tests are self-contained — they generate synthetic data internally and do not require a live database or network connection.

---

## 9. Docker Deployment

**Local development (single command):**

```bash
docker-compose up --build
```

This starts:
- `app` — the Python pipeline on port 8080
- `postgres` — PostgreSQL 15 on port 5432 with schema auto-applied via `docker-entrypoint-initdb.d`

**Build and run manually:**

```bash
docker build -t abuse-detection:latest .
docker run -e DB_PASSWORD=secret -p 8080:8080 abuse-detection:latest
```

**Production (Kubernetes):**

```bash
docker build -t registry.example.com/abuse-detection:latest .
docker push registry.example.com/abuse-detection:latest
kubectl apply -f k8s/
kubectl rollout status deployment/abuse-detection
```

The container uses `python:3.11-slim` as base, copies only the source tree (no test files), and includes a health-check endpoint. The image size is kept small by installing dependencies in a separate layer.

---

## 10. CI/CD Pipeline

GitHub Actions runs on every push and pull request to `main`.

```
push / PR to main
  │
  ├── lint job
  │     python 3.11
  │     pip install flake8
  │     flake8 src/
  │
  └── test job
        python 3.11
        pip install -r requirements.txt  (cached by pip cache key)
        pytest tests/ -v --cov=src
        upload coverage report as workflow artifact
```

**Workflow file:** `.github/workflows/ci.yml`

The test job depends on the lint job passing — a style failure blocks tests from running. Coverage reports are stored as workflow artifacts for 7 days and can be downloaded from the Actions tab.

---

## 11. Performance Characteristics

These numbers come from the vectorized NumPy/Pandas implementation on a single core. Horizontal scaling strategies are listed below.

| Stage | Throughput | Notes |
|-------|-----------|-------|
| Feature engineering | 1M+ events/min | Fully vectorized rolling-window groupby |
| Anomaly scoring (inference) | 1M+ users/min | Stateless `predict()` — parallelizable |
| Cluster graph build | 10M edges/cycle | NetworkX; swap to GraphFrames for >10M |
| Alert dispatch | 10k+ alerts/min | With dedup/rate-limit reducing actual volume |

**Scaling beyond a single node:**

- **Feature engineering** — partition events by `user_id` hash across workers; each worker processes its shard independently.
- **Anomaly scoring** — `AnomalyDetectionPipeline.predict()` is stateless after `fit()`; run multiple replicas behind a load balancer.
- **Cluster detection** — for graphs exceeding 10M edges, replace NetworkX with Apache Spark's GraphFrames.
- **Alerting** — replace the in-process dispatch loop with a Celery task queue backed by Redis for async delivery.

**Storage estimates at 10M events/day:**

| Data Type | Daily Volume | Annual Volume | Recommended Store |
|-----------|-------------|---------------|-------------------|
| Raw events (PostgreSQL) | ~2 GB/day | ~730 GB | Partition + S3 Parquet archive |
| Feature matrices | ~50 MB/cycle | — | In-memory / Redis cache |
| Model artifacts | ~5 MB | ~2 GB (versioned) | Local fs / S3 |
| Alert incidents (log) | ~10 MB/day | ~3.5 GB | Log aggregator (Datadog, CloudWatch) |

---

## 12. Failure Recovery

| Failure Scenario | How It's Detected | Recovery |
|-----------------|------------------|---------|
| DB connection lost | SQLAlchemy pool timeout | Automatic reconnect with exponential backoff |
| Model file missing at startup | `FileNotFoundError` on `load_model` | Fall back to last known-good artifact from S3 |
| Feature NaN values | Checked in `build_feature_matrix` | `fillna(0)` — graceful degradation, lower confidence |
| Webhook delivery failure | HTTP non-2xx or connection error | Retry up to 3× with 5-second exponential backoff |
| Pipeline crash | Unhandled exception in scoring loop | Systemd / Kubernetes liveness probe restarts service |
| Threshold drift | Live FPR exceeds 2× target | `auto_adjust_threshold()` raises threshold; on-call alert via `check_escalation_spike` |

All failure events are written to `logs/pipeline.log` with ISO 8601 timestamps and module-level context. The rotating handler caps the file at 10 MB with 5 backups.

---

## 13. Roadmap

| Phase | Feature | Target |
|-------|---------|--------|
| v1.1 | Kafka consumer for streaming micro-batch ingestion | Q1 |
| v1.2 | Spark / GraphFrames for billion-edge cluster detection | Q2 |
| v1.3 | Online learning — incremental IsolationForest on daily deltas | Q2 |
| v1.4 | Multi-tenant isolation — per-tenant feature spaces and thresholds | Q3 |
| v2.0 | LLM-assisted alert triage — summarize cluster evidence with context | Q4 |
| v2.1 | Federated learning — train across regions without data egress | H2 |

---

For a deeper dive into the system design, storage decisions, and deployment strategy, see [ARCHITECTURE.md](ARCHITECTURE.md).
