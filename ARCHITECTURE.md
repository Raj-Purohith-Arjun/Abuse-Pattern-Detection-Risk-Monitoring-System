# Abuse Pattern Detection & Risk Monitoring System — Architecture

## 1. System Overview

The Abuse Pattern Detection & Risk Monitoring System is a production-grade,
Python-based platform that ingests user event streams, engineers behavioural
features, scores each user and cluster in near-real-time with calibrated risk
scores, and dispatches actionable alerts to on-call teams via webhook.

The system is designed to detect:
- **Individual anomalies** – single accounts behaving outside their historical
  norm (automated account takeover, credential stuffing, scraping).
- **Coordinated abuse rings** – groups of accounts sharing network or device
  infrastructure (fake review farms, fraud rings, bot networks).

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Ingestion Layer                                  │
│  ┌──────────────┐   ┌────────────────┐   ┌───────────────────────────┐  │
│  │  Event Stream│──▶│ Batch Loader / │──▶│  Raw Event Store          │  │
│  │ (Kafka/Files)│   │ Stream Reader  │   │  (PostgreSQL / S3 Parquet)│  │
│  └──────────────┘   └────────────────┘   └───────────────────────────┘  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Feature Engineering Layer                         │
│   src/features/feature_engineering.py — FeatureEngineer                 │
│                                                                          │
│   • Action frequency (rolling 5 / 15 / 60 min windows)                  │
│   • IP entropy (Shannon H per user)                                      │
│   • Device reuse score (shared-device normalised 0-1)                   │
│   • Session velocity (events / second per session)                       │
│   • Enforcement history rate (fraction of enforced events)               │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
┌──────────────────────────┐     ┌───────────────────────────────────────┐
│  Anomaly Detection       │     │  Cluster / Graph Detection             │
│  src/detection/          │     │  src/detection/cluster_detection.py    │
│  anomaly_detection.py    │     │                                        │
│                          │     │  • Build user–user graph               │
│  • Z-score detector      │     │    (edges = shared IP / device)        │
│  • IsolationForest       │     │  • Detect communities (connected        │
│  • Weighted blend →      │     │    components / Louvain)               │
│    0-100 risk score      │     │  • Score clusters 0-100                │
└──────────────┬───────────┘     └──────────────────┬────────────────────┘
               │                                     │
               └──────────────┬──────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Threshold Calibration Layer                           │
│   src/calibration/threshold_calibration.py — ThresholdCalibrator        │
│                                                                          │
│   • Compute ROC / PR curves                                              │
│   • Find optimal threshold at target FPR (default 2%)                   │
│   • Auto-adjust threshold from live FPR feedback                        │
│   • Persist calibrated thresholds to threshold_history table            │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Alerting Layer                                   │
│   src/alerting/alert_engine.py — AlertEngine                            │
│                                                                          │
│   • Deduplication cache (per-entity, configurable window)               │
│   • Token-bucket rate limiter (max N alerts / 60 s)                     │
│   • HTTP webhook dispatch with exponential-backoff retry                │
│   • Structured JSON incident log (rotating file)                        │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                      ┌─────────────┴────────────────┐
                      ▼                              ▼
             ┌─────────────────┐          ┌─────────────────────┐
             │  Webhook / Slack│          │  Dashboard          │
             │  PagerDuty / etc│          │  (Grafana / custom) │
             └─────────────────┘          └─────────────────────┘
```

---

## 3. Component Breakdown

| Module | Class | Responsibility |
|---|---|---|
| `src/features/feature_engineering.py` | `FeatureEngineer` | Vectorised feature extraction from raw event logs |
| `src/detection/anomaly_detection.py` | `AnomalyDetectionPipeline` | Z-score + IsolationForest blended scoring |
| `src/detection/cluster_detection.py` | `AbuseClusterDetector` | Graph-based coordinated-abuse detection |
| `src/calibration/threshold_calibration.py` | `ThresholdCalibrator` | ROC-driven threshold selection and auto-adjustment |
| `src/alerting/alert_engine.py` | `AlertEngine` | Rate-limited, deduped webhook dispatch |
| `src/dashboard/dashboard_spec.py` | Dashboard helpers | Metric aggregation for BI/dashboard serving |
| `config/config.yaml` | — | Single source of configuration truth |
| `sql/schema.sql` | — | PostgreSQL DDL for all tables |
| `sql/queries.sql` | — | Pre-built analytical queries |

---

## 4. Data Flow Explanation

```
Raw Events (CSV / Kafka topic / DB table)
    │
    ▼
FeatureEngineer.build_feature_matrix()
    │  → per-user wide feature matrix (no NaNs)
    ▼
AnomalyDetectionPipeline.predict()
    │  → DataFrame[user_id, risk_score, is_anomaly]
    ▼
AbuseClusterDetector.build_graph() + score_clusters()
    │  → list of cluster dicts with risk scores
    ▼
ThresholdCalibrator.find_optimal_threshold()  (calibration batch)
    │  → float threshold persisted to DB
    ▼
AlertEngine.check_risk_threshold() / check_cluster_threshold()
    │  → HTTP POST to webhook if threshold exceeded
    ▼
Incident log + Dashboard metrics update
```

---

## 5. Storage Layer Decisions

| Data | Store | Rationale |
|---|---|---|
| Raw event logs | **PostgreSQL** (OLTP) + **S3 Parquet** (archive) | Queryable for recent events; cheap long-term storage |
| Feature matrices | In-memory (Pandas) or **Redis** cache | Avoid recomputing features per micro-batch |
| Model artefacts | **Local filesystem / S3** (`.pkl`) | `save_model` / `load_model` API |
| Threshold history | **PostgreSQL** `threshold_history` table | Full audit trail of threshold changes |
| Alert incidents | **Rotating JSON log file** (`logs/incidents.log`) | Durable, searchable, ingestible by any log aggregator |
| Cluster graphs | In-memory `networkx.Graph` | Rebuilt per detection cycle; no persistence required |

---

## 6. Batch vs Streaming Strategy

**Batch (default)**
- Scheduled every N minutes (e.g., Airflow DAG or cron).
- Reads all events from the last interval from PostgreSQL.
- Rebuilds the feature matrix, scores users, and fires alerts.
- Suitable for workloads where near-real-time latency (< 5 min) is acceptable.

**Streaming (future)**
- Kafka consumer reads events in micro-batches (e.g., 30-second windows).
- `FeatureEngineer` supports incremental window updates.
- `AnomalyDetectionPipeline.predict()` accepts any sized DataFrame, so
  micro-batch scoring is a drop-in replacement.
- Flink or Spark Structured Streaming would manage state across windows.

**Decision factors**

| Factor | Batch | Streaming |
|---|---|---|
| Latency requirement | > 1 min | < 30 s |
| Infrastructure cost | Low | Higher |
| Complexity | Low | Significant |
| Current system need | ✓ | Roadmap |

---

## 7. Risk Scoring Pipeline

```
Raw features (F dimensions)
    │
    ├─▶ StandardScaler.transform()
    │       │
    │       ├─▶ Z-score detector
    │       │       fraction of anomalous features per user → [0, 1]
    │       │
    │       └─▶ IsolationForest.decision_function()
    │               inverted + min-max normalised → [0, 1]
    │
    └─▶ Weighted blend:
            risk = clip((0.55 × IF_score + 0.45 × Z_score) × 100, 0, 100)
```

- Weights and thresholds are configurable in `config/config.yaml`.
- The decision threshold is calibrated to `target_fpr` (default 1%) on the
  training distribution using the `(1 − target_fpr)` quantile.
- `ThresholdCalibrator` can dynamically adjust the threshold based on live FPR
  feedback without model retraining.

---

## 8. Dashboard Serving Strategy

- `src/dashboard/dashboard_spec.py` defines metric aggregations and chart
  specifications (JSON-serialisable).
- Metric snapshots are written to a `dashboard_metrics` table in PostgreSQL
  on every scoring cycle.
- **Grafana** connects to PostgreSQL via the native data source plugin and
  renders:
  - Risk score distribution (histogram).
  - Top-N high-risk users (table panel).
  - Alert rate over time (time-series).
  - Cluster network graph (Node Graph panel).
- Alternatively, a lightweight FastAPI endpoint can serve `/metrics` (JSON)
  for a custom React dashboard.
- No server-side rendering is required; all queries are read-only against
  the analytics replica.

---

## 9. Alerting Mechanism

```
AlertEngine.check_risk_threshold(user_id, score)
    │
    ├── score < threshold? → return False (no alert)
    │
    ├── Dedup check: same user alerted within dedup_window seconds?
    │       └── yes → increment deduplicated counter, return False
    │
    ├── Rate limit: > rate_limit dispatches in last 60 s?
    │       └── yes → drop alert, return False
    │
    └── Dispatch: requests.post(webhook_url, json=payload)
            ├── success (2xx) → log to incidents.log, increment sent
            └── failure → exponential-backoff retry (up to retry_attempts)
                    └── all retries exhausted → log failure, increment failed
```

**Channels supported:**
- HTTP webhook (Slack, PagerDuty, Teams, custom)
- Email (configurable in `config.yaml`, disabled by default)

**Deduplication key:** `{alert_type}:{entity_id}` — ensures each entity is
alerted at most once per `dedup_window` seconds regardless of score changes.

---

## 10. Scalability Considerations

| Concern | Approach |
|---|---|
| High event throughput | Vectorised Pandas/NumPy; horizontal scaling via partitioning by `user_id` hash |
| Large user population | Feature matrix is `O(U × F)` where U = users; tested at 1 M+ users/min on a single core |
| Model retraining | Scheduled daily (`retrain_interval=86400 s`); models serialised to S3 via `save_model` |
| Graph detection at scale | `AbuseClusterDetector` uses NetworkX; swap to `GraphFrames` (Spark) for > 10 M edges |
| Alert fan-out | Token-bucket rate limiter prevents alert storms; webhook async dispatch queued via Celery for high throughput |

---

## 11. Cost Optimisation

- **Feature computation on DB replica** — avoids read load on the primary.
- **S3 Parquet archival** — 10× cheaper than keeping all events in PostgreSQL.
- **Model caching** — load the pickled pipeline once at service startup;
  `n_jobs=-1` parallelises scoring across CPU cores.
- **Selective alerting** — deduplication and rate limiting dramatically reduce
  webhook call volume.
- **Auto-scaling** — containerised app service scales to zero during off-peak
  hours in Kubernetes (HPA on CPU).

---

## 12. Failure Recovery Strategy

| Failure | Detection | Recovery |
|---|---|---|
| DB connection lost | SQLAlchemy pool timeout exception | Automatic reconnect with exponential backoff |
| Model file missing | `FileNotFoundError` on `load_model` | Fall back to last-known-good model from S3 |
| Feature engineering NaN | `fillna(0)` in `build_feature_matrix` | Graceful degradation; anomaly detected at lower confidence |
| Webhook delivery failure | HTTP non-2xx or exception | Retry with exponential backoff; log to `incidents.log` |
| Pipeline crash | Unhandled exception in scoring loop | Process supervisor (systemd / Kubernetes liveness probe) restarts service |
| Threshold drift | Live FPR exceeds target by > 2× | `auto_adjust_threshold` raises threshold; on-call alert via `check_escalation_spike` |

---

## 13. Deployment Plan

### Local Development
```bash
docker compose up --build
```

### Staging / Production (Kubernetes)
```
1. Build Docker image:
   docker build -t abuse-detection:latest .

2. Push to registry:
   docker push registry.example.com/abuse-detection:latest

3. Apply Kubernetes manifests:
   kubectl apply -f k8s/

4. Verify:
   kubectl rollout status deployment/abuse-detection
```

### CI/CD (GitHub Actions — `.github/workflows/ci.yml`)
- **lint** job: `flake8 src/` on every push / PR to `main`.
- **test** job: `pytest tests/ --cov=src` with coverage report uploaded as
  workflow artefact.

### Database migrations
- `sql/schema.sql` is idempotent (`CREATE TABLE IF NOT EXISTS`).
- Applied automatically via `docker-entrypoint-initdb.d` in the Compose stack.

---

## 14. Future Scalability Roadmap

| Phase | Feature | Timeline |
|---|---|---|
| v1.1 | Kafka consumer for streaming micro-batches | Q1 |
| v1.2 | Spark / GraphFrames for billion-edge cluster detection | Q2 |
| v1.3 | Online learning — partial-fit IsolationForest on daily deltas | Q2 |
| v1.4 | Multi-tenant isolation — per-tenant feature spaces and thresholds | Q3 |
| v2.0 | LLM-assisted alert triage — GPT-4o summarises cluster evidence | Q4 |
| v2.1 | Federated learning — train across regions without data egress | H2 |
