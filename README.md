# Abuse Pattern Detection & Risk Monitoring System

A production-grade system for detecting coordinated abuse patterns and monitoring risk at scale, designed to handle 10M+ behavioral events per day with near real-time detection (≤5 min latency).

---

## Features

| Task | Component | Description |
|------|-----------|-------------|
| 1 | Architecture | Scalable system design — see [ARCHITECTURE.md](ARCHITECTURE.md) |
| 2 | SQL Schema | 8-table PostgreSQL schema with partitioning & indexing — [`sql/schema.sql`](sql/schema.sql) |
| 3 | SQL Queries | 7 advanced abuse-detection queries with CTEs & window functions — [`sql/queries.sql`](sql/queries.sql) |
| 4 | Anomaly Detection | Z-score + Isolation Forest pipeline producing 0–100 risk scores — [`src/detection/anomaly_detection.py`](src/detection/anomaly_detection.py) |
| 5 | Cluster Detection | Graph-based coordinated abuse cluster detection — [`src/detection/cluster_detection.py`](src/detection/cluster_detection.py) |
| 6 | Threshold Calibration | ROC/PR curve optimisation with ≤2% FPR constraint — [`src/calibration/threshold_calibration.py`](src/calibration/threshold_calibration.py) |
| 7 | Dashboard Spec | Executive & analyst dashboard specifications with SQL extracts — [`src/dashboard/dashboard_spec.py`](src/dashboard/dashboard_spec.py) |
| 8 | Alerting Engine | Real-time webhook alerting with dedup, rate-limiting & retry — [`src/alerting/alert_engine.py`](src/alerting/alert_engine.py) |
| 9 | Testing | 37-test pytest suite covering all modules — [`tests/`](tests/) |
| 10 | Deployment | Docker, docker-compose, and GitHub Actions CI — [`Dockerfile`](Dockerfile), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

---

## Project Structure

```
.
├── ARCHITECTURE.md              # Full system architecture documentation
├── Dockerfile                   # Multi-stage container build
├── docker-compose.yml           # App + PostgreSQL service definitions
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
├── config/
│   └── config.yaml              # Config-driven settings (thresholds, DB, alerting)
├── sql/
│   ├── schema.sql               # PostgreSQL schema (partitioned, indexed)
│   └── queries.sql              # 7 advanced abuse-detection queries
├── src/
│   ├── features/
│   │   └── feature_engineering.py   # Vectorized feature computation
│   ├── detection/
│   │   ├── anomaly_detection.py     # Z-score + Isolation Forest pipeline
│   │   └── cluster_detection.py     # Graph-based cluster detection
│   ├── calibration/
│   │   └── threshold_calibration.py # ROC/PR threshold optimisation
│   ├── alerting/
│   │   └── alert_engine.py          # Real-time webhook alerting
│   └── dashboard/
│       └── dashboard_spec.py        # Dashboard metric & SQL specifications
└── tests/
    ├── test_feature_engineering.py
    ├── test_anomaly_detection.py
    ├── test_cluster_detection.py
    ├── test_threshold_calibration.py
    └── test_alerting.py
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure the system
Edit `config/config.yaml` — replace DB credentials and webhook URL placeholders.

### 3. Apply the database schema
```bash
psql -U <user> -d <database> -f sql/schema.sql
```

### 4. Run anomaly detection
```python
from src.features.feature_engineering import FeatureEngineer
from src.detection.anomaly_detection import AnomalyDetectionPipeline

fe = FeatureEngineer(config_path="config/config.yaml")
pipeline = AnomalyDetectionPipeline(config_path="config/config.yaml")

features = fe.build_feature_matrix(events_df)
pipeline.fit(features)
scored = pipeline.predict(features)
```

### 5. Detect abuse clusters
```python
from src.detection.cluster_detection import AbuseClusterDetector

detector = AbuseClusterDetector(config_path="config/config.yaml")
G = detector.build_graph(events_df)
clusters = detector.detect_clusters(G)
escalated = detector.escalate_risks(detector.score_clusters(G, clusters), threshold=60)
```

### 6. Run with Docker
```bash
docker-compose up --build
```

### 7. Run tests
```bash
pytest tests/ -v
```

---

## Key Design Decisions

- **Partitioning**: `raw_events` is range-partitioned by month for fast time-range pruning
- **Dual anomaly detection**: Z-score (statistical) + Isolation Forest (ML) combined into a single 0–100 risk score
- **False positive control**: Threshold calibration enforces ≤2% FPR while maximising recall
- **Graph clustering**: NetworkX connected components with temporal edge weighting to detect coordinated abuse rings
- **Real-time alerting**: Deduplication + token-bucket rate limiting + exponential backoff retries

---

## CI/CD

GitHub Actions runs on every push and PR to `main`:
- **lint**: `flake8` style checks
- **test**: `pytest` with coverage report (uploaded as artifact)
