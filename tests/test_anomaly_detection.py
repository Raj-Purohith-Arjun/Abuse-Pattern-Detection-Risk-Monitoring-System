"""
Tests for AnomalyDetectionPipeline (src/detection/anomaly_detection.py).
"""

import textwrap

import numpy as np
import pandas as pd
import pytest

from src.detection.anomaly_detection import AnomalyDetectionPipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = textwrap.dedent("""\
    database:
      host: localhost
      port: 5432
      name: test_db
      user: test_user
      password: test_pass
      pool_size: 2
      max_overflow: 2
      connect_timeout: 5

    anomaly_detection:
      zscore_threshold: 3.0
      contamination: 0.05
      risk_score_high: 70
      risk_score_medium: 40
      target_fpr: 0.05
      isolation_forest_weight: 0.55
      zscore_weight: 0.45
      random_state: 42

    feature_engineering:
      rolling_windows: [5, 15]
      session_gap_minutes: 30
      min_events_for_entropy: 3
      velocity_cap: 1000.0

    alerting:
      webhook_url: http://localhost/webhook
      rate_limit: 60
      dedup_window: 300
      retry_attempts: 3
      retry_backoff_seconds: 1
      channels: []

    model:
      model_version: "0.0.1"
      retrain_interval: 86400
      model_store_path: models/
      artifact_name: test_pipeline
      n_estimators: 10
      max_samples: auto
      n_jobs: 1

    logging:
      level: WARNING
      format: "%(message)s"
      file: logs/test.log
      max_bytes: 1048576
      backup_count: 1
""")


def _make_event_df(n_users: int = 60, events_per_user: int = 20, seed: int = 0):
    """Generate a synthetic event log."""
    rng = np.random.default_rng(seed)
    rows = []
    base_ts = pd.Timestamp("2024-01-01", tz="UTC")
    for i in range(n_users):
        uid = f"user_{i:04d}"
        for j in range(events_per_user):
            rows.append(
                {
                    "user_id": uid,
                    "ip_address": f"10.0.{rng.integers(0,5)}.{rng.integers(1,255)}",
                    "device_id": f"dev_{rng.integers(0, 10)}",
                    "session_id": f"sess_{i}_{j // 5}",
                    "action": rng.choice(["login", "search", "view"]),
                    "timestamp": base_ts + pd.Timedelta(minutes=int(j * 2 + rng.integers(0, 3))),
                    "enforced": int(rng.random() < 0.05),
                }
            )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_file(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(MINIMAL_CONFIG)
    return cfg


@pytest.fixture
def pipeline(config_file):
    return AnomalyDetectionPipeline(config_path=config_file)


@pytest.fixture
def fitted_pipeline(pipeline):
    df = _make_event_df(n_users=80)
    pipeline.fit(df)
    return pipeline, df


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_fit_does_not_raise(pipeline):
    df = _make_event_df(n_users=60)
    pipeline.fit(df)  # should not raise


def test_predict_returns_risk_score_column(fitted_pipeline):
    pipeline, df = fitted_pipeline
    result = pipeline.predict(df)
    assert "risk_score" in result.columns


def test_predict_scores_in_range(fitted_pipeline):
    pipeline, df = fitted_pipeline
    result = pipeline.predict(df)
    assert (result["risk_score"] >= 0).all()
    assert (result["risk_score"] <= 100).all()


def test_predict_returns_all_users(fitted_pipeline):
    pipeline, df = fitted_pipeline
    result = pipeline.predict(df)
    assert set(result["user_id"]) == set(df["user_id"].unique())


def test_high_risk_users_score_higher(config_file):
    """Inject obviously anomalous users and check they score higher on average."""
    pipeline = AnomalyDetectionPipeline(config_path=config_file)
    normal_df = _make_event_df(n_users=80, seed=1)
    pipeline.fit(normal_df)

    # Build a small batch: normal users + synthetic high-risk users
    normal_sample = _make_event_df(n_users=20, seed=2)

    # High-risk users: extremely high event rate from many IPs
    rng = np.random.default_rng(99)
    hr_rows = []
    base_ts = pd.Timestamp("2024-01-01", tz="UTC")
    for i in range(5):
        uid = f"highrisk_{i}"
        for j in range(200):
            hr_rows.append(
                {
                    "user_id": uid,
                    "ip_address": f"192.168.{rng.integers(0,255)}.{rng.integers(1,255)}",
                    "device_id": f"shared_dev_{rng.integers(0,2)}",
                    "session_id": f"sess_hr_{i}_{j}",
                    "action": "purchase",
                    "timestamp": base_ts + pd.Timedelta(seconds=int(j)),
                    "enforced": 1,
                }
            )
    hr_df = pd.DataFrame(hr_rows)
    combined = pd.concat([normal_sample, hr_df], ignore_index=True)
    result = pipeline.predict(combined)

    hr_scores = result[result["user_id"].str.startswith("highrisk_")]["risk_score"].mean()
    normal_scores = result[result["user_id"].str.startswith("user_")]["risk_score"].mean()
    assert hr_scores > normal_scores, (
        f"High-risk mean {hr_scores:.2f} should exceed normal mean {normal_scores:.2f}"
    )


def test_insert_anomaly_scores_required_columns(fitted_pipeline):
    pipeline, df = fitted_pipeline
    scores = pipeline.predict(df)
    enriched = pipeline.insert_anomaly_scores(df, scores)
    assert "risk_score" in enriched.columns
    assert "is_anomaly" in enriched.columns
    assert "user_id" in enriched.columns
    assert len(enriched) == len(df)


def test_predict_before_fit_raises(pipeline):
    df = _make_event_df(n_users=10)
    with pytest.raises(RuntimeError):
        pipeline.predict(df)
