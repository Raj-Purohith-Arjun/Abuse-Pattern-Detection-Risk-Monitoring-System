"""
Tests for AlertEngine (src/alerting/alert_engine.py).
"""

import textwrap
import time
from unittest.mock import MagicMock, patch

import pytest

from src.alerting.alert_engine import AlertEngine


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
      target_fpr: 0.02
      isolation_forest_weight: 0.55
      zscore_weight: 0.45
      random_state: 42

    feature_engineering:
      rolling_windows: [5, 15]
      session_gap_minutes: 30
      min_events_for_entropy: 3
      velocity_cap: 1000.0

    alerting:
      webhook_url: http://localhost/test-webhook
      rate_limit: 5
      dedup_window: 300
      retry_attempts: 1
      retry_backoff_seconds: 0
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_file(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(MINIMAL_CONFIG)
    # Ensure log dir exists inside tmp_path for incident logger
    (tmp_path / "logs").mkdir(exist_ok=True)
    return cfg


@pytest.fixture
def engine(config_file, tmp_path, monkeypatch):
    """Create AlertEngine with patched log directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir(exist_ok=True)
    return AlertEngine(config_path=config_file)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_high_risk_triggers_alert(engine):
    """score above threshold should dispatch an alert."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("requests.post", return_value=mock_response) as mock_post:
        sent = engine.check_risk_threshold("user_abc", risk_score=90.0)
    assert sent is True
    mock_post.assert_called_once()


def test_low_risk_does_not_trigger(engine):
    """score below threshold must NOT trigger an alert."""
    with patch("requests.post") as mock_post:
        sent = engine.check_risk_threshold("user_xyz", risk_score=20.0)
    assert sent is False
    mock_post.assert_not_called()


def test_deduplication_prevents_duplicate(engine):
    """Second alert for the same user within dedup window should be suppressed."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("requests.post", return_value=mock_response) as mock_post:
        first = engine.check_risk_threshold("user_dup", risk_score=95.0)
        second = engine.check_risk_threshold("user_dup", risk_score=95.0)

    assert first is True
    assert second is False
    assert mock_post.call_count == 1
    assert engine.get_alert_metrics()["deduplicated"] >= 1


def test_rate_limiting_prevents_excess_alerts(engine):
    """More than rate_limit alerts within 60 s should be rate-limited."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    rate_limit = engine.rate_limit  # 5 in the fixture config

    sent_count = 0
    with patch("requests.post", return_value=mock_response):
        for i in range(rate_limit + 5):
            if engine.check_risk_threshold(f"user_{i:04d}", risk_score=95.0):
                sent_count += 1

    assert sent_count <= rate_limit


def test_get_alert_metrics_keys(engine):
    """get_alert_metrics must return the expected keys."""
    metrics = engine.get_alert_metrics()
    assert "sent" in metrics
    assert "deduplicated" in metrics
    assert "failed" in metrics


def test_metrics_sent_increments(engine):
    """Successful send must increment the sent counter."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("requests.post", return_value=mock_response):
        engine.check_risk_threshold("user_metric_test", risk_score=95.0)
    assert engine.get_alert_metrics()["sent"] >= 1
