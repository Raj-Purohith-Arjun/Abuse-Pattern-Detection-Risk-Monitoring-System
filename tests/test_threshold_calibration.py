"""
Tests for ThresholdCalibrator (src/calibration/threshold_calibration.py).
"""

import textwrap

import numpy as np
import pytest

from src.calibration.threshold_calibration import ThresholdCalibrator


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


def _make_labels_and_scores(n_benign: int = 900, n_abuse: int = 100, seed: int = 42):
    """Synthetic scores: abuse users score higher on average."""
    rng = np.random.default_rng(seed)
    benign_scores = rng.uniform(0, 50, n_benign)
    abuse_scores = rng.uniform(50, 100, n_abuse)
    y_scores = np.concatenate([benign_scores, abuse_scores])
    y_true = np.array([0] * n_benign + [1] * n_abuse)
    return y_true, y_scores


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_file(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(MINIMAL_CONFIG)
    return cfg


@pytest.fixture
def calibrator(config_file):
    return ThresholdCalibrator(config_path=config_file)


@pytest.fixture
def labels_and_scores():
    return _make_labels_and_scores()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_compute_roc_curve_equal_length(calibrator, labels_and_scores):
    y_true, y_scores = labels_and_scores
    fpr, tpr, thresholds = calibrator.compute_roc_curve(y_true, y_scores)
    assert len(fpr) == len(tpr) == len(thresholds)


def test_compute_roc_curve_fpr_range(calibrator, labels_and_scores):
    y_true, y_scores = labels_and_scores
    fpr, tpr, _ = calibrator.compute_roc_curve(y_true, y_scores)
    assert (fpr >= 0).all() and (fpr <= 1).all()


def test_find_optimal_threshold_fpr_constraint(calibrator, labels_and_scores):
    y_true, y_scores = labels_and_scores
    threshold = calibrator.find_optimal_threshold(y_true, y_scores, max_fpr=0.02)
    # Verify the threshold actually keeps FPR at or below 2%
    actual_fpr = calibrator.compute_false_positive_rate(y_true, y_scores, threshold)
    assert actual_fpr <= 0.02 + 1e-6, (
        f"FPR {actual_fpr:.4f} exceeds 2% target at threshold {threshold:.2f}"
    )


def test_auto_adjust_threshold_moves_toward_target(calibrator):
    # If observed_fpr > target_fpr, threshold should increase
    new_t = calibrator.auto_adjust_threshold(
        current_threshold=50.0, observed_fpr=0.10, target_fpr=0.02
    )
    assert new_t > 50.0, "Threshold should increase when observed FPR exceeds target"

    # If observed_fpr < target_fpr, threshold should decrease
    new_t2 = calibrator.auto_adjust_threshold(
        current_threshold=50.0, observed_fpr=0.001, target_fpr=0.02
    )
    assert new_t2 < 50.0, "Threshold should decrease when observed FPR is below target"


def test_generate_threshold_report_keys(calibrator, labels_and_scores):
    y_true, y_scores = labels_and_scores
    report = calibrator.generate_threshold_report(y_true, y_scores)
    expected_keys = {
        "optimal_threshold",
        "max_fpr_constraint",
        "fpr",
        "tpr",
        "fnr",
        "roc_auc",
        "average_precision",
        "roc_curve",
        "pr_curve",
        "model_version",
    }
    assert expected_keys.issubset(report.keys()), (
        f"Missing keys: {expected_keys - set(report.keys())}"
    )


def test_save_threshold_to_db_sql_valid(calibrator):
    sql = calibrator.save_threshold_to_db_sql(
        metric_name="combined_risk_score",
        threshold_value=75.0,
        fpr=0.015,
        fnr=0.08,
    )
    assert isinstance(sql, str)
    assert "INSERT" in sql.upper() or "threshold_history" in sql.lower()
    assert "combined_risk_score" in sql
    assert "75" in sql


def test_false_positive_rate_all_benign(calibrator):
    y_true = np.zeros(100)
    y_scores = np.linspace(0, 100, 100)
    fpr = calibrator.compute_false_positive_rate(y_true, y_scores, threshold=50.0)
    assert 0.0 <= fpr <= 1.0
