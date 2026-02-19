"""
Tests for FeatureEngineer (src/features/feature_engineering.py).
"""

import numpy as np
import pandas as pd
import pytest

from src.features.feature_engineering import FeatureEngineer


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_df():
    """Synthetic event log: 100 users, 1000 rows."""
    rng = np.random.default_rng(42)
    n_users = 100
    n_rows = 1000

    user_ids = [f"user_{i:03d}" for i in rng.integers(0, n_users, n_rows)]
    ip_pool = [f"10.0.{rng.integers(0, 5)}.{rng.integers(1, 255)}" for _ in range(50)]
    device_pool = [f"dev_{i}" for i in range(30)]
    actions = ["login", "search", "purchase", "view", "logout"]

    timestamps = pd.date_range("2024-01-01", periods=n_rows, freq="1min", tz="UTC")

    df = pd.DataFrame(
        {
            "user_id": user_ids,
            "ip_address": [ip_pool[rng.integers(0, len(ip_pool))] for _ in range(n_rows)],
            "device_id": [device_pool[rng.integers(0, len(device_pool))] for _ in range(n_rows)],
            "session_id": [f"sess_{i}" for i in rng.integers(0, 200, n_rows)],
            "action": [actions[rng.integers(0, len(actions))] for _ in range(n_rows)],
            "timestamp": timestamps,
            "enforced": rng.integers(0, 2, n_rows),
        }
    )
    return df


@pytest.fixture
def engineer():
    return FeatureEngineer(rolling_windows=[5, 15], session_gap_minutes=30)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_action_frequency_columns(engineer, sample_df):
    result = engineer.compute_action_frequency(sample_df)
    for window in [5, 15]:
        assert f"action_freq_{window}m_mean" in result.columns
        assert f"action_freq_{window}m_max" in result.columns


def test_ip_entropy_range(engineer, sample_df):
    result = engineer.compute_ip_entropy(sample_df)
    max_ips = sample_df.groupby("user_id")["ip_address"].nunique().max()
    max_entropy = np.log2(max_ips) if max_ips > 1 else 0.0
    assert (result["ip_entropy"] >= 0).all()
    assert (result["ip_entropy"] <= max_entropy + 1e-9).all()


def test_device_reuse_score_range(engineer, sample_df):
    result = engineer.compute_device_reuse_score(sample_df)
    assert (result["device_reuse_score"] >= 0).all()
    assert (result["device_reuse_score"] <= 1.0 + 1e-9).all()


def test_session_velocity_positive(engineer, sample_df):
    result = engineer.compute_session_velocity(sample_df)
    assert (result["session_velocity_mean"] >= 0).all()
    assert (result["session_velocity_max"] >= 0).all()


def test_enforcement_history_rate_range(engineer, sample_df):
    result = engineer.compute_enforcement_history_rate(sample_df)
    assert (result["enforcement_rate"] >= 0).all()
    assert (result["enforcement_rate"] <= 1.0 + 1e-9).all()


def test_build_feature_matrix_no_nan(engineer, sample_df):
    matrix = engineer.build_feature_matrix(sample_df)
    assert not matrix.isnull().any().any(), "Feature matrix contains NaN values"


def test_build_feature_matrix_has_all_users(engineer, sample_df):
    matrix = engineer.build_feature_matrix(sample_df)
    expected_users = set(sample_df["user_id"].unique())
    assert set(matrix.index) == expected_users


def test_missing_column_raises(engineer):
    df = pd.DataFrame({"user_id": ["u1"], "ip_address": ["1.2.3.4"]})
    with pytest.raises(ValueError, match="missing columns"):
        engineer.build_feature_matrix(df)
