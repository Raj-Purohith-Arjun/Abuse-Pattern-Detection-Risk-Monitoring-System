"""
Tests for AbuseClusterDetector (src/detection/cluster_detection.py).
"""

import pandas as pd
import pytest

from src.detection.cluster_detection import AbuseClusterDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cluster_df():
    """
    Build a minimal DataFrame with two clear clusters:
    - users A and B share IP 1.2.3.4
    - users C and D share IP 5.6.7.8
    - user E has a unique IP
    """
    rows = []
    base = pd.Timestamp("2024-01-01 00:00:00", tz="UTC")
    delta = pd.Timedelta(minutes=10)

    for i, (uid, ip, dev) in enumerate(
        [
            ("A", "1.2.3.4", "dev1"),
            ("B", "1.2.3.4", "dev2"),
            ("C", "5.6.7.8", "dev3"),
            ("D", "5.6.7.8", "dev4"),
            ("E", "9.9.9.9", "dev5"),
        ]
    ):
        for j in range(5):
            rows.append(
                {
                    "user_id": uid,
                    "ip_address": ip,
                    "device_id": dev,
                    "session_id": f"sess_{uid}_{j}",
                    "action": "login",
                    "timestamp": base + delta * (i * 5 + j),
                    "enforced": 0,
                }
            )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def detector():
    return AbuseClusterDetector(min_shared_signals=1, cluster_risk_threshold=0.0)


@pytest.fixture
def cluster_df():
    return _make_cluster_df()


@pytest.fixture
def built_graph(detector, cluster_df):
    return detector.build_graph(cluster_df)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_build_graph_node_count(detector, cluster_df, built_graph):
    unique_users = cluster_df["user_id"].nunique()
    assert built_graph.number_of_nodes() == unique_users


def test_shared_ip_creates_edge(built_graph):
    """Users A and B share IP 1.2.3.4 → they must be connected."""
    assert built_graph.has_edge("A", "B"), "A and B share an IP and should be connected"
    assert built_graph.has_edge("C", "D"), "C and D share an IP and should be connected"


def test_unrelated_user_not_connected(built_graph):
    """User E has a unique IP and should not share an edge with A."""
    assert not built_graph.has_edge("A", "E")
    assert not built_graph.has_edge("C", "E")


def test_detect_clusters_nonempty(detector, built_graph):
    clusters = detector.detect_clusters(built_graph)
    assert len(clusters) > 0


def test_detect_clusters_covers_all_users(detector, built_graph, cluster_df):
    clusters = detector.detect_clusters(built_graph)
    all_members = set().union(*clusters)
    assert all_members == set(cluster_df["user_id"].unique())


def test_score_clusters_range(detector, built_graph):
    clusters = detector.detect_clusters(built_graph)
    scored = detector.score_clusters(built_graph, clusters)
    for c in scored:
        assert 0 <= c["risk_score"] <= 100, f"risk_score={c['risk_score']} out of range"


def test_score_clusters_required_keys(detector, built_graph):
    clusters = detector.detect_clusters(built_graph)
    scored = detector.score_clusters(built_graph, clusters)
    expected_keys = {"cluster_id", "size", "members", "risk_score", "density", "mean_edge_weight"}
    for c in scored:
        assert expected_keys.issubset(c.keys())


def test_simulate_example_returns_escalated(detector):
    result = detector.simulate_example()
    assert "escalated" in result
    assert isinstance(result["escalated"], list)
    assert len(result["escalated"]) > 0, "simulate_example should return at least one escalated cluster"


def test_simulate_example_no_error():
    d = AbuseClusterDetector()
    result = d.simulate_example()
    assert "dataframe" in result
    assert "graph" in result
    assert "clusters" in result
