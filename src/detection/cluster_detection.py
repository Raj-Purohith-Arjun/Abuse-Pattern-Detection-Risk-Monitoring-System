"""
cluster_detection.py
====================
Graph-based abuse cluster detection for the Abuse Pattern Detection &
Risk Monitoring System.

Design rationale
----------------
Individual anomaly scores (from ``anomaly_detection.py``) can miss
*coordinated* abuse where each individual account looks almost clean, but
the group of accounts exhibits shared infrastructure (IPs, devices, timing
patterns).  This module builds an undirected weighted graph where:

  - **Nodes** represent user accounts.
  - **Edges** represent shared signals (IP address or device ID) between
    pairs of users, weighted by signal strength and temporal proximity.

Community detection (connected components by default; Louvain when
``python-louvain`` is installed) then groups accounts into clusters, each
of which receives a composite risk score.

Complexity summary
------------------
- ``build_graph``              O(N · log N) via groupby + merge
- ``_compute_edge_weights``    O(E) where E = number of shared-signal pairs
- ``detect_clusters``          O(N + E)  (connected components)
- ``score_clusters``           O(N + E)
- ``escalate_risks``           O(K)  where K = number of clusters
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class AbuseClusterDetector:
    """
    Graph-based detector that surfaces coordinated abuse rings by
    connecting users who share network or device infrastructure.

    Parameters
    ----------
    min_shared_signals : int
        Minimum number of shared IP/device signals required to create an
        edge between two users (noise filter; default: 1).
    temporal_window_hours : float
        Maximum gap between events on the same IP/device for two users to
        be considered temporally overlapping (default: 24 h).
    cluster_risk_threshold : float
        Cluster risk score at or above which a cluster is escalated
        (default: 60.0 on a 0-100 scale).
    """

    def __init__(
        self,
        min_shared_signals: int = 1,
        temporal_window_hours: float = 24.0,
        cluster_risk_threshold: float = 60.0,
    ) -> None:
        self.min_shared_signals = min_shared_signals
        self.temporal_window_hours = temporal_window_hours
        self.cluster_risk_threshold = cluster_risk_threshold
        logger.info(
            "AbuseClusterDetector initialised | min_signals=%d temporal_window=%.1fh threshold=%.1f",
            min_shared_signals,
            temporal_window_hours,
            cluster_risk_threshold,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_graph(self, df: pd.DataFrame) -> nx.Graph:
        """
        Construct a weighted undirected graph from raw event logs.

        Nodes
        -----
        Each unique ``user_id`` becomes a node.  Node attributes:
          - ``event_count`` : total events by this user
          - ``unique_ips``  : number of distinct IPs used
          - ``unique_devices`` : number of distinct devices used

        Edges
        -----
        An edge (u, v) is created when users *u* and *v* share at least
        ``min_shared_signals`` IP addresses or device IDs within
        ``temporal_window_hours`` of each other.  Edge attributes:
          - ``weight``           : composite edge weight ∈ (0, 1]
          - ``shared_ips``       : number of shared IP addresses
          - ``shared_devices``   : number of shared device IDs
          - ``temporal_overlap`` : fraction of shared events within window

        Complexity: O(N · log N) for groupby; O(S²) worst-case for signal
        pairs where S = average users per shared signal (typically small).

        Parameters
        ----------
        df : pd.DataFrame
            Raw event log with columns:
            ``user_id``, ``ip_address``, ``device_id``, ``timestamp``.

        Returns
        -------
        nx.Graph
            Populated graph ready for ``detect_clusters``.
        """
        self._validate(df)
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

        G: nx.Graph = nx.Graph()

        # Add nodes with summary stats
        node_stats = df.groupby("user_id").agg(
            event_count=("user_id", "count"),
            unique_ips=("ip_address", "nunique"),
            unique_devices=("device_id", "nunique"),
        )
        for uid, row in node_stats.iterrows():
            G.add_node(
                uid,
                event_count=int(row["event_count"]),
                unique_ips=int(row["unique_ips"]),
                unique_devices=int(row["unique_devices"]),
            )

        # Build edges via shared-signal pairs
        edge_data = self._compute_edge_weights(df)
        for (u, v), attrs in edge_data.items():
            if attrs["total_shared"] >= self.min_shared_signals:
                G.add_edge(u, v, **attrs)

        logger.info(
            "build_graph complete | nodes=%d edges=%d",
            G.number_of_nodes(),
            G.number_of_edges(),
        )
        return G

    def _compute_edge_weights(
        self, df: pd.DataFrame
    ) -> dict[tuple[Any, Any], dict[str, Any]]:
        """
        Derive weighted edges from shared IP and device signals.

        Algorithm
        ---------
        For each shared signal (IP or device), find all pairs of users
        that used it.  For each pair compute:

          1. **shared_count** – how many distinct signals they share.
          2. **temporal_overlap** – fraction of shared events where the
             timestamps of the two users are within
             ``temporal_window_hours`` of each other.

        The composite edge weight is:

            weight = tanh(shared_count) × (0.5 + 0.5 × temporal_overlap)

        where ``tanh`` soft-caps the count contribution so that a very
        large shared count does not dominate, and the temporal factor
        rewards closer temporal proximity.

        Complexity: O(S²) per signal value, O(E_total) overall, where
        S is the mean number of users per shared signal.

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log.

        Returns
        -------
        dict mapping (user_a, user_b) → edge attribute dict.
        """
        tw = pd.Timedelta(hours=self.temporal_window_hours)
        edges: dict[tuple[Any, Any], dict[str, Any]] = {}

        for signal_col in ("ip_address", "device_id"):
            signal_key = "shared_ips" if signal_col == "ip_address" else "shared_devices"

            # For each signal value, collect (user_id, timestamp) pairs
            grouped = (
                df.groupby(signal_col)["user_id"]
                .apply(set)
                .reset_index()
                .rename(columns={"user_id": "users"})
            )
            # Only signals shared by ≥2 users are interesting
            shared = grouped[grouped["users"].apply(len) >= 2]

            for _, row in shared.iterrows():
                users = list(row["users"])
                # Timestamps per user for this signal value
                ts_map: dict[Any, pd.Series] = {
                    uid: df.loc[
                        df["user_id"] == uid, "timestamp"
                    ].reset_index(drop=True)
                    for uid in users
                }
                # Generate all unique pairs
                for i in range(len(users)):
                    for j in range(i + 1, len(users)):
                        u, v = users[i], users[j]
                        key = (min(u, v), max(u, v))

                        # Temporal overlap: do any events fall within window?
                        ts_u = ts_map[u].values
                        ts_v = ts_map[v].values
                        # Broadcasting: |ts_u - ts_v| ≤ tw
                        diff = np.abs(
                            ts_u[:, None].astype("datetime64[ns]")
                            - ts_v[None, :].astype("datetime64[ns]")
                        )
                        overlap_count = int((diff <= tw.to_timedelta64()).sum())
                        max_pairs = len(ts_u) * len(ts_v)
                        temporal_overlap = overlap_count / max_pairs if max_pairs else 0.0

                        if key not in edges:
                            edges[key] = {
                                "shared_ips": 0,
                                "shared_devices": 0,
                                "temporal_overlap": temporal_overlap,
                                "total_shared": 0,
                            }
                        else:
                            # Update temporal overlap as a running mean
                            prev = edges[key]["temporal_overlap"]
                            edges[key]["temporal_overlap"] = (prev + temporal_overlap) / 2.0

                        edges[key][signal_key] = edges[key].get(signal_key, 0) + 1
                        edges[key]["total_shared"] += 1

        # Compute composite weight for each edge
        for key, attrs in edges.items():
            count = attrs["total_shared"]
            t_overlap = attrs["temporal_overlap"]
            attrs["weight"] = float(np.tanh(count) * (0.5 + 0.5 * t_overlap))

        return edges

    def detect_clusters(
        self, G: nx.Graph, use_louvain: bool = False
    ) -> list[set[Any]]:
        """
        Partition the graph into abuse clusters.

        By default, uses NetworkX connected components (exact, O(N+E)).
        If ``use_louvain=True`` and the ``community`` package is
        installed, the Louvain method is used instead for finer-grained
        sub-community detection.

        Parameters
        ----------
        G : nx.Graph
            Graph produced by ``build_graph``.
        use_louvain : bool
            Attempt Louvain community detection (requires
            ``python-louvain``).  Falls back to connected components if
            the package is not available.

        Returns
        -------
        list[set]
            Each element is a set of ``user_id`` values belonging to one
            cluster.  Clusters are sorted descending by size.
        """
        if use_louvain:
            try:
                import community as community_louvain  # type: ignore[import]
                partition: dict[Any, int] = community_louvain.best_partition(G)
                cluster_map: dict[int, set] = {}
                for node, cid in partition.items():
                    cluster_map.setdefault(cid, set()).add(node)
                clusters = list(cluster_map.values())
                logger.info("detect_clusters | method=louvain clusters=%d", len(clusters))
            except ImportError:
                logger.warning(
                    "python-louvain not installed; falling back to connected components"
                )
                clusters = list(nx.connected_components(G))
        else:
            clusters = list(nx.connected_components(G))
            logger.info(
                "detect_clusters | method=connected_components clusters=%d", len(clusters)
            )

        # Sort largest clusters first
        clusters.sort(key=len, reverse=True)
        return clusters

    def score_clusters(
        self, G: nx.Graph, clusters: list[set[Any]]
    ) -> list[dict[str, Any]]:
        """
        Assign a composite risk score (0-100) to each cluster.

        Scoring factors
        ---------------
        1. **size_score** – logarithmic function of cluster size;
           large clusters are more suspicious: ``min(log2(size+1)/log2(101), 1)``.
        2. **density_score** – edge density of the subgraph (0-1).
        3. **weight_score** – mean edge weight across the subgraph (0-1).
        4. **node_event_score** – mean per-node event count, normalised
           by the 95th percentile of all node event counts.

        Final score = 100 × mean(size_score, density_score,
                                  weight_score, node_event_score).

        Complexity: O(K · (N_k + E_k)) where N_k, E_k are nodes and
        edges per cluster k.

        Parameters
        ----------
        G : nx.Graph
            Graph produced by ``build_graph``.
        clusters : list[set]
            Output of ``detect_clusters``.

        Returns
        -------
        list[dict]
            Each dict contains:
            ``cluster_id``, ``size``, ``members``, ``risk_score``,
            ``density``, ``mean_edge_weight``.
            Sorted descending by ``risk_score``.
        """
        all_event_counts = np.array([
            G.nodes[n].get("event_count", 1) for n in G.nodes
        ], dtype=float)
        p95 = float(np.percentile(all_event_counts, 95)) or 1.0

        scored: list[dict[str, Any]] = []
        for cid, members in enumerate(clusters):
            sub: nx.Graph = G.subgraph(members)
            size = len(members)

            size_score = min(np.log2(size + 1) / np.log2(101), 1.0)

            density = nx.density(sub) if size > 1 else 0.0

            weights = [d["weight"] for _, _, d in sub.edges(data=True) if "weight" in d]
            mean_weight = float(np.mean(weights)) if weights else 0.0

            event_counts = np.array([
                sub.nodes[n].get("event_count", 1) for n in members
            ], dtype=float)
            node_event_score = float(np.clip(event_counts.mean() / p95, 0, 1))

            risk = 100.0 * np.mean([
                size_score, density, mean_weight, node_event_score
            ])

            scored.append(
                {
                    "cluster_id": cid,
                    "size": size,
                    "members": list(members),
                    "risk_score": round(float(risk), 2),
                    "density": round(density, 4),
                    "mean_edge_weight": round(mean_weight, 4),
                }
            )

        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        logger.info(
            "score_clusters | clusters=%d top_score=%.2f",
            len(scored),
            scored[0]["risk_score"] if scored else 0.0,
        )
        return scored

    def escalate_risks(
        self,
        clusters: list[dict[str, Any]],
        threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        """
        Filter clusters whose risk score meets or exceeds the threshold.

        Parameters
        ----------
        clusters : list[dict]
            Output of ``score_clusters``.
        threshold : float | None
            Override ``self.cluster_risk_threshold`` for this call.

        Returns
        -------
        list[dict]
            High-risk clusters, each enriched with ``escalated=True``.
            Sorted descending by ``risk_score``.
        """
        cutoff = threshold if threshold is not None else self.cluster_risk_threshold
        escalated = [
            {**c, "escalated": True}
            for c in clusters
            if c["risk_score"] >= cutoff
        ]
        logger.info(
            "escalate_risks | threshold=%.1f total=%d escalated=%d",
            cutoff,
            len(clusters),
            len(escalated),
        )
        return escalated

    def simulate_example(self) -> dict[str, Any]:
        """
        Generate synthetic event data and run the full detection pipeline
        as a self-contained demonstration.

        Simulation design
        -----------------
        - 50 legitimate users, each operating from 1-3 unique IPs and
          1-2 devices over a 7-day window.
        - 3 coordinated abuse rings (sizes 8, 5, 4) sharing a pool of
          2-3 IPs and 1-2 devices, with tightly clustered timestamps.
        - All events are labelled with ``enforced=0/1`` to exercise the
          full feature pipeline.

        Returns
        -------
        dict with keys:
          ``dataframe``  – synthetic pd.DataFrame
          ``graph``      – nx.Graph
          ``clusters``   – scored cluster list
          ``escalated``  – high-risk cluster list
        """
        random.seed(42)
        np.random.seed(42)

        base_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
        rows: list[dict[str, Any]] = []
        actions = ["login", "search", "purchase", "view", "logout"]

        def _make_events(
            user_id: str,
            ips: list[str],
            devices: list[str],
            n: int,
            start: datetime,
            jitter_hours: float = 168.0,
        ) -> None:
            for _ in range(n):
                ts = start + timedelta(
                    seconds=random.uniform(0, jitter_hours * 3600)
                )
                rows.append(
                    {
                        "user_id": user_id,
                        "ip_address": random.choice(ips),
                        "device_id": random.choice(devices),
                        "session_id": f"sess_{user_id}_{random.randint(1, 5)}",
                        "action": random.choice(actions),
                        "timestamp": ts,
                        "enforced": int(random.random() < 0.05),
                    }
                )

        # Legitimate users
        for i in range(50):
            uid = f"legit_{i:03d}"
            ips = [f"10.0.{i}.{j}" for j in range(random.randint(1, 3))]
            devices = [f"dev_L{i}_{k}" for k in range(random.randint(1, 2))]
            _make_events(uid, ips, devices, random.randint(10, 40), base_time)

        # Abuse rings
        ring_specs = [
            ("ring_A", 8, ["192.168.1.10", "192.168.1.11"], ["dev_shared_A1", "dev_shared_A2"], 2.0),
            ("ring_B", 5, ["10.10.0.5"], ["dev_shared_B1"], 1.0),
            ("ring_C", 4, ["172.16.0.3", "172.16.0.4"], ["dev_shared_C1"], 3.0),
        ]
        for ring_name, size, shared_ips, shared_devices, jitter_h in ring_specs:
            for k in range(size):
                uid = f"{ring_name}_user_{k}"
                _make_events(
                    uid,
                    shared_ips,
                    shared_devices,
                    random.randint(15, 50),
                    base_time,
                    jitter_h,
                )

        df = pd.DataFrame(rows)

        G = self.build_graph(df)
        clusters_raw = self.detect_clusters(G)
        clusters_scored = self.score_clusters(G, clusters_raw)
        escalated = self.escalate_risks(clusters_scored)

        logger.info(
            "simulate_example | events=%d users=%d escalated_clusters=%d",
            len(df),
            df["user_id"].nunique(),
            len(escalated),
        )
        return {
            "dataframe": df,
            "graph": G,
            "clusters": clusters_scored,
            "escalated": escalated,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate(df: pd.DataFrame) -> None:
        """Raise ``ValueError`` if required columns are absent."""
        required = {"user_id", "ip_address", "device_id", "timestamp"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"DataFrame missing required columns: {missing}")
        if df.empty:
            raise ValueError("Input DataFrame is empty.")
