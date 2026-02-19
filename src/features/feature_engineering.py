"""
feature_engineering.py
=======================
Vectorised feature engineering for the Abuse Pattern Detection & Risk
Monitoring System.

Expected input DataFrame columns
---------------------------------
user_id        : str/int  - unique user identifier
ip_address     : str      - IPv4/IPv6 address of the request
device_id      : str      - fingerprinted device identifier
session_id     : str      - session token / identifier
action         : str      - event/action type (e.g. "login", "purchase")
timestamp      : datetime - UTC event timestamp (timezone-aware or naive)
enforced       : bool/int - 1 if an enforcement action was taken, else 0

All computations are fully vectorised (no Python-level loops over rows).
"""

from __future__ import annotations

import logging
from typing import List

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Builds a rich feature matrix from raw event logs for downstream
    anomaly detection.

    Parameters
    ----------
    rolling_windows : list[int]
        Rolling window sizes **in minutes** used for action-frequency
        features (default: [5, 15, 60]).
    session_gap_minutes : int
        Idle gap that defines a new session boundary (default: 30).
    min_events_for_entropy : int
        Minimum number of events a user must have before IP entropy is
        computed; users below this threshold receive entropy = 0.
    velocity_cap : float
        Maximum allowed events-per-second value to suppress extreme
        outliers from inflating model inputs.
    """

    def __init__(
        self,
        rolling_windows: List[int] | None = None,
        session_gap_minutes: int = 30,
        min_events_for_entropy: int = 3,
        velocity_cap: float = 1000.0,
    ) -> None:
        self.rolling_windows: List[int] = rolling_windows or [5, 15, 60]
        self.session_gap_minutes: int = session_gap_minutes
        self.min_events_for_entropy: int = min_events_for_entropy
        self.velocity_cap: float = velocity_cap
        logger.info(
            "FeatureEngineer initialised | windows=%s session_gap=%dm",
            self.rolling_windows,
            self.session_gap_minutes,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_feature_matrix(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Orchestrate all feature computations and return a single wide
        DataFrame indexed by ``user_id``.

        Parameters
        ----------
        df : pd.DataFrame
            Raw event log with the columns described at module level.

        Returns
        -------
        pd.DataFrame
            One row per user, columns = all engineered features.
            No NaN values (filled with 0).
        """
        self._validate(df)
        df = self._prepare(df)

        logger.info("Building feature matrix for %d events / %d users",
                    len(df), df["user_id"].nunique())

        freq = self.compute_action_frequency(df)
        entropy = self.compute_ip_entropy(df)
        reuse = self.compute_device_reuse_score(df)
        velocity = self.compute_session_velocity(df)
        enforcement = self.compute_enforcement_history_rate(df)

        feature_matrix = (
            freq
            .join(entropy, how="outer")
            .join(reuse, how="outer")
            .join(velocity, how="outer")
            .join(enforcement, how="outer")
            .fillna(0.0)
        )

        logger.info(
            "Feature matrix built | shape=%s", feature_matrix.shape
        )
        return feature_matrix

    def compute_action_frequency(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Count actions per user within each rolling time window.

        The function groups by ``user_id`` and time-based rolling windows
        to produce per-user action counts, then aggregates to a per-user
        summary (mean and max count observed across the time-series).

        Complexity
        ----------
        O(N · W) where N = number of events, W = number of rolling windows.

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log (output of ``_prepare``).

        Returns
        -------
        pd.DataFrame
            Index = user_id.  Columns:
            ``action_freq_{w}m_mean``, ``action_freq_{w}m_max``
            for each window w in ``self.rolling_windows``.
        """
        df = df.sort_values(["user_id", "timestamp"])
        results: dict[str, pd.Series] = {}

        for window in self.rolling_windows:
            win_str = f"{window}min"
            # Rolling count per user using time-based window
            rolled = (
                df.set_index("timestamp")
                .groupby("user_id")["action"]
                .rolling(win_str)
                .count()
                .rename(f"count_{window}m")
            )
            rolled = rolled.reset_index(level=0, drop=True)
            tmp = df[["user_id"]].copy()
            tmp[f"count_{window}m"] = rolled.values

            grp = tmp.groupby("user_id")[f"count_{window}m"]
            results[f"action_freq_{window}m_mean"] = grp.mean()
            results[f"action_freq_{window}m_max"] = grp.max()

        return pd.DataFrame(results)

    def compute_ip_entropy(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute the Shannon entropy of the IP address distribution for
        each user.

        A legitimate user typically connects from a small, stable set of
        IPs.  High entropy signals a diverse / rotating IP pool, which is
        a strong abuse indicator.

        H(X) = -Σ p_i · log2(p_i)

        Users with fewer than ``min_events_for_entropy`` events receive
        entropy = 0 (insufficient signal).

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log.

        Returns
        -------
        pd.DataFrame
            Index = user_id.  Columns: ``ip_entropy``, ``unique_ip_count``.
        """
        counts = (
            df.groupby(["user_id", "ip_address"])["action"]
            .count()
            .rename("ip_count")
            .reset_index()
        )
        # Total events per user
        total = df.groupby("user_id")["action"].count().rename("total")
        counts = counts.join(total, on="user_id")
        counts["p"] = counts["ip_count"] / counts["total"]
        # p * log2(p) — avoid log(0) by masking
        counts["p_log_p"] = np.where(
            counts["p"] > 0, counts["p"] * np.log2(counts["p"]), 0.0
        )
        entropy = (
            counts.groupby("user_id")["p_log_p"]
            .sum()
            .mul(-1)
            .rename("ip_entropy")
        )
        unique_ips = (
            df.groupby("user_id")["ip_address"]
            .nunique()
            .rename("unique_ip_count")
        )
        event_counts = df.groupby("user_id")["action"].count()
        # Zero-out entropy for users with insufficient events
        mask = event_counts < self.min_events_for_entropy
        entropy.loc[mask[mask].index] = 0.0

        return pd.DataFrame({"ip_entropy": entropy, "unique_ip_count": unique_ips})

    def compute_device_reuse_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Measure how many distinct user accounts share each device, then
        aggregate to a per-user score.

        A device shared across many accounts is a strong cluster signal.

        Score formula per user
        ----------------------
        ``device_reuse_score`` = mean(accounts_sharing_device - 1)
        across all devices used by the user, capped at 1 (normalised).

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log.

        Returns
        -------
        pd.DataFrame
            Index = user_id.  Columns: ``device_reuse_score``,
            ``max_device_sharing``.
        """
        device_sharing = (
            df.groupby("device_id")["user_id"]
            .nunique()
            .rename("users_per_device")
            .reset_index()
        )
        merged = df[["user_id", "device_id"]].drop_duplicates().merge(
            device_sharing, on="device_id", how="left"
        )
        # Excess users beyond the owning account
        merged["excess"] = (merged["users_per_device"] - 1).clip(lower=0)
        grp = merged.groupby("user_id")["excess"]
        score = grp.mean().rename("device_reuse_score")
        max_sharing = grp.max().rename("max_device_sharing")

        # Normalise score to [0, 1] using global max to keep it bounded
        global_max = score.max()
        if global_max > 0:
            score = score / global_max

        return pd.DataFrame(
            {"device_reuse_score": score, "max_device_sharing": max_sharing}
        )

    def compute_session_velocity(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute the rate of events per unit time within each session, then
        aggregate to per-user statistics.

        Sessions are delimited by a ``session_gap_minutes`` idle gap.
        Velocity = (event_count - 1) / session_duration_seconds, capped at
        ``velocity_cap`` to suppress noise from single-event sessions.

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log.

        Returns
        -------
        pd.DataFrame
            Index = user_id.  Columns: ``session_velocity_mean``,
            ``session_velocity_max``, ``session_count``.
        """
        gap = pd.Timedelta(minutes=self.session_gap_minutes)
        df = df.sort_values(["user_id", "timestamp"])

        # Assign session IDs: new session whenever gap between events > threshold
        time_diff = df.groupby("user_id")["timestamp"].diff()
        new_session = (time_diff > gap) | time_diff.isna()
        df = df.copy()
        df["_session_seq"] = new_session.groupby(df["user_id"]).cumsum()
        df["_session_key"] = df["user_id"].astype(str) + "_" + df["_session_seq"].astype(str)

        sess = df.groupby("_session_key").agg(
            user_id=("user_id", "first"),
            n_events=("action", "count"),
            duration_s=(
                "timestamp",
                lambda s: (s.max() - s.min()).total_seconds(),
            ),
        )
        # Events per second; guard zero-duration (single-event) sessions
        sess["velocity"] = np.where(
            sess["duration_s"] > 0,
            (sess["n_events"] - 1) / sess["duration_s"],
            0.0,
        ).clip(max=self.velocity_cap)

        grp = sess.groupby("user_id")["velocity"]
        mean_vel = grp.mean().rename("session_velocity_mean")
        max_vel = grp.max().rename("session_velocity_max")
        sess_count = sess.groupby("user_id").size().rename("session_count")

        return pd.DataFrame(
            {
                "session_velocity_mean": mean_vel,
                "session_velocity_max": max_vel,
                "session_count": sess_count,
            }
        )

    def compute_enforcement_history_rate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate the fraction of past events for each user that resulted
        in an enforcement action.

        A rising enforcement rate is a strong recidivism signal.

        Parameters
        ----------
        df : pd.DataFrame
            Prepared event log.  Must contain an ``enforced`` column
            (1 = action taken, 0 = clean).

        Returns
        -------
        pd.DataFrame
            Index = user_id.  Columns: ``enforcement_rate``,
            ``total_enforcements``, ``total_events``.
        """
        if "enforced" not in df.columns:
            logger.warning("'enforced' column missing; defaulting enforcement features to 0")
            users = df["user_id"].unique()
            zero = pd.Series(0.0, index=users)
            return pd.DataFrame(
                {
                    "enforcement_rate": zero,
                    "total_enforcements": zero.astype(int),
                    "total_events": df.groupby("user_id")["action"].count(),
                }
            )

        grp = df.groupby("user_id")
        total = grp["action"].count().rename("total_events")
        enforcements = grp["enforced"].sum().rename("total_enforcements")
        rate = (enforcements / total).rename("enforcement_rate").fillna(0.0)

        return pd.DataFrame(
            {
                "enforcement_rate": rate,
                "total_enforcements": enforcements,
                "total_events": total,
            }
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self, df: pd.DataFrame) -> None:
        """Raise ``ValueError`` if required columns are absent."""
        required = {"user_id", "ip_address", "device_id", "session_id",
                    "action", "timestamp"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Input DataFrame missing columns: {missing}")
        if df.empty:
            raise ValueError("Input DataFrame is empty.")

    def _prepare(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Coerce types and sort for downstream computation.

        - Converts ``timestamp`` to UTC-aware datetime if not already.
        - Ensures ``enforced`` is numeric (int) when present.
        - Drops duplicate events (same user + timestamp + action).
        """
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        if "enforced" in df.columns:
            df["enforced"] = pd.to_numeric(df["enforced"], errors="coerce").fillna(0).astype(int)
        df = df.drop_duplicates(subset=["user_id", "timestamp", "action"])
        df = df.sort_values(["user_id", "timestamp"]).reset_index(drop=True)
        return df
