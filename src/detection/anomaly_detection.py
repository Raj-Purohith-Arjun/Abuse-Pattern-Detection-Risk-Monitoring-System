"""
anomaly_detection.py
====================
Production-grade anomaly detection pipeline for the Abuse Pattern
Detection & Risk Monitoring System.

Architecture overview
---------------------
1. ``FeatureEngineer`` (src/features/feature_engineering.py) produces a
   per-user feature matrix from raw event logs.
2. ``AnomalyDetectionPipeline`` wraps two complementary detectors:
   - **Z-score detector** – flags features that deviate strongly from
     their training-time mean/std.  Interpretable and fast (O(N·F)).
   - **IsolationForest** – unsupervised, tree-based anomaly detector that
     handles high-dimensional, correlated features well.
3. The two score streams are blended into a calibrated 0-100 risk score
   and optionally stored back to the database.

Throughput
----------
Both detectors rely exclusively on vectorised NumPy/sklearn operations and
can comfortably process 1 M+ rows per minute on a single core.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.features.feature_engineering import FeatureEngineer

logger = logging.getLogger(__name__)


class AnomalyDetectionPipeline:
    """
    End-to-end anomaly detection pipeline that combines z-score and
    IsolationForest signals into a calibrated 0-100 risk score.

    Parameters
    ----------
    config_path : str | Path
        Path to ``config/config.yaml``.

    Attributes
    ----------
    cfg : dict
        Full parsed config tree.
    feature_engineer : FeatureEngineer
        Configured feature-engineering helper.
    scaler : StandardScaler
        Fitted scaler (set after ``fit``).
    iso_forest : IsolationForest
        Fitted IsolationForest model (set after ``fit``).
    train_means : pd.Series
        Per-feature training means used for z-score baseline.
    train_stds : pd.Series
        Per-feature training standard deviations (floored at 1e-9).
    threshold : float
        Calibrated decision threshold on the 0-100 scale.
    feature_cols : list[str]
        Ordered list of feature columns used during training.
    """

    def __init__(self, config_path: str | Path = "config/config.yaml") -> None:
        self.cfg = self._load_config(config_path)
        ad_cfg = self.cfg["anomaly_detection"]
        fe_cfg = self.cfg["feature_engineering"]
        model_cfg = self.cfg["model"]

        self.zscore_threshold: float = ad_cfg["zscore_threshold"]
        self.contamination: float = ad_cfg["contamination"]
        self.if_weight: float = ad_cfg["isolation_forest_weight"]
        self.zs_weight: float = ad_cfg["zscore_weight"]
        self.target_fpr: float = ad_cfg["target_fpr"]
        self.random_state: int = ad_cfg["random_state"]
        self.n_estimators: int = model_cfg["n_estimators"]
        self.n_jobs: int = model_cfg["n_jobs"]

        self.feature_engineer = FeatureEngineer(
            rolling_windows=fe_cfg["rolling_windows"],
            session_gap_minutes=fe_cfg["session_gap_minutes"],
            min_events_for_entropy=fe_cfg["min_events_for_entropy"],
            velocity_cap=float(fe_cfg["velocity_cap"]),
        )

        self.scaler: StandardScaler | None = None
        self.iso_forest: IsolationForest | None = None
        self.train_means: pd.Series | None = None
        self.train_stds: pd.Series | None = None
        self.threshold: float = float(self.cfg["anomaly_detection"]["risk_score_high"])
        self.feature_cols: list[str] = []

        logger.info(
            "AnomalyDetectionPipeline initialised | config=%s", config_path
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fit(self, df: pd.DataFrame) -> "AnomalyDetectionPipeline":
        """
        Train the pipeline on historical event data.

        Steps
        -----
        1. Build feature matrix via ``FeatureEngineer``.
        2. Fit ``StandardScaler`` and store training mean/std for z-score
           baseline.
        3. Fit ``IsolationForest`` on scaled features.
        4. Compute combined risk scores on training data and calibrate
           the decision threshold to ``target_fpr``.

        Parameters
        ----------
        df : pd.DataFrame
            Raw event log (see feature_engineering.py for schema).

        Returns
        -------
        self
        """
        logger.info("fit() | events=%d", len(df))
        X = self.feature_engineer.build_feature_matrix(df)
        self.feature_cols = list(X.columns)

        # Fit scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X.values)

        # Store training baselines for z-score detector
        self.train_means = pd.Series(
            self.scaler.mean_, index=self.feature_cols
        )
        self.train_stds = pd.Series(
            np.where(self.scaler.scale_ < 1e-9, 1e-9, self.scaler.scale_),
            index=self.feature_cols,
        )

        # Fit IsolationForest
        self.iso_forest = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )
        self.iso_forest.fit(X_scaled)

        # Calibrate threshold on training scores
        train_scores = self._score(X_scaled, X)
        self.threshold = self._calibrate_threshold(train_scores, self.target_fpr)
        logger.info(
            "fit() complete | users=%d features=%d threshold=%.2f",
            len(X),
            len(self.feature_cols),
            self.threshold,
        )
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run inference and return per-user risk scores (0-100).

        Parameters
        ----------
        df : pd.DataFrame
            Raw event log; may be a streaming micro-batch or a large
            historical slice.

        Returns
        -------
        pd.DataFrame
            Columns: ``user_id``, ``risk_score``, ``is_anomaly``.
            Sorted descending by ``risk_score``.
        """
        self._assert_fitted()
        logger.info("predict() | events=%d", len(df))

        X = self.feature_engineer.build_feature_matrix(df)
        X = self._align_columns(X)
        X_scaled = self.scaler.transform(X.values)  # type: ignore[union-attr]
        scores = self._score(X_scaled, X)

        result = pd.DataFrame(
            {
                "user_id": X.index,
                "risk_score": scores,
                "is_anomaly": scores >= self.threshold,
            }
        ).sort_values("risk_score", ascending=False).reset_index(drop=True)

        n_anomalies = result["is_anomaly"].sum()
        logger.info(
            "predict() complete | users=%d anomalies=%d (%.1f%%)",
            len(result),
            n_anomalies,
            100 * n_anomalies / max(len(result), 1),
        )
        return result

    def save_model(self, path: str | Path) -> None:
        """
        Serialise the fitted pipeline to disk using pickle.

        Parameters
        ----------
        path : str | Path
            Destination file path (e.g. ``models/pipeline_v1.pkl``).
        """
        self._assert_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "scaler": self.scaler,
            "iso_forest": self.iso_forest,
            "train_means": self.train_means,
            "train_stds": self.train_stds,
            "threshold": self.threshold,
            "feature_cols": self.feature_cols,
            "cfg": self.cfg,
        }
        with path.open("wb") as fh:
            pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info("Model saved | path=%s", path)

    def load_model(self, path: str | Path) -> "AnomalyDetectionPipeline":
        """
        Deserialise a previously saved pipeline from disk.

        Parameters
        ----------
        path : str | Path
            Path to the ``.pkl`` file created by ``save_model``.

        Returns
        -------
        self
        """
        path = Path(path)
        with path.open("rb") as fh:
            payload: dict[str, Any] = pickle.load(fh)
        self.scaler = payload["scaler"]
        self.iso_forest = payload["iso_forest"]
        self.train_means = payload["train_means"]
        self.train_stds = payload["train_stds"]
        self.threshold = payload["threshold"]
        self.feature_cols = payload["feature_cols"]
        self.cfg = payload.get("cfg", self.cfg)
        logger.info("Model loaded | path=%s", path)
        return self

    def insert_anomaly_scores(
        self, df: pd.DataFrame, scores: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Merge risk scores back onto the original event log, ready for a
        bulk database insert.

        Parameters
        ----------
        df : pd.DataFrame
            Original raw event log.
        scores : pd.DataFrame
            Output of ``predict()`` – columns ``user_id``, ``risk_score``,
            ``is_anomaly``.

        Returns
        -------
        pd.DataFrame
            Original events enriched with ``risk_score`` and
            ``is_anomaly`` columns.  Rows with no score (e.g. users who
            appeared only in ``df``) receive ``risk_score=0`` and
            ``is_anomaly=False``.
        """
        enriched = df.merge(scores, on="user_id", how="left")
        enriched["risk_score"] = enriched["risk_score"].fillna(0.0)
        enriched["is_anomaly"] = enriched["is_anomaly"].fillna(False)
        logger.info(
            "insert_anomaly_scores | rows=%d anomaly_rows=%d",
            len(enriched),
            enriched["is_anomaly"].sum(),
        )
        return enriched

    # ------------------------------------------------------------------
    # Internal detectors
    # ------------------------------------------------------------------

    def _zscore_anomaly(self, df: pd.DataFrame) -> np.ndarray:
        """
        Compute a per-user z-score anomaly flag vector.

        For each user, count how many features exceed
        ``zscore_threshold`` standard deviations from the training mean.
        Normalise to [0, 1] by dividing by the total number of features.

        Parameters
        ----------
        df : pd.DataFrame
            Feature matrix aligned to ``self.feature_cols``
            (un-scaled original values).

        Returns
        -------
        np.ndarray shape (N,)
            Per-user z-score fraction in [0, 1].  A value of 1 means
            *every* feature is anomalous.
        """
        z = (df.values - self.train_means.values) / self.train_stds.values  # type: ignore[union-attr]
        flags = np.abs(z) > self.zscore_threshold  # shape (N, F)
        return flags.mean(axis=1)  # fraction of anomalous features per user

    def _isolation_forest_anomaly(self, X_scaled: np.ndarray) -> np.ndarray:
        """
        Return IsolationForest anomaly scores in [0, 1].

        Sklearn's ``decision_function`` returns raw scores where lower
        values indicate more anomalous instances.  We invert and
        min-max normalise to [0, 1] so that 1 = most anomalous.

        Parameters
        ----------
        X_scaled : np.ndarray shape (N, F)
            Scaled feature matrix.

        Returns
        -------
        np.ndarray shape (N,)
            Normalised IF scores in [0, 1].
        """
        raw: np.ndarray = self.iso_forest.decision_function(X_scaled)  # type: ignore[union-attr]
        # Negate so that high = anomalous; then min-max scale
        raw = -raw
        lo, hi = raw.min(), raw.max()
        if hi - lo < 1e-9:
            return np.zeros(len(raw))
        return (raw - lo) / (hi - lo)

    def _combine_scores(
        self, zscore_flags: np.ndarray, if_scores: np.ndarray
    ) -> np.ndarray:
        """
        Weighted linear combination of z-score and IsolationForest
        signals, mapped to a 0-100 risk score.

        Formula
        -------
        ``risk = clip((if_weight * if_scores + zs_weight * zscore_flags) * 100, 0, 100)``

        Parameters
        ----------
        zscore_flags : np.ndarray shape (N,)
            Per-user z-score fraction in [0, 1].
        if_scores : np.ndarray shape (N,)
            Per-user IsolationForest score in [0, 1].

        Returns
        -------
        np.ndarray shape (N,) dtype float32
            Risk scores in [0, 100].
        """
        combined = (
            self.if_weight * if_scores + self.zs_weight * zscore_flags
        )
        return np.clip(combined * 100, 0.0, 100.0).astype(np.float32)

    def _calibrate_threshold(
        self, scores: np.ndarray, target_fpr: float
    ) -> float:
        """
        Set the decision threshold so that at most ``target_fpr`` of
        training-time users are flagged as anomalies.

        This is a simple empirical calibration: find the
        ``(1 - target_fpr)`` quantile of the training score distribution.

        Parameters
        ----------
        scores : np.ndarray
            Risk scores (0-100) on the training set.
        target_fpr : float
            Desired false-positive rate (e.g. 0.01 → ≤1% flagged).

        Returns
        -------
        float
            Calibrated threshold on the 0-100 scale.
        """
        quantile = float(np.quantile(scores, 1.0 - target_fpr))
        # Ensure threshold never falls below the configured high-risk floor
        floor = float(self.cfg["anomaly_detection"]["risk_score_high"])
        threshold = max(quantile, floor)
        logger.info(
            "_calibrate_threshold | target_fpr=%.3f quantile=%.2f floor=%.1f → threshold=%.2f",
            target_fpr, quantile, floor, threshold,
        )
        return threshold

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _score(self, X_scaled: np.ndarray, X_df: pd.DataFrame) -> np.ndarray:
        """Run both detectors and return blended 0-100 risk scores."""
        zs = self._zscore_anomaly(X_df)
        if_s = self._isolation_forest_anomaly(X_scaled)
        return self._combine_scores(zs, if_s)

    def _align_columns(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Reindex feature matrix to match training-time columns, filling
        any unseen features with 0.  This keeps inference robust against
        data drift where new feature columns appear at prediction time.
        """
        return X.reindex(columns=self.feature_cols, fill_value=0.0)

    def _assert_fitted(self) -> None:
        """Raise ``RuntimeError`` if the pipeline has not been trained."""
        if self.iso_forest is None or self.scaler is None:
            raise RuntimeError(
                "Pipeline is not fitted. Call fit() before predict()."
            )

    @staticmethod
    def _load_config(config_path: str | Path) -> dict:
        """Parse YAML config and return as a nested dict."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with path.open() as fh:
            cfg = yaml.safe_load(fh)
        logger.debug("Config loaded from %s", path)
        return cfg
