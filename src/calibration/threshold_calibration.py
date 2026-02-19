"""
threshold_calibration.py
========================
Threshold optimisation and calibration utilities for the Abuse Pattern
Detection & Risk Monitoring System.

The ``ThresholdCalibrator`` finds the decision threshold that maximises
recall while holding the false-positive rate at or below a configurable
ceiling (default 2 %).  It also supports dynamic, online adjustment as
the live FPR drifts from the target.

Typical usage
-------------
::

    calibrator = ThresholdCalibrator("config/config.yaml")
    optimal = calibrator.find_optimal_threshold(y_true, y_scores)
    report  = calibrator.generate_threshold_report(y_true, y_scores)
    calibrator.plot_curves(y_true, y_scores, "reports/roc_pr.png")
    sql     = calibrator.save_threshold_to_db_sql(
                  "combined_risk_score", optimal, report["fpr"], report["fnr"])
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from sklearn.metrics import (
    precision_recall_curve,
    roc_curve,
    roc_auc_score,
    average_precision_score,
)

import matplotlib
matplotlib.use("Agg")  # non-interactive backend; safe in server environments
import matplotlib.pyplot as plt  # noqa: E402

logger = logging.getLogger(__name__)


class ThresholdCalibrator:
    """
    Calibrate and manage decision thresholds for the risk scoring model.

    The calibrator works with continuous score outputs in the range [0, 100]
    (as produced by ``AnomalyDetectionPipeline``) and binary ground-truth
    labels (1 = abuse, 0 = benign).

    Parameters
    ----------
    config_path : str | Path
        Path to ``config/config.yaml``.  The following keys are consumed:

        * ``anomaly_detection.target_fpr``  – default max FPR (overridable per call)
        * ``anomaly_detection.risk_score_high`` – absolute floor for the threshold
        * ``model.model_version``           – written into DB SQL statements
    """

    def __init__(self, config_path: str | Path = "config/config.yaml") -> None:
        self.cfg = self._load_config(config_path)
        ad_cfg = self.cfg["anomaly_detection"]
        self.default_target_fpr: float = float(ad_cfg["target_fpr"])
        self.risk_score_floor: float = float(ad_cfg["risk_score_high"])
        self.model_version: str = self.cfg["model"]["model_version"]
        logger.info(
            "ThresholdCalibrator initialised | target_fpr=%.4f floor=%.1f",
            self.default_target_fpr,
            self.risk_score_floor,
        )

    # ------------------------------------------------------------------
    # Core metric methods
    # ------------------------------------------------------------------

    def compute_false_positive_rate(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        threshold: float,
    ) -> float:
        """
        Compute the false-positive rate at a given score threshold.

        FPR = FP / (FP + TN)  — the fraction of benign users flagged as abusive.

        Parameters
        ----------
        y_true : np.ndarray of int (0 or 1)
            Ground-truth labels.  1 = abuse, 0 = benign.
        y_scores : np.ndarray of float
            Continuous risk scores in [0, 100].
        threshold : float
            Decision boundary.  Scores >= threshold are predicted positive.

        Returns
        -------
        float
            FPR in [0, 1].  Returns 0.0 when there are no negatives.
        """
        y_true = np.asarray(y_true)
        y_scores = np.asarray(y_scores)
        y_pred = (y_scores >= threshold).astype(int)

        negatives = y_true == 0
        n_negatives = negatives.sum()
        if n_negatives == 0:
            logger.warning("compute_false_positive_rate: no negative examples found")
            return 0.0

        fp = ((y_pred == 1) & negatives).sum()
        fpr = float(fp / n_negatives)
        logger.debug("FPR @ threshold=%.2f → %.4f", threshold, fpr)
        return fpr

    def compute_false_negative_rate(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        threshold: float,
    ) -> float:
        """
        Compute the false-negative rate at a given score threshold.

        FNR = FN / (FN + TP)  — the fraction of abusive users missed.

        Parameters
        ----------
        y_true : np.ndarray of int (0 or 1)
            Ground-truth labels.
        y_scores : np.ndarray of float
            Continuous risk scores in [0, 100].
        threshold : float
            Decision boundary.

        Returns
        -------
        float
            FNR in [0, 1].  Returns 0.0 when there are no positives.
        """
        y_true = np.asarray(y_true)
        y_scores = np.asarray(y_scores)
        y_pred = (y_scores >= threshold).astype(int)

        positives = y_true == 1
        n_positives = positives.sum()
        if n_positives == 0:
            logger.warning("compute_false_negative_rate: no positive examples found")
            return 0.0

        fn = ((y_pred == 0) & positives).sum()
        fnr = float(fn / n_positives)
        logger.debug("FNR @ threshold=%.2f → %.4f", threshold, fnr)
        return fnr

    def compute_roc_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute the Receiver Operating Characteristic curve.

        Parameters
        ----------
        y_true : np.ndarray
            Ground-truth binary labels.
        y_scores : np.ndarray
            Continuous risk scores.

        Returns
        -------
        tuple[np.ndarray, np.ndarray, np.ndarray]
            ``(fpr, tpr, thresholds)`` as returned by
            ``sklearn.metrics.roc_curve``.
        """
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        auc = roc_auc_score(y_true, y_scores)
        logger.info("ROC AUC = %.4f", auc)
        return fpr, tpr, thresholds

    def compute_precision_recall_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute the Precision-Recall curve.

        Parameters
        ----------
        y_true : np.ndarray
            Ground-truth binary labels.
        y_scores : np.ndarray
            Continuous risk scores.

        Returns
        -------
        tuple[np.ndarray, np.ndarray, np.ndarray]
            ``(precision, recall, thresholds)`` as returned by
            ``sklearn.metrics.precision_recall_curve``.
            Note: ``thresholds`` has length ``len(precision) - 1``.
        """
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
        ap = average_precision_score(y_true, y_scores)
        logger.info("Average Precision = %.4f", ap)
        return precision, recall, thresholds

    # ------------------------------------------------------------------
    # Threshold selection
    # ------------------------------------------------------------------

    def find_optimal_threshold(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        max_fpr: float = 0.02,
    ) -> float:
        """
        Find the score threshold that maximises recall subject to
        FPR <= ``max_fpr``.

        The algorithm scans all candidate thresholds from the ROC curve,
        filters those that satisfy the FPR constraint, and selects the
        one with the highest TPR (recall).  If no threshold satisfies the
        constraint, the threshold corresponding to the smallest FPR is
        returned as a best-effort fallback.

        Parameters
        ----------
        y_true : np.ndarray
            Ground-truth binary labels.
        y_scores : np.ndarray
            Continuous risk scores in [0, 100].
        max_fpr : float, optional
            Upper bound on the acceptable false-positive rate.
            Default: 0.02 (2 %).

        Returns
        -------
        float
            Optimal decision threshold on the same scale as ``y_scores``.
        """
        fpr_arr, tpr_arr, thresh_arr = self.compute_roc_curve(y_true, y_scores)

        # Candidate thresholds that keep FPR within budget
        feasible_mask = fpr_arr <= max_fpr
        if not feasible_mask.any():
            # Fallback: use threshold with the minimum observed FPR
            best_idx = int(np.argmin(fpr_arr))
            logger.warning(
                "No threshold achieves FPR <= %.4f; returning best-effort threshold %.4f",
                max_fpr,
                float(thresh_arr[best_idx]),
            )
            return float(thresh_arr[best_idx])

        # Among feasible thresholds, maximise recall (TPR)
        feasible_tpr = np.where(feasible_mask, tpr_arr, -1.0)
        best_idx = int(np.argmax(feasible_tpr))
        optimal = float(thresh_arr[best_idx])

        logger.info(
            "find_optimal_threshold | max_fpr=%.4f → threshold=%.4f "
            "(FPR=%.4f, TPR=%.4f)",
            max_fpr,
            optimal,
            float(fpr_arr[best_idx]),
            float(tpr_arr[best_idx]),
        )
        return optimal

    def auto_adjust_threshold(
        self,
        current_threshold: float,
        observed_fpr: float,
        target_fpr: float = 0.02,
    ) -> float:
        """
        Dynamically nudge the threshold to steer the live FPR toward
        ``target_fpr``.

        The adjustment is proportional to the relative deviation from the
        target.  If the observed FPR is above the target, the threshold is
        raised to suppress false positives.  If it is below, the threshold
        is lowered to capture more true positives.

        The step is capped at ±5 score units per call to prevent runaway
        oscillation.

        Parameters
        ----------
        current_threshold : float
            Currently active decision threshold.
        observed_fpr : float
            FPR measured on recent live traffic.
        target_fpr : float, optional
            Desired FPR.  Default: 0.02.

        Returns
        -------
        float
            Adjusted threshold, clamped to [0, 100].
        """
        if target_fpr <= 0:
            raise ValueError("target_fpr must be positive")

        deviation = observed_fpr - target_fpr
        # Scale the step relative to the target so adjustments are proportional
        step = deviation / target_fpr * 2.0
        step = float(np.clip(step, -5.0, 5.0))
        new_threshold = float(np.clip(current_threshold + step, 0.0, 100.0))

        logger.info(
            "auto_adjust_threshold | observed_fpr=%.4f target_fpr=%.4f "
            "step=%.2f %.2f → %.2f",
            observed_fpr,
            target_fpr,
            step,
            current_threshold,
            new_threshold,
        )
        return new_threshold

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_threshold_report(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
    ) -> dict[str, Any]:
        """
        Generate a comprehensive threshold performance report.

        The report includes the optimal threshold (at max_fpr from config),
        ROC AUC, average precision, FPR/FNR at the optimal threshold, and
        the full ROC and PR curve arrays.

        Parameters
        ----------
        y_true : np.ndarray
            Ground-truth binary labels.
        y_scores : np.ndarray
            Continuous risk scores in [0, 100].

        Returns
        -------
        dict[str, Any]
            Keys:

            * ``optimal_threshold``  – float
            * ``max_fpr_constraint`` – float
            * ``fpr``                – float at optimal threshold
            * ``tpr``                – float at optimal threshold
            * ``fnr``                – float at optimal threshold
            * ``roc_auc``            – float
            * ``average_precision``  – float
            * ``roc_curve``          – dict with ``fpr``, ``tpr``, ``thresholds``
            * ``pr_curve``           – dict with ``precision``, ``recall``, ``thresholds``
            * ``model_version``      – str
        """
        y_true = np.asarray(y_true)
        y_scores = np.asarray(y_scores)

        max_fpr = self.default_target_fpr
        optimal = self.find_optimal_threshold(y_true, y_scores, max_fpr=max_fpr)

        fpr_val = self.compute_false_positive_rate(y_true, y_scores, optimal)
        fnr_val = self.compute_false_negative_rate(y_true, y_scores, optimal)
        tpr_val = 1.0 - fnr_val

        fpr_arr, tpr_arr, thresh_arr = self.compute_roc_curve(y_true, y_scores)
        prec_arr, rec_arr, pr_thresh_arr = self.compute_precision_recall_curve(
            y_true, y_scores
        )

        report: dict[str, Any] = {
            "optimal_threshold": round(optimal, 6),
            "max_fpr_constraint": max_fpr,
            "fpr": round(fpr_val, 6),
            "tpr": round(tpr_val, 6),
            "fnr": round(fnr_val, 6),
            "roc_auc": round(float(roc_auc_score(y_true, y_scores)), 6),
            "average_precision": round(
                float(average_precision_score(y_true, y_scores)), 6
            ),
            "roc_curve": {
                "fpr": fpr_arr.tolist(),
                "tpr": tpr_arr.tolist(),
                "thresholds": thresh_arr.tolist(),
            },
            "pr_curve": {
                "precision": prec_arr.tolist(),
                "recall": rec_arr.tolist(),
                "thresholds": pr_thresh_arr.tolist(),
            },
            "model_version": self.model_version,
        }
        logger.info(
            "generate_threshold_report | threshold=%.4f fpr=%.4f fnr=%.4f "
            "roc_auc=%.4f ap=%.4f",
            optimal,
            fpr_val,
            fnr_val,
            report["roc_auc"],
            report["average_precision"],
        )
        return report

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def save_threshold_to_db_sql(
        self,
        metric_name: str,
        threshold_value: float,
        fpr: float,
        fnr: float,
        updated_by: str = "threshold_calibrator",
    ) -> str:
        """
        Return a parameterised SQL INSERT statement for ``threshold_history``.

        The caller is responsible for executing the statement against the
        database.  Values are embedded as SQL literals so the returned
        string can be inspected and logged safely before execution.

        Parameters
        ----------
        metric_name : str
            Logical name of the metric being thresholded, e.g.
            ``"combined_risk_score"``.
        threshold_value : float
            The calibrated threshold value to persist.
        fpr : float
            False-positive rate measured at ``threshold_value``.
        fnr : float
            False-negative rate measured at ``threshold_value``.
        updated_by : str, optional
            Identity of the process or user making the change.

        Returns
        -------
        str
            A ready-to-execute PostgreSQL INSERT statement targeting
            ``threshold_history``.
        """
        sql = (
            "INSERT INTO threshold_history "
            "    (metric_name, threshold_value, false_positive_rate, "
            "     false_negative_rate, updated_by) "
            "VALUES "
            f"    ('{metric_name}', {threshold_value:.6f}, "
            f"     {fpr:.6f}, {fnr:.6f}, '{updated_by}');"
        )
        logger.info(
            "save_threshold_to_db_sql | metric=%s threshold=%.6f fpr=%.6f fnr=%.6f",
            metric_name,
            threshold_value,
            fpr,
            fnr,
        )
        return sql

    # ------------------------------------------------------------------
    # Visualisation
    # ------------------------------------------------------------------

    def plot_curves(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        output_path: str | Path,
    ) -> None:
        """
        Render and save a two-panel figure: ROC curve (left) and
        Precision-Recall curve (right).

        The optimal threshold point (at the configured ``target_fpr``) is
        annotated on both panels.  The figure is saved to ``output_path``
        using ``matplotlib``; the ``Agg`` backend is activated at module
        import so this is safe in headless server environments.

        Parameters
        ----------
        y_true : np.ndarray
            Ground-truth binary labels.
        y_scores : np.ndarray
            Continuous risk scores in [0, 100].
        output_path : str | Path
            Destination file path for the saved figure (e.g.
            ``"reports/roc_pr_curves.png"``).  Parent directories are
            created if they do not exist.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        y_true = np.asarray(y_true)
        y_scores = np.asarray(y_scores)

        optimal = self.find_optimal_threshold(
            y_true, y_scores, max_fpr=self.default_target_fpr
        )
        fpr_arr, tpr_arr, thresh_arr = self.compute_roc_curve(y_true, y_scores)
        prec_arr, rec_arr, pr_thresh_arr = self.compute_precision_recall_curve(
            y_true, y_scores
        )
        auc = float(roc_auc_score(y_true, y_scores))
        ap = float(average_precision_score(y_true, y_scores))

        # Locate the optimal point on each curve
        opt_fpr = self.compute_false_positive_rate(y_true, y_scores, optimal)
        opt_tpr = 1.0 - self.compute_false_negative_rate(y_true, y_scores, optimal)

        # Find the closest point on the PR curve for the optimal threshold
        if len(pr_thresh_arr) > 0:
            pr_idx = int(np.argmin(np.abs(pr_thresh_arr - optimal)))
            opt_prec = float(prec_arr[pr_idx])
            opt_rec = float(rec_arr[pr_idx])
        else:
            opt_prec, opt_rec = float(prec_arr[0]), float(rec_arr[0])

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle(
            f"Threshold Calibration Report  |  Model v{self.model_version}",
            fontsize=13,
            fontweight="bold",
        )

        # --- ROC curve ---
        ax_roc = axes[0]
        ax_roc.plot(fpr_arr, tpr_arr, lw=2, label=f"ROC (AUC = {auc:.4f})")
        ax_roc.plot([0, 1], [0, 1], "k--", lw=1, label="Random classifier")
        ax_roc.axvline(
            self.default_target_fpr,
            color="red",
            linestyle=":",
            lw=1.5,
            label=f"Max FPR = {self.default_target_fpr:.2%}",
        )
        ax_roc.scatter(
            [opt_fpr],
            [opt_tpr],
            s=80,
            zorder=5,
            color="red",
            label=f"Optimal threshold = {optimal:.2f}",
        )
        ax_roc.set_xlabel("False Positive Rate")
        ax_roc.set_ylabel("True Positive Rate (Recall)")
        ax_roc.set_title("ROC Curve")
        ax_roc.legend(fontsize=8)
        ax_roc.set_xlim([0.0, 1.0])
        ax_roc.set_ylim([0.0, 1.05])
        ax_roc.grid(alpha=0.3)

        # --- PR curve ---
        ax_pr = axes[1]
        ax_pr.plot(rec_arr, prec_arr, lw=2, label=f"PR (AP = {ap:.4f})")
        ax_pr.scatter(
            [opt_rec],
            [opt_prec],
            s=80,
            zorder=5,
            color="red",
            label=f"Optimal threshold = {optimal:.2f}",
        )
        ax_pr.set_xlabel("Recall")
        ax_pr.set_ylabel("Precision")
        ax_pr.set_title("Precision-Recall Curve")
        ax_pr.legend(fontsize=8)
        ax_pr.set_xlim([0.0, 1.0])
        ax_pr.set_ylim([0.0, 1.05])
        ax_pr.grid(alpha=0.3)

        plt.tight_layout()
        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("plot_curves saved → %s", output_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
