"""
alert_engine.py
===============
Real-time alerting engine for the Abuse Pattern Detection & Risk
Monitoring System.

``AlertEngine`` monitors three independent signal streams:

1. **User-level risk scores** – triggers when a single user's combined
   risk score exceeds the configured high-risk threshold.
2. **Cluster-level scores** – triggers when a coordinated abuse cluster's
   average risk score exceeds a separate ceiling.
3. **Enforcement spikes** – triggers when the volume of enforcement
   actions surges beyond a rolling Z-score threshold, indicating a
   potential incident or model mis-calibration.

All alerts pass through a deduplication cache (keyed by entity + alert
type) and a token-bucket rate limiter before being dispatched via HTTP
webhook with exponential-backoff retry.  Every send attempt—successful
or otherwise—is written to a structured incident log file.

Typical usage
-------------
::

    engine = AlertEngine("config/config.yaml")

    # Per-event scoring loop
    for user_id, score in risk_scores.items():
        engine.check_risk_threshold(user_id, score)

    # Cluster sweep
    for cid, cscore in cluster_scores.items():
        engine.check_cluster_threshold(cid, cscore)

    # Periodic spike check
    engine.check_escalation_spike(enforcement_counts_df)

    print(engine.get_alert_metrics())
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd
import requests
import yaml

logger = logging.getLogger(__name__)

# Sentinel used as the dictionary key for the global rate-limit bucket
_GLOBAL_RATE_KEY = "__global__"


class AlertEngine:
    """
    Real-time alerting engine with deduplication, rate limiting, and
    webhook dispatch.

    Parameters
    ----------
    config_path : str | Path
        Path to ``config/config.yaml``.  The following ``alerting`` keys
        are consumed:

        * ``webhook_url``          – destination for HTTP POST payloads
        * ``rate_limit``           – max alerts per 60-second window
        * ``dedup_window``         – seconds to suppress duplicate alerts
        * ``retry_attempts``       – max webhook delivery attempts (≥ 1)
        * ``retry_backoff_seconds``– base delay for exponential backoff

        And from ``anomaly_detection``:

        * ``risk_score_high``      – threshold above which a user alert fires
        * ``zscore_threshold``     – Z-score multiplier for spike detection

    Attributes
    ----------
    _dedup_cache : dict[str, float]
        Maps alert-key strings to the UNIX timestamp of the last dispatch.
    _rate_bucket : dict[str, list[float]]
        Sliding window of dispatch timestamps for rate-limit accounting.
    _metrics : dict[str, int]
        Running counters: ``sent``, ``deduplicated``, ``failed``.
    """

    def __init__(self, config_path: str | Path = "config/config.yaml") -> None:
        self.cfg = self._load_config(config_path)
        alert_cfg = self.cfg["alerting"]
        ad_cfg = self.cfg["anomaly_detection"]

        self.webhook_url: str = alert_cfg["webhook_url"]
        self.rate_limit: int = int(alert_cfg["rate_limit"])
        self.dedup_window: int = int(alert_cfg["dedup_window"])
        self.retry_attempts: int = max(1, int(alert_cfg["retry_attempts"]))
        self.retry_backoff: float = float(alert_cfg["retry_backoff_seconds"])

        self.risk_threshold: float = float(ad_cfg["risk_score_high"])
        self.cluster_threshold: float = float(ad_cfg["risk_score_high"])
        self.zscore_threshold: float = float(ad_cfg["zscore_threshold"])

        # Dedup cache: alert_key → last_sent_epoch
        self._dedup_cache: dict[str, float] = {}

        # Rate-limit sliding window: key → list of dispatch timestamps
        self._rate_bucket: dict[str, list[float]] = defaultdict(list)

        # Operational counters
        self._metrics: dict[str, int] = {
            "sent": 0,
            "deduplicated": 0,
            "failed": 0,
        }

        # Incident log – rotating file handler separate from the root logger
        self._incident_logger = self._build_incident_logger()

        logger.info(
            "AlertEngine initialised | webhook=%s rate_limit=%d/min dedup=%ds",
            self.webhook_url,
            self.rate_limit,
            self.dedup_window,
        )

    # ------------------------------------------------------------------
    # Public signal checks
    # ------------------------------------------------------------------

    def check_risk_threshold(self, user_id: str, risk_score: float) -> bool:
        """
        Trigger a ``user_high_risk`` alert when ``risk_score`` exceeds the
        configured high-risk threshold.

        Parameters
        ----------
        user_id : str
            UUID or opaque identifier of the user.
        risk_score : float
            Combined risk score in [0, 100].

        Returns
        -------
        bool
            ``True`` if an alert was dispatched (not deduped/rate-limited).
        """
        if risk_score < self.risk_threshold:
            return False

        details: dict[str, Any] = {
            "user_id": user_id,
            "risk_score": risk_score,
            "threshold": self.risk_threshold,
        }
        logger.debug(
            "check_risk_threshold | user=%s score=%.2f >= threshold=%.2f",
            user_id,
            risk_score,
            self.risk_threshold,
        )
        return self.send_alert("user_high_risk", details)

    def check_cluster_threshold(
        self, cluster_id: str, cluster_score: float
    ) -> bool:
        """
        Trigger a ``cluster_high_risk`` alert when the cluster's average
        risk score exceeds the cluster threshold.

        Parameters
        ----------
        cluster_id : str
            UUID of the abuse cluster.
        cluster_score : float
            Average risk score across cluster members in [0, 1] or [0, 100].

        Returns
        -------
        bool
            ``True`` if an alert was dispatched.
        """
        # Normalise: cluster scores from the DB are in [0,1]; scale to [0,100]
        normalised_score = cluster_score * 100.0 if cluster_score <= 1.0 else cluster_score
        if normalised_score < self.cluster_threshold:
            return False

        details: dict[str, Any] = {
            "cluster_id": cluster_id,
            "cluster_score": cluster_score,
            "normalised_score": normalised_score,
            "threshold": self.cluster_threshold,
        }
        logger.debug(
            "check_cluster_threshold | cluster=%s score=%.2f >= threshold=%.2f",
            cluster_id,
            normalised_score,
            self.cluster_threshold,
        )
        return self.send_alert("cluster_high_risk", details)

    def check_escalation_spike(
        self, enforcement_counts_df: pd.DataFrame
    ) -> bool:
        """
        Detect a sudden spike in enforcement action volume.

        A spike is declared when the latest period's count exceeds the
        rolling mean by more than ``zscore_threshold`` standard deviations.
        The DataFrame must contain a ``enforcement_count`` column with one
        row per time period (most recent last).

        Parameters
        ----------
        enforcement_counts_df : pd.DataFrame
            Time-series of enforcement counts.  Required column:
            ``enforcement_count`` (int).  Optional column: ``period``
            (label used in the alert payload).

        Returns
        -------
        bool
            ``True`` if a spike alert was dispatched.

        Raises
        ------
        ValueError
            If the DataFrame does not contain an ``enforcement_count`` column
            or has fewer than 2 rows.
        """
        if "enforcement_count" not in enforcement_counts_df.columns:
            raise ValueError(
                "enforcement_counts_df must contain an 'enforcement_count' column"
            )
        if len(enforcement_counts_df) < 2:
            raise ValueError(
                "enforcement_counts_df must have at least 2 rows to detect a spike"
            )

        counts = enforcement_counts_df["enforcement_count"].astype(float).values
        mean = counts[:-1].mean()
        std = counts[:-1].std(ddof=1) if len(counts) > 2 else 0.0
        latest = counts[-1]

        if std < 1e-9:
            # No variance — can't compute a meaningful Z-score
            logger.debug("check_escalation_spike | zero variance, skipping")
            return False

        z = (latest - mean) / std
        logger.debug(
            "check_escalation_spike | latest=%.0f mean=%.2f std=%.2f z=%.2f",
            latest,
            mean,
            std,
            z,
        )

        if z <= self.zscore_threshold:
            return False

        period_label = (
            str(enforcement_counts_df.iloc[-1]["period"])
            if "period" in enforcement_counts_df.columns
            else "latest"
        )
        details: dict[str, Any] = {
            "period": period_label,
            "enforcement_count": int(latest),
            "rolling_mean": round(mean, 2),
            "rolling_std": round(std, 2),
            "z_score": round(z, 4),
            "threshold_z": self.zscore_threshold,
        }
        return self.send_alert("escalation_spike", details)

    # ------------------------------------------------------------------
    # Alert dispatch
    # ------------------------------------------------------------------

    def send_alert(self, alert_type: str, details: dict[str, Any]) -> bool:
        """
        Validate, deduplicate, rate-limit, and dispatch an alert.

        Parameters
        ----------
        alert_type : str
            Short identifier for the alert class (e.g. ``"user_high_risk"``).
        details : dict[str, Any]
            Arbitrary key-value payload attached to the alert.

        Returns
        -------
        bool
            ``True`` if the alert was successfully delivered to the webhook.
        """
        # Build a stable dedup key from alert type + primary entity identifier
        entity_key = str(
            details.get("user_id")
            or details.get("cluster_id")
            or details.get("period")
            or "global"
        )
        alert_key = f"{alert_type}:{entity_key}"

        if self._deduplicate(alert_key):
            self._metrics["deduplicated"] += 1
            logger.info("Alert suppressed (dedup) | key=%s", alert_key)
            return False

        if not self._rate_limit_check():
            self._metrics["failed"] += 1
            logger.warning("Alert dropped (rate limit) | type=%s", alert_type)
            return False

        payload: dict[str, Any] = {
            "alert_type": alert_type,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "details": details,
        }

        success = self._send_webhook(payload)
        if success:
            self._dedup_cache[alert_key] = time.time()
            self._metrics["sent"] += 1
            self.log_incident(alert_type, details)
        else:
            self._metrics["failed"] += 1

        return success

    # ------------------------------------------------------------------
    # Dedup & rate limiting
    # ------------------------------------------------------------------

    def _deduplicate(self, alert_key: str) -> bool:
        """
        Return ``True`` if this alert key was already dispatched within
        the deduplication window and should therefore be suppressed.

        Parameters
        ----------
        alert_key : str
            Composite key identifying the entity + alert type.

        Returns
        -------
        bool
            ``True`` → suppress (duplicate within window).
            ``False`` → proceed with dispatch.
        """
        last_sent = self._dedup_cache.get(alert_key)
        if last_sent is None:
            return False
        age = time.time() - last_sent
        return age < self.dedup_window

    def _rate_limit_check(self) -> bool:
        """
        Enforce a token-bucket rate limit: at most ``self.rate_limit``
        alerts may be dispatched in any rolling 60-second window.

        Returns
        -------
        bool
            ``True`` → within limit, proceed.
            ``False`` → limit exceeded, suppress.
        """
        now = time.time()
        window_start = now - 60.0
        bucket = self._rate_bucket[_GLOBAL_RATE_KEY]

        # Purge timestamps outside the rolling window
        self._rate_bucket[_GLOBAL_RATE_KEY] = [
            t for t in bucket if t > window_start
        ]
        if len(self._rate_bucket[_GLOBAL_RATE_KEY]) >= self.rate_limit:
            logger.warning(
                "_rate_limit_check | %d/%d alerts in last 60s — throttling",
                len(self._rate_bucket[_GLOBAL_RATE_KEY]),
                self.rate_limit,
            )
            return False

        self._rate_bucket[_GLOBAL_RATE_KEY].append(now)
        return True

    # ------------------------------------------------------------------
    # Webhook delivery
    # ------------------------------------------------------------------

    def _send_webhook(self, payload: dict[str, Any]) -> bool:
        """
        HTTP POST ``payload`` to the configured webhook URL with
        exponential-backoff retry.

        Attempts up to ``self.retry_attempts`` times.  The delay between
        attempts follows ``retry_backoff * 2^(attempt - 1)`` seconds.

        Parameters
        ----------
        payload : dict[str, Any]
            JSON-serialisable alert payload.

        Returns
        -------
        bool
            ``True`` if any attempt returned HTTP 2xx.
        """
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        for attempt in range(1, self.retry_attempts + 1):
            try:
                response = requests.post(
                    self.webhook_url,
                    data=body,
                    headers=headers,
                    timeout=10,
                )
                if response.ok:
                    logger.info(
                        "_send_webhook | attempt=%d status=%d OK",
                        attempt,
                        response.status_code,
                    )
                    return True

                logger.warning(
                    "_send_webhook | attempt=%d status=%d body=%.200s",
                    attempt,
                    response.status_code,
                    response.text,
                )

            except requests.RequestException as exc:
                logger.error(
                    "_send_webhook | attempt=%d error=%s", attempt, exc
                )

            if attempt < self.retry_attempts:
                backoff = self.retry_backoff * (2 ** (attempt - 1))
                logger.debug(
                    "_send_webhook | backing off %.1fs before attempt %d",
                    backoff,
                    attempt + 1,
                )
                time.sleep(backoff)

        logger.error(
            "_send_webhook | all %d attempts failed | alert_type=%s",
            self.retry_attempts,
            payload.get("alert_type"),
        )
        return False

    # ------------------------------------------------------------------
    # Incident logging
    # ------------------------------------------------------------------

    def log_incident(
        self, alert_type: str, details: dict[str, Any]
    ) -> None:
        """
        Write a structured JSON incident record to the rotating incident
        log file.

        Parameters
        ----------
        alert_type : str
            Alert class identifier.
        details : dict[str, Any]
            Alert payload details.
        """
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "alert_type": alert_type,
            "details": details,
        }
        self._incident_logger.info(json.dumps(record))

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_alert_metrics(self) -> dict[str, int]:
        """
        Return a snapshot of operational counters.

        Returns
        -------
        dict[str, int]
            Keys: ``sent``, ``deduplicated``, ``failed``.
        """
        return dict(self._metrics)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_incident_logger() -> logging.Logger:
        """
        Create a dedicated logger that writes JSON incident records to a
        rotating file (``logs/incidents.log``), separate from the root
        application logger.
        """
        inc_logger = logging.getLogger("alert_engine.incidents")
        if not inc_logger.handlers:
            log_dir = Path("logs")
            log_dir.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                log_dir / "incidents.log",
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            inc_logger.addHandler(handler)
            inc_logger.setLevel(logging.INFO)
            inc_logger.propagate = False
        return inc_logger

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
