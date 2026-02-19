"""
dashboard_spec.py
=================
Dashboard specification generator for the Abuse Pattern Detection &
Risk Monitoring System.

``DashboardSpecGenerator`` produces machine-readable specifications for
two dashboard surfaces:

* **Executive overview** – KPI tiles and trend charts for leadership.
  Refresh: every 15 minutes.
* **Analyst view** – granular metrics, per-user drilldown, and model
  diagnostics for the Trust & Safety team.  Refresh: every 5 minutes.

Each surface is described by:

* Metric definitions (name, description, unit, calculated field, refresh)
* SQL extract queries aligned to the production schema in ``schema.sql``
* Visualisation mappings (metric → chart type)
* Alert rule definitions for automated monitoring

The full specification can be exported as a JSON file via
``export_spec(output_path)``.

Typical usage
-------------
::

    gen = DashboardSpecGenerator()
    exec_metrics = gen.executive_overview_metrics()
    sql_queries  = gen.get_sql_extracts()
    gen.export_spec("reports/dashboard_spec.json")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DashboardSpecGenerator:
    """
    Generate structured specifications for the executive and analyst
    dashboards, including SQL extracts, visualisation mappings, and
    alert rules.

    No external dependencies beyond the standard library are required.
    The specification is purely declarative—execution against the
    database is handled by the calling application.
    """

    # ------------------------------------------------------------------
    # Dashboard metric definitions
    # ------------------------------------------------------------------

    def executive_overview_metrics(self) -> dict[str, Any]:
        """
        Return metric definitions for the executive-level dashboard.

        Each key is a metric identifier; each value is a dict describing
        the metric's human-readable attributes, unit, calculation, and
        refresh cadence.

        Returns
        -------
        dict[str, Any]
            Mapping of metric_id → metric definition dict.
        """
        return {
            "total_flagged_users": {
                "label": "Total Flagged Users",
                "description": (
                    "Count of distinct users whose latest combined_risk_score "
                    "exceeds the high-risk threshold or whose is_flagged profile "
                    "bit is set."
                ),
                "unit": "users",
                "calculated_field": (
                    "COUNT(DISTINCT user_id) FILTER (WHERE is_flagged = TRUE)"
                ),
                "refresh_seconds": 900,
                "category": "risk_overview",
            },
            "high_risk_rate_pct": {
                "label": "High-Risk Rate (%)",
                "description": (
                    "Percentage of all active users flagged as high-risk in the "
                    "current reporting window.  Trend above 2 % triggers an "
                    "executive alert."
                ),
                "unit": "percent",
                "calculated_field": (
                    "ROUND(100.0 * SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END) "
                    "/ NULLIF(COUNT(*), 0), 2)"
                ),
                "refresh_seconds": 900,
                "category": "risk_overview",
            },
            "enforcement_actions_24h": {
                "label": "Enforcement Actions (24 h)",
                "description": (
                    "Total enforcement actions triggered in the last 24 hours "
                    "across all action types (suspend, rate_limit, captcha, ban)."
                ),
                "unit": "actions",
                "calculated_field": (
                    "COUNT(*) FILTER ("
                    "WHERE triggered_at >= NOW() - INTERVAL '24 hours')"
                ),
                "refresh_seconds": 900,
                "category": "enforcement",
            },
            "false_positive_rate_latest": {
                "label": "False-Positive Rate (latest threshold)",
                "description": (
                    "False-positive rate recorded for the most recently "
                    "calibrated combined_risk_score threshold, sourced from "
                    "threshold_history."
                ),
                "unit": "rate [0–1]",
                "calculated_field": (
                    "false_positive_rate  -- from threshold_history latest row"
                ),
                "refresh_seconds": 3600,
                "category": "model_health",
            },
            "active_abuse_clusters": {
                "label": "Active Abuse Clusters",
                "description": (
                    "Count of abuse clusters detected in the last 7 days with "
                    "avg_risk_score > 0.5."
                ),
                "unit": "clusters",
                "calculated_field": (
                    "COUNT(*) FILTER ("
                    "WHERE detected_at >= NOW() - INTERVAL '7 days' "
                    "  AND avg_risk_score > 0.5)"
                ),
                "refresh_seconds": 900,
                "category": "cluster_risk",
            },
            "avg_risk_score_all_users": {
                "label": "Average Risk Score (all users)",
                "description": (
                    "Mean combined_risk_score across the latest score per user. "
                    "A rising trend signals systemic model drift or an emerging "
                    "abuse campaign."
                ),
                "unit": "score [0–1]",
                "calculated_field": "AVG(combined_risk_score)",
                "refresh_seconds": 900,
                "category": "risk_overview",
            },
            "new_account_abuse_rate_pct": {
                "label": "New-Account Abuse Rate (%)",
                "description": (
                    "Percentage of accounts created within the last 7 days that "
                    "have been flagged or enforced against.  Elevated values "
                    "indicate a new-account abuse campaign."
                ),
                "unit": "percent",
                "calculated_field": (
                    "ROUND(100.0 * SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END) "
                    "/ NULLIF(COUNT(*), 0), 2) "
                    "-- filtered to account_age_days < 7"
                ),
                "refresh_seconds": 900,
                "category": "cohort_risk",
            },
            "enforcement_false_positive_outcomes_pct": {
                "label": "Enforcement False-Positive Outcome Rate (%)",
                "description": (
                    "Percentage of closed enforcement actions whose outcome was "
                    "'false_positive'.  Indicates over-triggering."
                ),
                "unit": "percent",
                "calculated_field": (
                    "ROUND(100.0 * SUM(CASE WHEN outcome = 'false_positive' "
                    "THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) "
                    "-- filtered to resolved_at IS NOT NULL"
                ),
                "refresh_seconds": 3600,
                "category": "enforcement",
            },
        }

    def analyst_view_metrics(self) -> dict[str, Any]:
        """
        Return metric definitions for the analyst-level dashboard.

        Analyst metrics are more granular and refresh more frequently.

        Returns
        -------
        dict[str, Any]
            Mapping of metric_id → metric definition dict.
        """
        return {
            "top_risk_users_live": {
                "label": "Top 50 Highest-Risk Users (live)",
                "description": (
                    "Ranked list of users by latest combined_risk_score, "
                    "including account age, country, and open enforcement actions."
                ),
                "unit": "user list",
                "calculated_field": (
                    "RANK() OVER (ORDER BY combined_risk_score DESC) AS risk_rank"
                ),
                "refresh_seconds": 300,
                "category": "user_drilldown",
            },
            "anomaly_score_distribution": {
                "label": "Risk Score Distribution (histogram)",
                "description": (
                    "Frequency distribution of latest combined_risk_score "
                    "across all users in 0.05-wide buckets."
                ),
                "unit": "user count per bucket",
                "calculated_field": (
                    "WIDTH_BUCKET(combined_risk_score, 0, 1, 20) AS score_bucket, "
                    "COUNT(*) AS user_count"
                ),
                "refresh_seconds": 300,
                "category": "model_diagnostics",
            },
            "enforcement_action_breakdown": {
                "label": "Enforcement Actions by Type (rolling 24 h)",
                "description": (
                    "Count of each enforcement action type in the last 24 hours: "
                    "suspend, rate_limit, captcha, ban, warning."
                ),
                "unit": "action count",
                "calculated_field": (
                    "action_type, COUNT(*) AS action_count "
                    "-- GROUP BY action_type"
                ),
                "refresh_seconds": 300,
                "category": "enforcement",
            },
            "burst_activity_heatmap": {
                "label": "High-Burst Users Heatmap (last 1 h)",
                "description": (
                    "Matrix of (user_id × 5-minute window) showing burst_score "
                    "from time_window_activity where burst_score > 0.75."
                ),
                "unit": "burst_score [0–1]",
                "calculated_field": (
                    "burst_score  -- from time_window_activity WHERE window_type = '5min'"
                ),
                "refresh_seconds": 300,
                "category": "burst_detection",
            },
            "cluster_risk_leaderboard": {
                "label": "Abuse Cluster Risk Leaderboard",
                "description": (
                    "Ranked list of abuse clusters by avg_risk_score detected "
                    "in the last 7 days, with cluster_size and shared signal summary."
                ),
                "unit": "cluster list",
                "calculated_field": (
                    "RANK() OVER (ORDER BY avg_risk_score DESC) AS cluster_rank"
                ),
                "refresh_seconds": 300,
                "category": "cluster_risk",
            },
            "ip_multi_account_signals": {
                "label": "Multi-Account IP Signals (last 24 h)",
                "description": (
                    "IP addresses associated with ≥ 3 distinct user accounts "
                    "in any 10-minute window, with average risk score of those "
                    "accounts."
                ),
                "unit": "IP address list",
                "calculated_field": (
                    "COUNT(DISTINCT user_id) AS distinct_accounts, "
                    "AVG(combined_risk_score) AS avg_risk"
                ),
                "refresh_seconds": 300,
                "category": "network_signals",
            },
            "device_reuse_signals": {
                "label": "Device Fingerprint Reuse Signals (last 24 h)",
                "description": (
                    "Device fingerprints shared across ≥ 2 distinct user "
                    "accounts with account switches within 30 minutes."
                ),
                "unit": "device list",
                "calculated_field": (
                    "COUNT(DISTINCT user_id) AS accounts_seen, "
                    "COUNT(*) AS total_switches"
                ),
                "refresh_seconds": 300,
                "category": "network_signals",
            },
            "threshold_drift_monitor": {
                "label": "Threshold Drift Monitor",
                "description": (
                    "Time-series of FPR and FNR from threshold_history over "
                    "the last 30 days, with the active threshold overlaid."
                ),
                "unit": "rate [0–1]",
                "calculated_field": (
                    "false_positive_rate, false_negative_rate, threshold_value"
                ),
                "refresh_seconds": 3600,
                "category": "model_health",
            },
            "session_success_rate_anomalies": {
                "label": "Abnormal Session Success Rates",
                "description": (
                    "Sessions with success_zscore < -2 in the last 24 hours, "
                    "indicating potential brute-force or credential-stuffing."
                ),
                "unit": "session list",
                "calculated_field": (
                    "(session_success_rate - baseline_mean) "
                    "/ NULLIF(baseline_stddev, 0) AS success_zscore"
                ),
                "refresh_seconds": 300,
                "category": "session_analysis",
            },
            "cohort_abuse_comparison": {
                "label": "Cohort Abuse Rate Comparison",
                "description": (
                    "Flagged-user rate and average risk score split by account-"
                    "age cohort: 0–6 days, 7–29 days, 30–89 days, 90+ days."
                ),
                "unit": "percent / score",
                "calculated_field": (
                    "CASE "
                    "  WHEN account_age_days < 7   THEN '0-6 days' "
                    "  WHEN account_age_days < 30  THEN '7-29 days' "
                    "  WHEN account_age_days < 90  THEN '30-89 days' "
                    "  ELSE '90+ days' "
                    "END AS age_cohort"
                ),
                "refresh_seconds": 900,
                "category": "cohort_risk",
            },
        }

    # ------------------------------------------------------------------
    # SQL extracts
    # ------------------------------------------------------------------

    def get_sql_extracts(self) -> dict[str, str]:
        """
        Return SQL query strings for each dashboard metric, keyed by
        metric identifier.

        All queries target the production schema defined in
        ``sql/schema.sql`` and follow the conventions established in
        ``sql/queries.sql`` (named bind parameters, partition pruning,
        window functions).

        Returns
        -------
        dict[str, str]
            Mapping of metric_id → SQL query string.
        """
        return {
            # ── Executive metrics ─────────────────────────────────────
            "total_flagged_users": """
SELECT
    COUNT(DISTINCT up.user_id)                                AS total_flagged_users,
    NOW()                                                     AS computed_at
FROM user_profiles up
WHERE up.is_flagged = TRUE;
""".strip(),

            "high_risk_rate_pct": """
WITH latest_scores AS (
    SELECT DISTINCT ON (user_id)
        user_id,
        combined_risk_score,
        is_flagged
    FROM anomaly_scores
    ORDER BY user_id, computed_at DESC
)
SELECT
    COUNT(*)                                                  AS total_scored_users,
    SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END)               AS flagged_users,
    ROUND(
        100.0 * SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
        2
    )                                                         AS high_risk_rate_pct,
    NOW()                                                     AS computed_at
FROM latest_scores;
""".strip(),

            "enforcement_actions_24h": """
SELECT
    action_type,
    COUNT(*)                                                  AS action_count,
    MIN(triggered_at)                                         AS earliest,
    MAX(triggered_at)                                         AS latest
FROM enforcement_actions
WHERE triggered_at >= NOW() - INTERVAL '24 hours'
GROUP BY action_type
ORDER BY action_count DESC;
""".strip(),

            "false_positive_rate_latest": """
SELECT
    metric_name,
    threshold_value,
    false_positive_rate,
    false_negative_rate,
    updated_at,
    updated_by
FROM threshold_history
WHERE metric_name = 'combined_risk_score'
ORDER BY updated_at DESC
LIMIT 1;
""".strip(),

            "active_abuse_clusters": """
SELECT
    cluster_id,
    detected_at,
    cluster_size,
    ROUND(avg_risk_score::NUMERIC, 4)                         AS avg_risk_score,
    cluster_label,
    shared_ips,
    shared_devices
FROM abuse_clusters
WHERE detected_at >= NOW() - INTERVAL '7 days'
  AND avg_risk_score > 0.5
ORDER BY avg_risk_score DESC, cluster_size DESC;
""".strip(),

            "avg_risk_score_all_users": """
WITH latest_scores AS (
    SELECT DISTINCT ON (user_id)
        user_id,
        combined_risk_score
    FROM anomaly_scores
    ORDER BY user_id, computed_at DESC
)
SELECT
    ROUND(AVG(combined_risk_score)::NUMERIC, 6)               AS avg_risk_score,
    ROUND(STDDEV_POP(combined_risk_score)::NUMERIC, 6)        AS stddev_risk_score,
    MIN(combined_risk_score)                                  AS min_risk_score,
    MAX(combined_risk_score)                                  AS max_risk_score,
    COUNT(*)                                                  AS scored_users,
    NOW()                                                     AS computed_at
FROM latest_scores;
""".strip(),

            "new_account_abuse_rate_pct": """
SELECT
    CASE
        WHEN account_age_days < 7  THEN '0-6 days'
        WHEN account_age_days < 30 THEN '7-29 days'
        ELSE '30+ days'
    END                                                       AS age_cohort,
    COUNT(*)                                                  AS total_users,
    SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END)               AS flagged_users,
    ROUND(
        100.0 * SUM(CASE WHEN is_flagged THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
        2
    )                                                         AS abuse_rate_pct
FROM user_profiles
GROUP BY 1
ORDER BY MIN(account_age_days);
""".strip(),

            "enforcement_false_positive_outcomes_pct": """
SELECT
    COUNT(*)                                                  AS total_resolved,
    SUM(CASE WHEN outcome = 'false_positive' THEN 1 ELSE 0 END)
                                                              AS false_positive_count,
    ROUND(
        100.0 * SUM(CASE WHEN outcome = 'false_positive' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
        2
    )                                                         AS fp_outcome_rate_pct
FROM enforcement_actions
WHERE resolved_at IS NOT NULL
  AND triggered_at >= NOW() - INTERVAL '30 days';
""".strip(),

            # ── Analyst metrics ───────────────────────────────────────
            "top_risk_users_live": """
WITH latest_scores AS (
    SELECT DISTINCT ON (as2.user_id)
        as2.user_id,
        as2.combined_risk_score,
        as2.zscore_value,
        as2.isolation_score,
        as2.is_flagged,
        as2.computed_at,
        as2.model_version
    FROM anomaly_scores as2
    ORDER BY as2.user_id, as2.computed_at DESC
)
SELECT
    RANK() OVER (ORDER BY ls.combined_risk_score DESC)        AS risk_rank,
    ls.user_id,
    up.country,
    up.account_age_days,
    up.is_flagged                                             AS profile_flagged,
    ROUND(ls.combined_risk_score::NUMERIC, 4)                 AS combined_risk_score,
    ROUND(ls.zscore_value::NUMERIC, 4)                        AS zscore_value,
    ROUND(ls.isolation_score::NUMERIC, 4)                     AS isolation_score,
    ls.computed_at,
    ls.model_version,
    COUNT(ea.action_id) FILTER (WHERE ea.resolved_at IS NULL) AS open_enforcements
FROM latest_scores ls
JOIN user_profiles up USING (user_id)
LEFT JOIN enforcement_actions ea USING (user_id)
GROUP BY
    ls.user_id, up.country, up.account_age_days, up.is_flagged,
    ls.combined_risk_score, ls.zscore_value, ls.isolation_score,
    ls.computed_at, ls.model_version
ORDER BY ls.combined_risk_score DESC
LIMIT 50;
""".strip(),

            "anomaly_score_distribution": """
WITH latest_scores AS (
    SELECT DISTINCT ON (user_id)
        user_id,
        combined_risk_score
    FROM anomaly_scores
    ORDER BY user_id, computed_at DESC
),
bucketed AS (
    SELECT
        WIDTH_BUCKET(combined_risk_score, 0, 1, 20) AS bucket_num,
        COUNT(*)                                    AS user_count
    FROM latest_scores
    GROUP BY 1
)
SELECT
    bucket_num,
    ROUND(((bucket_num - 1) * 0.05)::NUMERIC, 2)  AS bucket_low,
    ROUND((bucket_num * 0.05)::NUMERIC, 2)         AS bucket_high,
    user_count
FROM bucketed
ORDER BY bucket_num;
""".strip(),

            "enforcement_action_breakdown": """
SELECT
    action_type,
    COUNT(*)                                                  AS total_actions,
    COUNT(*) FILTER (WHERE resolved_at IS NOT NULL)           AS resolved_actions,
    COUNT(*) FILTER (WHERE resolved_at IS NULL)               AS open_actions,
    COUNT(*) FILTER (WHERE outcome = 'confirmed_abuse')       AS confirmed_abuse,
    COUNT(*) FILTER (WHERE outcome = 'false_positive')        AS false_positives,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE outcome = 'false_positive')
            / NULLIF(COUNT(*) FILTER (WHERE resolved_at IS NOT NULL), 0),
        2
    )                                                         AS fp_rate_pct
FROM enforcement_actions
WHERE triggered_at >= NOW() - INTERVAL '24 hours'
GROUP BY action_type
ORDER BY total_actions DESC;
""".strip(),

            "burst_activity_heatmap": """
SELECT
    twa.user_id,
    up.country,
    twa.window_start,
    twa.window_end,
    twa.window_type,
    twa.action_count,
    ROUND(twa.burst_score::NUMERIC, 4)                        AS burst_score
FROM time_window_activity twa
JOIN user_profiles up USING (user_id)
WHERE twa.window_start >= NOW() - INTERVAL '1 hour'
  AND twa.window_type  = '5min'
  AND twa.burst_score  > 0.75
ORDER BY twa.burst_score DESC, twa.window_start DESC;
""".strip(),

            "cluster_risk_leaderboard": """
SELECT
    RANK() OVER (ORDER BY avg_risk_score DESC)                AS cluster_rank,
    cluster_id,
    detected_at,
    cluster_size,
    ROUND(avg_risk_score::NUMERIC, 4)                         AS avg_risk_score,
    cluster_label,
    shared_ips,
    shared_devices
FROM abuse_clusters
WHERE detected_at >= NOW() - INTERVAL '7 days'
ORDER BY avg_risk_score DESC, cluster_size DESC
LIMIT 100;
""".strip(),

            "ip_multi_account_signals": """
WITH ip_buckets AS (
    SELECT
        ip_address,
        DATE_TRUNC('hour', "timestamp")
            + (EXTRACT(MINUTE FROM "timestamp")::INT / 10)
              * INTERVAL '10 minutes'                         AS bucket_start,
        user_id,
        COUNT(*)                                              AS event_count
    FROM raw_events
    WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
    GROUP BY ip_address, bucket_start, user_id
),
ip_agg AS (
    SELECT
        ip_address,
        bucket_start,
        COUNT(DISTINCT user_id)                               AS distinct_accounts,
        SUM(event_count)                                      AS total_events,
        ARRAY_AGG(DISTINCT user_id ORDER BY user_id)          AS account_list
    FROM ip_buckets
    GROUP BY ip_address, bucket_start
    HAVING COUNT(DISTINCT user_id) >= 3
),
enriched AS (
    SELECT
        ia.ip_address,
        ia.bucket_start,
        ia.bucket_start + INTERVAL '10 minutes'              AS bucket_end,
        ia.distinct_accounts,
        ia.total_events,
        ia.account_list,
        AVG(ls.combined_risk_score)                          AS avg_risk_score
    FROM ip_agg ia
    LEFT JOIN LATERAL (
        SELECT combined_risk_score
        FROM anomaly_scores
        WHERE user_id = ANY(ia.account_list)
        ORDER BY computed_at DESC
        LIMIT 1
    ) ls ON TRUE
    GROUP BY ia.ip_address, ia.bucket_start, ia.distinct_accounts,
             ia.total_events, ia.account_list
)
SELECT
    ip_address,
    bucket_start,
    bucket_end,
    distinct_accounts,
    total_events,
    ROUND(avg_risk_score::NUMERIC, 4)                         AS avg_risk_score,
    account_list
FROM enriched
ORDER BY distinct_accounts DESC, avg_risk_score DESC NULLS LAST;
""".strip(),

            "device_reuse_signals": """
WITH device_events AS (
    SELECT
        device_id,
        user_id,
        "timestamp",
        LAG(user_id)    OVER (PARTITION BY device_id ORDER BY "timestamp") AS prev_user,
        LAG("timestamp") OVER (PARTITION BY device_id ORDER BY "timestamp") AS prev_ts
    FROM raw_events
    WHERE "timestamp"  >= NOW() - INTERVAL '24 hours'
      AND device_id NOT IN ('', 'unknown', 'N/A')
),
switches AS (
    SELECT
        device_id,
        prev_user                                              AS user_from,
        user_id                                                AS user_to,
        "timestamp"                                            AS switch_ts,
        EXTRACT(EPOCH FROM ("timestamp" - prev_ts))            AS seconds_between
    FROM device_events
    WHERE prev_user IS NOT NULL
      AND prev_user <> user_id
      AND EXTRACT(EPOCH FROM ("timestamp" - prev_ts)) <= 1800
)
SELECT
    device_id,
    COUNT(DISTINCT user_from)                                  AS accounts_seen,
    COUNT(*)                                                   AS total_switches,
    MIN(switch_ts)                                             AS first_switch,
    MAX(switch_ts)                                             AS last_switch,
    ROUND(AVG(seconds_between)::NUMERIC, 1)                    AS avg_seconds_between,
    ARRAY_AGG(DISTINCT user_from)                              AS involved_accounts
FROM switches
GROUP BY device_id
HAVING COUNT(DISTINCT user_from) >= 2
ORDER BY accounts_seen DESC, total_switches DESC;
""".strip(),

            "threshold_drift_monitor": """
SELECT
    threshold_id,
    metric_name,
    threshold_value,
    false_positive_rate,
    false_negative_rate,
    updated_at,
    updated_by,
    LAG(threshold_value) OVER (
        PARTITION BY metric_name
        ORDER BY updated_at
    )                                                          AS prev_threshold,
    threshold_value - LAG(threshold_value) OVER (
        PARTITION BY metric_name
        ORDER BY updated_at
    )                                                          AS threshold_delta,
    false_positive_rate - LAG(false_positive_rate) OVER (
        PARTITION BY metric_name
        ORDER BY updated_at
    )                                                          AS fpr_delta
FROM threshold_history
WHERE updated_at >= NOW() - INTERVAL '30 days'
ORDER BY metric_name, updated_at;
""".strip(),

            "session_success_rate_anomalies": """
WITH session_stats AS (
    SELECT
        user_id,
        session_id,
        MIN("timestamp")                                       AS session_start,
        MAX("timestamp")                                       AS session_end,
        COUNT(*)                                               AS total_events,
        SUM(CASE WHEN success_flag THEN 1 ELSE 0 END)          AS success_count,
        SUM(CASE WHEN NOT success_flag THEN 1 ELSE 0 END)      AS failure_count,
        AVG(success_flag::INT)                                 AS session_success_rate
    FROM raw_events
    WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
    GROUP BY user_id, session_id
    HAVING COUNT(*) >= 10
),
user_baseline AS (
    SELECT
        user_id,
        AVG(success_rate)                                      AS mean_success_rate,
        STDDEV_POP(success_rate)                               AS stddev_success_rate
    FROM aggregated_user_metrics
    WHERE window_start >= NOW() - INTERVAL '30 days'
    GROUP BY user_id
),
scored AS (
    SELECT
        ss.user_id,
        ss.session_id,
        ss.session_start,
        ss.session_end,
        ss.total_events,
        ss.success_count,
        ss.failure_count,
        ROUND(ss.session_success_rate::NUMERIC, 4)             AS session_success_rate,
        ROUND(ub.mean_success_rate::NUMERIC, 4)                AS baseline_mean,
        ROUND(ub.stddev_success_rate::NUMERIC, 4)              AS baseline_stddev,
        ROUND(
            (ss.session_success_rate - ub.mean_success_rate)
                / NULLIF(ub.stddev_success_rate, 0),
            4
        )                                                      AS success_zscore
    FROM session_stats ss
    JOIN user_baseline ub USING (user_id)
)
SELECT
    s.user_id,
    up.country,
    up.is_flagged,
    s.session_id,
    s.session_start,
    s.session_end,
    s.total_events,
    s.success_count,
    s.failure_count,
    s.session_success_rate,
    s.baseline_mean,
    s.baseline_stddev,
    s.success_zscore
FROM scored s
JOIN user_profiles up USING (user_id)
WHERE s.success_zscore < -2
ORDER BY s.success_zscore ASC;
""".strip(),

            "cohort_abuse_comparison": """
WITH latest_scores AS (
    SELECT DISTINCT ON (user_id)
        user_id,
        combined_risk_score,
        is_flagged AS score_flagged
    FROM anomaly_scores
    ORDER BY user_id, computed_at DESC
),
user_enforcements AS (
    SELECT user_id, COUNT(*) AS enforcement_count
    FROM enforcement_actions
    WHERE triggered_at >= NOW() - INTERVAL '30 days'
    GROUP BY user_id
)
SELECT
    CASE
        WHEN up.account_age_days < 7  THEN '0-6 days'
        WHEN up.account_age_days < 30 THEN '7-29 days'
        WHEN up.account_age_days < 90 THEN '30-89 days'
        ELSE '90+ days'
    END                                                        AS age_cohort,
    COUNT(*)                                                   AS total_users,
    SUM(CASE WHEN up.is_flagged THEN 1 ELSE 0 END)             AS flagged_users,
    ROUND(
        100.0 * SUM(CASE WHEN up.is_flagged THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
        2
    )                                                          AS flagged_rate_pct,
    ROUND(AVG(ls.combined_risk_score)::NUMERIC, 4)             AS avg_risk_score,
    ROUND(AVG(COALESCE(ue.enforcement_count, 0))::NUMERIC, 4)  AS avg_enforcements
FROM user_profiles up
LEFT JOIN latest_scores ls   USING (user_id)
LEFT JOIN user_enforcements ue USING (user_id)
GROUP BY 1
ORDER BY MIN(up.account_age_days);
""".strip(),
        }

    # ------------------------------------------------------------------
    # Visualisation mapping
    # ------------------------------------------------------------------

    def get_visualization_mapping(self) -> dict[str, dict[str, Any]]:
        """
        Return a mapping from metric identifier to chart type and
        rendering options.

        Returns
        -------
        dict[str, dict[str, Any]]
            Keys match ``executive_overview_metrics`` and
            ``analyst_view_metrics`` identifiers.  Each value is a dict
            with at least:

            * ``chart_type`` – one of ``"kpi_tile"``, ``"line"``,
              ``"bar"``, ``"histogram"``, ``"heatmap"``, ``"table"``,
              ``"scatter"``
            * ``x_field`` / ``y_field`` – column names for axis mapping
              (where applicable)
            * ``color_field`` – column used for series colour coding
              (where applicable)
        """
        return {
            # Executive
            "total_flagged_users": {
                "chart_type": "kpi_tile",
                "value_field": "total_flagged_users",
                "sparkline": True,
                "color_threshold": {"warn": 1000, "critical": 5000},
            },
            "high_risk_rate_pct": {
                "chart_type": "kpi_tile",
                "value_field": "high_risk_rate_pct",
                "unit": "%",
                "color_threshold": {"warn": 1.0, "critical": 2.0},
            },
            "enforcement_actions_24h": {
                "chart_type": "bar",
                "x_field": "action_type",
                "y_field": "action_count",
                "color_field": "action_type",
                "orientation": "horizontal",
            },
            "false_positive_rate_latest": {
                "chart_type": "kpi_tile",
                "value_field": "false_positive_rate",
                "unit": "rate",
                "color_threshold": {"warn": 0.02, "critical": 0.05},
            },
            "active_abuse_clusters": {
                "chart_type": "kpi_tile",
                "value_field": "cluster_count",
                "sparkline": True,
            },
            "avg_risk_score_all_users": {
                "chart_type": "kpi_tile",
                "value_field": "avg_risk_score",
                "unit": "score",
                "color_threshold": {"warn": 0.3, "critical": 0.5},
            },
            "new_account_abuse_rate_pct": {
                "chart_type": "bar",
                "x_field": "age_cohort",
                "y_field": "abuse_rate_pct",
                "color_field": "age_cohort",
            },
            "enforcement_false_positive_outcomes_pct": {
                "chart_type": "kpi_tile",
                "value_field": "fp_outcome_rate_pct",
                "unit": "%",
                "color_threshold": {"warn": 5.0, "critical": 10.0},
            },
            # Analyst
            "top_risk_users_live": {
                "chart_type": "table",
                "columns": [
                    "risk_rank", "user_id", "country", "account_age_days",
                    "combined_risk_score", "zscore_value", "isolation_score",
                    "open_enforcements", "computed_at",
                ],
                "sort_field": "risk_rank",
                "sort_direction": "asc",
                "row_color_field": "combined_risk_score",
            },
            "anomaly_score_distribution": {
                "chart_type": "histogram",
                "x_field": "bucket_low",
                "y_field": "user_count",
                "bin_width": 0.05,
            },
            "enforcement_action_breakdown": {
                "chart_type": "bar",
                "x_field": "action_type",
                "y_field": "total_actions",
                "stacked_fields": ["confirmed_abuse", "false_positives", "open_actions"],
            },
            "burst_activity_heatmap": {
                "chart_type": "heatmap",
                "x_field": "window_start",
                "y_field": "user_id",
                "value_field": "burst_score",
                "color_scale": "YlOrRd",
            },
            "cluster_risk_leaderboard": {
                "chart_type": "table",
                "columns": [
                    "cluster_rank", "cluster_id", "detected_at", "cluster_size",
                    "avg_risk_score", "cluster_label",
                ],
                "sort_field": "cluster_rank",
                "sort_direction": "asc",
            },
            "ip_multi_account_signals": {
                "chart_type": "table",
                "columns": [
                    "ip_address", "bucket_start", "distinct_accounts",
                    "total_events", "avg_risk_score",
                ],
                "sort_field": "distinct_accounts",
                "sort_direction": "desc",
            },
            "device_reuse_signals": {
                "chart_type": "table",
                "columns": [
                    "device_id", "accounts_seen", "total_switches",
                    "avg_seconds_between", "first_switch", "last_switch",
                ],
                "sort_field": "accounts_seen",
                "sort_direction": "desc",
            },
            "threshold_drift_monitor": {
                "chart_type": "line",
                "x_field": "updated_at",
                "series": [
                    {"y_field": "threshold_value", "label": "Threshold"},
                    {"y_field": "false_positive_rate", "label": "FPR"},
                    {"y_field": "false_negative_rate", "label": "FNR"},
                ],
                "color_field": "metric_name",
            },
            "session_success_rate_anomalies": {
                "chart_type": "scatter",
                "x_field": "session_start",
                "y_field": "success_zscore",
                "color_field": "country",
                "size_field": "total_events",
            },
            "cohort_abuse_comparison": {
                "chart_type": "bar",
                "x_field": "age_cohort",
                "y_field": "flagged_rate_pct",
                "secondary_y_field": "avg_risk_score",
                "color_field": "age_cohort",
            },
        }

    # ------------------------------------------------------------------
    # Alert rules
    # ------------------------------------------------------------------

    def get_alert_rules(self) -> list[dict[str, Any]]:
        """
        Return a list of alert rule definitions for automated monitoring.

        Each rule specifies a metric, a condition, a severity level, and
        notification channels.  These rules are intended to be consumed
        by a monitoring platform (e.g. Grafana, Datadog, or the
        ``AlertEngine`` in this package).

        Returns
        -------
        list[dict[str, Any]]
            Each element is a dict with keys:
            ``rule_id``, ``metric_id``, ``condition``, ``threshold``,
            ``severity``, ``message_template``, ``channels``,
            ``evaluation_interval_seconds``.
        """
        return [
            {
                "rule_id": "exec_high_risk_rate",
                "metric_id": "high_risk_rate_pct",
                "condition": "gt",
                "threshold": 2.0,
                "severity": "critical",
                "message_template": (
                    "High-risk user rate exceeded 2%: current value is "
                    "{high_risk_rate_pct:.2f}%."
                ),
                "channels": ["webhook", "email"],
                "evaluation_interval_seconds": 900,
            },
            {
                "rule_id": "exec_enforcement_spike",
                "metric_id": "enforcement_actions_24h",
                "condition": "zscore_gt",
                "threshold": 3.0,
                "severity": "warning",
                "message_template": (
                    "Enforcement action volume spike detected: Z-score = "
                    "{z_score:.2f} (count = {enforcement_count})."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 900,
            },
            {
                "rule_id": "exec_fpr_breach",
                "metric_id": "false_positive_rate_latest",
                "condition": "gt",
                "threshold": 0.05,
                "severity": "critical",
                "message_template": (
                    "False-positive rate for {metric_name} exceeds 5%: "
                    "current FPR = {false_positive_rate:.4f}. "
                    "Threshold recalibration required."
                ),
                "channels": ["webhook", "email"],
                "evaluation_interval_seconds": 3600,
            },
            {
                "rule_id": "analyst_cluster_surge",
                "metric_id": "active_abuse_clusters",
                "condition": "gt",
                "threshold": 10,
                "severity": "warning",
                "message_template": (
                    "Active high-risk abuse clusters exceeded 10: "
                    "{active_cluster_count} clusters detected in the last 7 days."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 300,
            },
            {
                "rule_id": "analyst_new_account_abuse",
                "metric_id": "new_account_abuse_rate_pct",
                "condition": "gt",
                "threshold": 5.0,
                "severity": "warning",
                "message_template": (
                    "New-account (0–6 days) abuse rate exceeded 5%: "
                    "current rate = {abuse_rate_pct:.2f}%."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 900,
            },
            {
                "rule_id": "analyst_burst_heatmap_saturation",
                "metric_id": "burst_activity_heatmap",
                "condition": "row_count_gt",
                "threshold": 500,
                "severity": "warning",
                "message_template": (
                    "More than 500 high-burst sessions detected in the last hour "
                    "({burst_row_count} rows with burst_score > 0.75)."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 300,
            },
            {
                "rule_id": "analyst_device_reuse_surge",
                "metric_id": "device_reuse_signals",
                "condition": "row_count_gt",
                "threshold": 50,
                "severity": "warning",
                "message_template": (
                    "Device fingerprint reuse signals surged: {device_count} "
                    "devices seen across multiple accounts in the last 24 hours."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 300,
            },
            {
                "rule_id": "analyst_ip_multi_account_surge",
                "metric_id": "ip_multi_account_signals",
                "condition": "row_count_gt",
                "threshold": 20,
                "severity": "warning",
                "message_template": (
                    "Multi-account IP signals surged: {ip_count} IPs linked to "
                    "3+ accounts in a 10-minute window in the last 24 hours."
                ),
                "channels": ["webhook"],
                "evaluation_interval_seconds": 300,
            },
        ]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_spec(self, output_path: str | Path) -> None:
        """
        Serialise the full dashboard specification to a JSON file.

        The exported document contains:

        * ``executive_metrics``   – from ``executive_overview_metrics()``
        * ``analyst_metrics``     – from ``analyst_view_metrics()``
        * ``sql_extracts``        – from ``get_sql_extracts()``
        * ``visualization_mapping`` – from ``get_visualization_mapping()``
        * ``alert_rules``         – from ``get_alert_rules()``
        * ``schema_version``      – semantic version of this spec format
        * ``generated_at``        – ISO-8601 UTC timestamp

        Parameters
        ----------
        output_path : str | Path
            Destination file path.  Parent directories are created if
            they do not exist.
        """
        import datetime

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        spec: dict[str, Any] = {
            "schema_version": "1.0.0",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "executive_metrics": self.executive_overview_metrics(),
            "analyst_metrics": self.analyst_view_metrics(),
            "sql_extracts": self.get_sql_extracts(),
            "visualization_mapping": self.get_visualization_mapping(),
            "alert_rules": self.get_alert_rules(),
        }

        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(spec, fh, indent=2, ensure_ascii=False)

        logger.info(
            "export_spec | written %d bytes → %s",
            output_path.stat().st_size,
            output_path,
        )
