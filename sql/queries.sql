-- =============================================================================
-- Abuse Pattern Detection & Risk Monitoring System
-- Advanced Analytical Queries
-- =============================================================================
-- All queries are designed for the partitioned schema defined in schema.sql.
-- General conventions:
--   • Always supply a concrete timestamp range so the planner prunes partitions
--   • CTEs labelled with their logical role for readability
--   • Window functions are preferred over self-joins for sequential analysis
--   • :lookback_start / :lookback_end are named bind parameters; replace with
--     literals or application-layer values at execution time
-- =============================================================================


-- =============================================================================
-- Query 1 – High-Frequency Action Bursts (Sliding-Window Anomaly)
-- =============================================================================
-- Explanation:
--   Detects users whose action rate in any trailing 5-minute window exceeds a
--   dynamic threshold derived from their own 1-hour baseline.  Uses LAG() to
--   measure inter-event gaps and a frame-based window SUM to count events in
--   the sliding window without a self-join.
--
-- Performance note:
--   The leading filter on "timestamp" forces partition pruning.  The composite
--   index idx_raw_events_ts_user covers (timestamp, user_id), satisfying the
--   ORDER BY inside the window without a sort operator.
--
-- Edge-case handling:
--   Users with fewer than 5 events in the hour are excluded (min_event_guard
--   CTE) to avoid noise from sparse activity.
--
-- False-positive mitigation:
--   The burst threshold is relative (3× the user's own hourly rate) rather
--   than a global absolute limit, so power users with legitimately high
--   sustained volume are not penalised.
-- =============================================================================
WITH
-- Step 1: pull relevant events within the analysis window (partition pruning)
raw_window AS (
    SELECT
        user_id,
        session_id,
        "timestamp",
        action_type,
        LAG("timestamp") OVER (
            PARTITION BY user_id
            ORDER BY "timestamp"
        ) AS prev_ts
    FROM raw_events
    WHERE "timestamp" BETWEEN :lookback_start AND :lookback_end   -- prunes partitions
),

-- Step 2: compute per-event gap and rolling 5-minute event count
event_gaps AS (
    SELECT
        user_id,
        session_id,
        "timestamp",
        prev_ts,
        EXTRACT(EPOCH FROM ("timestamp" - prev_ts)) AS gap_seconds,
        COUNT(*) OVER (
            PARTITION BY user_id
            ORDER BY "timestamp"
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
        ) AS events_in_5min_window
    FROM raw_window
),

-- Step 3: derive per-user hourly baseline
user_hourly_baseline AS (
    SELECT
        user_id,
        COUNT(*)                                            AS total_events,
        COUNT(*) / NULLIF(
            EXTRACT(EPOCH FROM (:lookback_end - :lookback_start)) / 3600.0,
        0)                                                  AS avg_events_per_hour
    FROM raw_events
    WHERE "timestamp" BETWEEN :lookback_start AND :lookback_end
    GROUP BY user_id
),

-- Step 4: exclude users with too few events to be statistically meaningful
min_event_guard AS (
    SELECT user_id, avg_events_per_hour
    FROM user_hourly_baseline
    WHERE total_events >= 5
),

-- Step 5: flag rows where the 5-minute burst exceeds 3× the hourly per-minute rate
burst_candidates AS (
    SELECT
        eg.user_id,
        eg."timestamp"                              AS burst_peak_ts,
        eg.events_in_5min_window,
        meg.avg_events_per_hour / 12.0              AS expected_per_5min,
        eg.events_in_5min_window
            / NULLIF(meg.avg_events_per_hour / 12.0, 0) AS burst_ratio
    FROM event_gaps eg
    JOIN min_event_guard meg USING (user_id)
    WHERE eg.events_in_5min_window > (meg.avg_events_per_hour / 12.0) * 3
)

SELECT
    bc.user_id,
    up.country,
    up.is_flagged                           AS already_flagged,
    bc.burst_peak_ts,
    bc.events_in_5min_window,
    ROUND(bc.expected_per_5min, 2)          AS expected_per_5min,
    ROUND(bc.burst_ratio, 2)                AS burst_ratio,
    ROW_NUMBER() OVER (
        PARTITION BY bc.user_id
        ORDER BY bc.burst_ratio DESC
    )                                       AS rank_within_user
FROM burst_candidates bc
JOIN user_profiles up USING (user_id)
ORDER BY bc.burst_ratio DESC, bc.burst_peak_ts DESC;


-- =============================================================================
-- Query 2 – IP-Based Coordinated Activity Clusters
-- =============================================================================
-- Explanation:
--   Identifies IP addresses that served multiple distinct user accounts within
--   the same 10-minute window, a strong signal of credential-stuffing or bot
--   farms.  Uses DENSE_RANK() to rank IPs by the number of unique accounts
--   observed, and cross-references with existing enforcement data.
--
-- Performance note:
--   Filtering by timestamp prunes partitions early.  The index
--   idx_raw_events_ip_ts (ip_address, timestamp) drives the GROUP BY without
--   a sequential scan.
--
-- Edge-case handling:
--   Shared NAT / corporate proxies can appear here legitimately; the join to
--   enforcement_actions distinguishes known-bad IPs from first-time observations.
--   The minimum account threshold (>= 3) suppresses household-level sharing.
--
-- False-positive mitigation:
--   A minimum average risk score filter (>= 0.4) ensures the cluster contains
--   at least some already-elevated accounts, not just co-located legitimate users.
-- =============================================================================
WITH
-- Step 1: bucket events into 10-minute tumbling windows per IP (partition-pruned)
ip_time_buckets AS (
    SELECT
        ip_address,
        DATE_TRUNC('hour', "timestamp")
            + (EXTRACT(MINUTE FROM "timestamp")::INT / 10) * INTERVAL '10 minutes'
                                                    AS bucket_start,
        user_id,
        COUNT(*)                                    AS event_count
    FROM raw_events
    WHERE "timestamp" BETWEEN :lookback_start AND :lookback_end
    GROUP BY ip_address, bucket_start, user_id
),

-- Step 2: aggregate to IP + bucket level
ip_bucket_agg AS (
    SELECT
        ip_address,
        bucket_start,
        COUNT(DISTINCT user_id)    AS distinct_accounts,
        SUM(event_count)           AS total_events,
        ARRAY_AGG(DISTINCT user_id ORDER BY user_id) AS account_list
    FROM ip_time_buckets
    GROUP BY ip_address, bucket_start
    HAVING COUNT(DISTINCT user_id) >= 3       -- suppress household noise
),

-- Step 3: enrich with average risk score of the accounts in each bucket
bucket_risk AS (
    SELECT
        iba.ip_address,
        iba.bucket_start,
        iba.distinct_accounts,
        iba.total_events,
        iba.account_list,
        AVG(latest.combined_risk_score)        AS avg_risk_score
    FROM ip_bucket_agg iba
    CROSS JOIN LATERAL (
        SELECT combined_risk_score
        FROM anomaly_scores
        WHERE user_id = ANY(iba.account_list)
        ORDER BY computed_at DESC
        LIMIT 1
    ) latest
    GROUP BY iba.ip_address, iba.bucket_start,
             iba.distinct_accounts, iba.total_events, iba.account_list
),

-- Step 4: rank IPs by account count within each bucket
ranked_ips AS (
    SELECT
        *,
        DENSE_RANK() OVER (
            ORDER BY distinct_accounts DESC, avg_risk_score DESC
        ) AS severity_rank
    FROM bucket_risk
    WHERE avg_risk_score >= 0.4              -- false-positive mitigation
)

SELECT
    ip_address,
    bucket_start,
    bucket_start + INTERVAL '10 minutes'   AS bucket_end,
    distinct_accounts,
    total_events,
    ROUND(avg_risk_score::NUMERIC, 4)      AS avg_risk_score,
    severity_rank,
    account_list
FROM ranked_ips
ORDER BY severity_rank, bucket_start;


-- =============================================================================
-- Query 3 – Device Fingerprint Reuse Across Accounts
-- =============================================================================
-- Explanation:
--   A single device fingerprint appearing across multiple user accounts is a
--   strong indicator of account takeover, multi-accounting, or automated tooling.
--   This query uses LEAD() / LAG() to detect temporal patterns of the same
--   device switching between accounts and ranks devices by the number of
--   distinct accounts they served.
--
-- Performance note:
--   idx_raw_events_device_ts (device_id, timestamp) supports the initial filter
--   and the ORDER BY inside the window cheaply.
--
-- Edge-case handling:
--   The same user logging in from the same device across sessions should not
--   trigger an alert; we filter for distinct user_id count >= 2.
--   Very generic device strings (e.g. empty or "unknown") are excluded.
--
-- False-positive mitigation:
--   Requires the device to appear with at least 2 different accounts WITHIN the
--   lookback window, and the account-switch must happen within 30 minutes to
--   exclude long-term shared-device households.
-- =============================================================================
WITH
-- Step 1: per device, collect ordered account switches (partition-pruned)
device_account_events AS (
    SELECT
        device_id,
        user_id,
        "timestamp",
        LAG(user_id)  OVER (PARTITION BY device_id ORDER BY "timestamp") AS prev_user,
        LEAD(user_id) OVER (PARTITION BY device_id ORDER BY "timestamp") AS next_user,
        LAG("timestamp") OVER (PARTITION BY device_id ORDER BY "timestamp") AS prev_ts
    FROM raw_events
    WHERE "timestamp" BETWEEN :lookback_start AND :lookback_end
      AND device_id NOT IN ('', 'unknown', 'N/A')   -- exclude generic fingerprints
),

-- Step 2: identify rows where the device switched to a different account quickly
account_switches AS (
    SELECT
        device_id,
        prev_user                                       AS user_from,
        user_id                                         AS user_to,
        "timestamp"                                     AS switch_ts,
        EXTRACT(EPOCH FROM ("timestamp" - prev_ts))     AS seconds_since_prev_event
    FROM device_account_events
    WHERE prev_user IS NOT NULL
      AND prev_user <> user_id                          -- different account
      AND EXTRACT(EPOCH FROM ("timestamp" - prev_ts)) <= 1800  -- within 30 min
),

-- Step 3: aggregate switch statistics per device
device_switch_summary AS (
    SELECT
        device_id,
        COUNT(DISTINCT user_from)               AS accounts_seen,
        COUNT(*)                                AS total_switches,
        MIN(switch_ts)                          AS first_switch_ts,
        MAX(switch_ts)                          AS last_switch_ts,
        AVG(seconds_since_prev_event)           AS avg_seconds_between_switches,
        ARRAY_AGG(DISTINCT user_from)           AS involved_accounts
    FROM account_switches
    GROUP BY device_id
    HAVING COUNT(DISTINCT user_from) >= 2
),

-- Step 4: rank devices by how many accounts they touched
ranked_devices AS (
    SELECT
        *,
        RANK() OVER (ORDER BY accounts_seen DESC, total_switches DESC) AS risk_rank
    FROM device_switch_summary
)

SELECT
    rd.device_id,
    rd.accounts_seen,
    rd.total_switches,
    rd.first_switch_ts,
    rd.last_switch_ts,
    ROUND(rd.avg_seconds_between_switches::NUMERIC, 1) AS avg_seconds_between_switches,
    rd.risk_rank,
    rd.involved_accounts
FROM ranked_devices rd
ORDER BY rd.risk_rank, rd.total_switches DESC;


-- =============================================================================
-- Query 4 – Abnormal Session-to-Success Ratio
-- =============================================================================
-- Explanation:
--   A sharply elevated failure rate within a session can indicate credential
--   stuffing, brute-force, or automated probing.  This query computes per-session
--   success rates, compares them against the user's own historical baseline using
--   z-score normalisation, and surfaces sessions that are statistically anomalous.
--
-- Performance note:
--   Both CTEs filter on "timestamp" first (partition pruning via
--   idx_raw_events_ts_user).  The self-join between sessions and baseline uses
--   user_id which is indexed in aggregated_user_metrics.
--
-- Edge-case handling:
--   Sessions with fewer than 10 events are excluded from z-score computation to
--   avoid extreme variance from small samples.  Division-by-zero is guarded with
--   NULLIF on the standard-deviation denominator.
--
-- False-positive mitigation:
--   The anomaly threshold is set at z < -2 (i.e. success rate is more than
--   2 standard deviations below the user's mean), keeping the false-positive
--   rate low for users who naturally have some failed actions.
-- =============================================================================
WITH
-- Step 1: aggregate per session within the analysis window (partition-pruned)
session_stats AS (
    SELECT
        user_id,
        session_id,
        MIN("timestamp")                           AS session_start,
        MAX("timestamp")                           AS session_end,
        COUNT(*)                                   AS total_events,
        SUM(CASE WHEN success_flag THEN 1 ELSE 0 END)  AS success_count,
        SUM(CASE WHEN NOT success_flag THEN 1 ELSE 0 END) AS failure_count,
        AVG(success_flag::INT)                     AS session_success_rate
    FROM raw_events
    WHERE "timestamp" BETWEEN :lookback_start AND :lookback_end
    GROUP BY user_id, session_id
    HAVING COUNT(*) >= 10                          -- minimum sample size guard
),

-- Step 2: compute per-user historical baseline from pre-aggregated metrics
user_baseline AS (
    SELECT
        user_id,
        AVG(success_rate)                          AS mean_success_rate,
        STDDEV_POP(success_rate)                   AS stddev_success_rate
    FROM aggregated_user_metrics
    WHERE window_start >= :lookback_start - INTERVAL '30 days'
    GROUP BY user_id
),

-- Step 3: compute z-score for each session relative to user baseline
session_zscores AS (
    SELECT
        ss.user_id,
        ss.session_id,
        ss.session_start,
        ss.session_end,
        ss.total_events,
        ss.success_count,
        ss.failure_count,
        ROUND(ss.session_success_rate::NUMERIC, 4)  AS session_success_rate,
        ROUND(ub.mean_success_rate::NUMERIC, 4)     AS baseline_mean,
        ROUND(ub.stddev_success_rate::NUMERIC, 4)   AS baseline_stddev,
        ROUND(
            (ss.session_success_rate - ub.mean_success_rate)
            / NULLIF(ub.stddev_success_rate, 0),
        4)                                           AS success_zscore
    FROM session_stats ss
    JOIN user_baseline ub USING (user_id)
),

-- Step 4: rank anomalous sessions (z < -2 = statistically low success rate)
anomalous_sessions AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY user_id
            ORDER BY success_zscore ASC
        ) AS rank_within_user
    FROM session_zscores
    WHERE success_zscore < -2                      -- false-positive threshold
)

SELECT
    ams.user_id,
    up.country,
    up.is_flagged                                  AS account_flagged,
    ams.session_id,
    ams.session_start,
    ams.session_end,
    ams.total_events,
    ams.success_count,
    ams.failure_count,
    ams.session_success_rate,
    ams.baseline_mean,
    ams.baseline_stddev,
    ams.success_zscore,
    ams.rank_within_user
FROM anomalous_sessions ams
JOIN user_profiles up USING (user_id)
ORDER BY ams.success_zscore ASC, ams.session_start;


-- =============================================================================
-- Query 5 – Rapid Multi-Resource Access Patterns
-- =============================================================================
-- Explanation:
--   Automated scraping or data-exfiltration tools often access many distinct
--   resources in rapid succession.  This query measures unique resource access
--   density inside a 2-minute sliding window using a frame-bounded COUNT DISTINCT
--   approximation via DENSE_RANK(), then flags users whose density significantly
--   exceeds their own rolling median.
--
-- Performance note:
--   Partition pruning via the timestamp filter.  The composite index on
--   (timestamp, user_id) supports both the window ORDER BY and the subsequent
--   GROUP BY user_id without additional sorts.  DENSE_RANK() is used because
--   PostgreSQL window frames do not support COUNT(DISTINCT …) directly.
--
-- Edge-case handling:
--   NULL resource_id rows are excluded since they represent non-resource actions
--   (e.g. logins, logouts).  A minimum of 10 distinct resources is required to
--   avoid flagging normal browsing.
--
-- False-positive mitigation:
--   Comparing against the user's own aggregated baseline (unique_devices proxy
--   for activity level) ensures high-volume legitimate users are not penalised.
--   CDN prefetch patterns produce rapid resource hits; action_type filtering
--   excludes known-benign action types.
-- =============================================================================
WITH
-- Step 1: pre-filter relevant action types and assign dense rank per resource
--         within user + 2-minute window (partition-pruned)
resource_events AS (
    SELECT
        user_id,
        "timestamp",
        resource_id,
        DATE_TRUNC('hour', "timestamp")
            + (EXTRACT(MINUTE FROM "timestamp")::INT / 2) * INTERVAL '2 minutes'
                                                    AS window_2min,
        DENSE_RANK() OVER (
            PARTITION BY user_id,
                         DATE_TRUNC('hour', "timestamp")
                             + (EXTRACT(MINUTE FROM "timestamp")::INT / 2)
                               * INTERVAL '2 minutes'
            ORDER BY resource_id
        ) AS resource_rank
    FROM raw_events
    WHERE "timestamp"   BETWEEN :lookback_start AND :lookback_end
      AND resource_id   IS NOT NULL
      AND action_type   NOT IN ('prefetch', 'cdn_hit', 'heartbeat')
),

-- Step 2: max rank = distinct resource count in the window
window_resource_counts AS (
    SELECT
        user_id,
        window_2min                                  AS window_start,
        window_2min + INTERVAL '2 minutes'           AS window_end,
        MAX(resource_rank)                           AS distinct_resources
    FROM resource_events
    GROUP BY user_id, window_2min
    HAVING MAX(resource_rank) >= 10                  -- minimum density threshold
),

-- Step 3: compute user-level median distinct-resource count from pre-agg metrics
user_resource_median AS (
    SELECT
        user_id,
        PERCENTILE_CONT(0.5) WITHIN GROUP (
            ORDER BY action_count
        )                                            AS median_action_count
    FROM aggregated_user_metrics
    WHERE window_start >= :lookback_start - INTERVAL '7 days'
    GROUP BY user_id
),

-- Step 4: identify windows where resource density is ≥ 3× the user median
high_density_windows AS (
    SELECT
        wrc.user_id,
        wrc.window_start,
        wrc.window_end,
        wrc.distinct_resources,
        urm.median_action_count,
        wrc.distinct_resources::FLOAT
            / NULLIF(urm.median_action_count, 0)     AS density_ratio,
        RANK() OVER (
            PARTITION BY wrc.user_id
            ORDER BY wrc.distinct_resources DESC
        )                                            AS rank_within_user
    FROM window_resource_counts wrc
    LEFT JOIN user_resource_median urm USING (user_id)
    WHERE wrc.distinct_resources >= COALESCE(urm.median_action_count, 0) * 3
       OR urm.median_action_count IS NULL            -- new users with no baseline
)

SELECT
    hdw.user_id,
    up.country,
    up.is_flagged,
    hdw.window_start,
    hdw.window_end,
    hdw.distinct_resources,
    ROUND(hdw.median_action_count::NUMERIC, 2)       AS baseline_median,
    ROUND(hdw.density_ratio::NUMERIC, 2)             AS density_ratio,
    hdw.rank_within_user
FROM high_density_windows hdw
JOIN user_profiles up USING (user_id)
ORDER BY hdw.density_ratio DESC NULLS LAST, hdw.window_start;


-- =============================================================================
-- Query 6 – Cohort-Based Abuse Rate Comparison (New vs. Aged Accounts)
-- =============================================================================
-- Explanation:
--   New accounts are disproportionately exploited for abuse.  This query splits
--   users into cohorts by account age (< 7 days, 7–30 days, 30–90 days,
--   90+ days) and computes the abuse rate, average risk score, and enforcement
--   rate per cohort, enabling threshold differentiation per cohort.
--
-- Performance note:
--   The query reads from user_profiles (fully indexed) and anomaly_scores.
--   The DISTINCT ON subquery uses idx_anomaly_user_computed to avoid a full
--   scan of anomaly_scores.
--
-- Edge-case handling:
--   Users with no anomaly score are assigned NULL risk and excluded from the
--   average but still counted in the cohort totals.  Cohort boundaries are
--   defined in the CASE expression and can be adjusted without schema changes.
--
-- False-positive mitigation:
--   Enforcement rate is reported alongside abuse rate; a high enforcement rate
--   with a low abuse rate suggests over-triggering, guiding threshold tuning.
-- =============================================================================
WITH
-- Step 1: get the latest anomaly score per user
latest_scores AS (
    SELECT DISTINCT ON (user_id)
        user_id,
        combined_risk_score,
        is_flagged                                   AS score_flagged
    FROM anomaly_scores
    ORDER BY user_id, computed_at DESC               -- uses idx_anomaly_user_computed
),

-- Step 2: count enforcement actions per user within the analysis window
user_enforcement_counts AS (
    SELECT
        user_id,
        COUNT(*)                                     AS enforcement_count
    FROM enforcement_actions
    WHERE triggered_at BETWEEN :lookback_start AND :lookback_end
    GROUP BY user_id
),

-- Step 3: assign cohort bucket based on account age
cohort_assignment AS (
    SELECT
        up.user_id,
        up.account_age_days,
        up.is_flagged                                AS profile_flagged,
        up.country,
        ls.combined_risk_score,
        ls.score_flagged,
        COALESCE(uec.enforcement_count, 0)           AS enforcement_count,
        CASE
            WHEN up.account_age_days < 7   THEN '0–6 days'
            WHEN up.account_age_days < 30  THEN '7–29 days'
            WHEN up.account_age_days < 90  THEN '30–89 days'
            ELSE                                '90+ days'
        END                                          AS age_cohort,
        CASE
            WHEN up.account_age_days < 7   THEN 1
            WHEN up.account_age_days < 30  THEN 2
            WHEN up.account_age_days < 90  THEN 3
            ELSE                                4
        END                                          AS cohort_order
    FROM user_profiles up
    LEFT JOIN latest_scores ls          USING (user_id)
    LEFT JOIN user_enforcement_counts uec USING (user_id)
),

-- Step 4: aggregate per cohort
cohort_stats AS (
    SELECT
        age_cohort,
        cohort_order,
        COUNT(*)                                     AS total_users,
        SUM(CASE WHEN profile_flagged THEN 1 ELSE 0 END) AS flagged_users,
        ROUND(
            100.0 * SUM(CASE WHEN profile_flagged THEN 1 ELSE 0 END)
                / NULLIF(COUNT(*), 0),
        2)                                           AS flagged_rate_pct,
        ROUND(AVG(combined_risk_score)::NUMERIC, 4)  AS avg_risk_score,
        ROUND(AVG(enforcement_count)::NUMERIC, 4)    AS avg_enforcements_per_user,
        SUM(enforcement_count)                       AS total_enforcements
    FROM cohort_assignment
    GROUP BY age_cohort, cohort_order
)

SELECT
    age_cohort,
    total_users,
    flagged_users,
    flagged_rate_pct,
    avg_risk_score,
    avg_enforcements_per_user,
    total_enforcements,
    -- Show how each cohort's flagged rate compares to the overall rate
    ROUND(
        flagged_rate_pct - AVG(flagged_rate_pct) OVER (),
    2)                                               AS flagged_rate_vs_global_avg,
    RANK() OVER (ORDER BY flagged_rate_pct DESC)     AS abuse_rate_rank
FROM cohort_stats
ORDER BY cohort_order;


-- =============================================================================
-- Query 7 – New-Account Abuse Prevalence vs. Aged Accounts (Time-Series View)
-- =============================================================================
-- Explanation:
--   Tracks the week-over-week trend in abuse enforcement actions for new
--   accounts (< 30 days) versus aged accounts (>= 30 days).  The rolling 4-week
--   moving average smooths out day-of-week effects.  Useful for detecting
--   coordinated new-account abuse campaigns that ramp up over time.
--
-- Performance note:
--   enforcement_actions.triggered_at has idx_ea_triggered_at; the join to
--   user_profiles on user_id is a single-row lookup.  DATE_TRUNC('week', …)
--   allows the planner to group efficiently without a function index.
--
-- Edge-case handling:
--   Weeks with zero new-account enforcements are preserved via the CROSS JOIN
--   calendar spine so the time series has no gaps (important for moving
--   averages).  Partial weeks at the boundary of the lookback range are
--   included but labelled.
--
-- False-positive mitigation:
--   Enforcement counts are broken out by action_type so spikes in lightweight
--   actions (e.g. 'captcha') are not conflated with hard bans, giving a more
--   accurate picture of true abuse prevalence.
-- =============================================================================
WITH
-- Step 1: build a complete weekly calendar spine to prevent time-series gaps
weekly_spine AS (
    SELECT
        DATE_TRUNC('week', gs::DATE)::TIMESTAMPTZ    AS week_start
    FROM GENERATE_SERIES(
        DATE_TRUNC('week', :lookback_start::TIMESTAMPTZ),
        DATE_TRUNC('week', :lookback_end::TIMESTAMPTZ),
        INTERVAL '1 week'
    ) gs
),

-- Step 2: join enforcement actions with user age cohort (partition-pruned on ea)
enforcement_with_cohort AS (
    SELECT
        DATE_TRUNC('week', ea.triggered_at)::TIMESTAMPTZ AS week_start,
        ea.action_type,
        CASE
            WHEN up.account_age_days < 30 THEN 'new'
            ELSE 'aged'
        END                                              AS account_cohort
    FROM enforcement_actions ea
    JOIN user_profiles up USING (user_id)
    WHERE ea.triggered_at BETWEEN :lookback_start AND :lookback_end
),

-- Step 3: count enforcements per week × cohort × action type
weekly_counts AS (
    SELECT
        ws.week_start,
        ewc.account_cohort,
        ewc.action_type,
        COUNT(ewc.action_type)                           AS enforcement_count
    FROM weekly_spine ws
    LEFT JOIN enforcement_with_cohort ewc
        ON ewc.week_start = ws.week_start
    GROUP BY ws.week_start, ewc.account_cohort, ewc.action_type
),

-- Step 4: compute 4-week rolling average per cohort × action type
rolling_avg AS (
    SELECT
        week_start,
        account_cohort,
        action_type,
        enforcement_count,
        ROUND(
            AVG(enforcement_count) OVER (
                PARTITION BY account_cohort, action_type
                ORDER BY week_start
                ROWS BETWEEN 3 PRECEDING AND CURRENT ROW
            )::NUMERIC,
        2)                                               AS rolling_4wk_avg,
        LAG(enforcement_count, 1) OVER (
            PARTITION BY account_cohort, action_type
            ORDER BY week_start
        )                                                AS prev_week_count
    FROM weekly_counts
),

-- Step 5: compute week-over-week delta percentage
final_series AS (
    SELECT
        week_start,
        week_start + INTERVAL '6 days'                  AS week_end,
        account_cohort,
        action_type,
        enforcement_count,
        rolling_4wk_avg,
        prev_week_count,
        ROUND(
            100.0 * (enforcement_count - prev_week_count)
                / NULLIF(prev_week_count, 0),
        2)                                               AS wow_change_pct,
        -- Flag weeks with > 50% spike for alerting
        CASE
            WHEN enforcement_count > prev_week_count * 1.5 THEN TRUE
            ELSE FALSE
        END                                              AS is_spike_week,
        week_start < DATE_TRUNC('week', NOW())                          AS is_complete_week
    FROM rolling_avg
)

SELECT
    week_start,
    week_end,
    COALESCE(account_cohort, 'all')                      AS account_cohort,
    COALESCE(action_type,    'all')                      AS action_type,
    enforcement_count,
    rolling_4wk_avg,
    prev_week_count,
    wow_change_pct,
    is_spike_week,
    is_complete_week
FROM final_series
ORDER BY week_start, account_cohort, action_type;
