-- =============================================================================
-- Abuse Pattern Detection & Risk Monitoring System
-- PostgreSQL Production Schema
-- =============================================================================
-- Design principles:
--   • raw_events is range-partitioned by month for efficient pruning & archiving
--   • Every FK references a concrete partition key so queries stay on-partition
--   • Indexes are targeted: composite where selectivity benefits from it
--   • UUIDs are used for externally-visible identifiers; serial for internal PKs
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "btree_gist"; -- GiST indexes on range types if needed later

-- =============================================================================
-- 1. raw_events
-- Immutable event log.  Partitioned by month so old partitions can be detached
-- and archived without locking the live table.
-- =============================================================================
CREATE TABLE raw_events (
    event_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    user_id            UUID        NOT NULL,
    session_id         UUID        NOT NULL,
    -- timestamp is the partition key; must appear in every index on this table
    "timestamp"        TIMESTAMPTZ NOT NULL,
    ip_address         INET        NOT NULL,
    device_id          TEXT        NOT NULL,
    action_type        TEXT        NOT NULL,
    resource_id        TEXT,
    -- Stored as (longitude, latitude) text; use POINT or PostGIS geography in
    -- deployments that need spatial queries.
    geo_location       TEXT,
    success_flag       BOOLEAN     NOT NULL DEFAULT TRUE,
    enforcement_action TEXT,                 -- NULL means no enforcement taken
    PRIMARY KEY (event_id, "timestamp")      -- partition key must be in PK
) PARTITION BY RANGE ("timestamp");

COMMENT ON TABLE raw_events IS
  'Immutable stream of all user-generated events.  '
  'Partitioned monthly; each partition covers one calendar month.';
COMMENT ON COLUMN raw_events.geo_location       IS 'Approximate location string, e.g. "37.7749,-122.4194".';
COMMENT ON COLUMN raw_events.enforcement_action IS 'Populated when an automated enforcement action was taken in real-time (e.g. "rate_limit", "block").';

-- Seed partitions: adjust the range as needed for production
CREATE TABLE raw_events_2024_01 PARTITION OF raw_events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE raw_events_2024_02 PARTITION OF raw_events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
CREATE TABLE raw_events_2024_03 PARTITION OF raw_events
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');
CREATE TABLE raw_events_2024_04 PARTITION OF raw_events
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');
CREATE TABLE raw_events_2024_05 PARTITION OF raw_events
    FOR VALUES FROM ('2024-05-01') TO ('2024-06-01');
CREATE TABLE raw_events_2024_06 PARTITION OF raw_events
    FOR VALUES FROM ('2024-06-01') TO ('2024-07-01');
CREATE TABLE raw_events_2024_07 PARTITION OF raw_events
    FOR VALUES FROM ('2024-07-01') TO ('2024-08-01');
CREATE TABLE raw_events_2024_08 PARTITION OF raw_events
    FOR VALUES FROM ('2024-08-01') TO ('2024-09-01');
CREATE TABLE raw_events_2024_09 PARTITION OF raw_events
    FOR VALUES FROM ('2024-09-01') TO ('2024-10-01');
CREATE TABLE raw_events_2024_10 PARTITION OF raw_events
    FOR VALUES FROM ('2024-10-01') TO ('2024-11-01');
CREATE TABLE raw_events_2024_11 PARTITION OF raw_events
    FOR VALUES FROM ('2024-11-01') TO ('2024-12-01');
CREATE TABLE raw_events_2024_12 PARTITION OF raw_events
    FOR VALUES FROM ('2024-12-01') TO ('2025-01-01');
CREATE TABLE raw_events_2025_01 PARTITION OF raw_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE raw_events_2025_02 PARTITION OF raw_events
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE raw_events_2025_03 PARTITION OF raw_events
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE raw_events_2025_04 PARTITION OF raw_events
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE raw_events_2025_05 PARTITION OF raw_events
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE raw_events_2025_06 PARTITION OF raw_events
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE raw_events_2025_07 PARTITION OF raw_events
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE raw_events_2025_08 PARTITION OF raw_events
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE raw_events_2025_09 PARTITION OF raw_events
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE raw_events_2025_10 PARTITION OF raw_events
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE raw_events_2025_11 PARTITION OF raw_events
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE raw_events_2025_12 PARTITION OF raw_events
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Catch-all partition for rows outside the seeded ranges (prevents insert errors)
CREATE TABLE raw_events_default PARTITION OF raw_events DEFAULT;

-- Indexes on each partition are automatically inherited.
-- Composite indexes put the partition key first so the planner can prune.
CREATE INDEX idx_raw_events_ts_user
    ON raw_events ("timestamp", user_id);

CREATE INDEX idx_raw_events_ip_ts
    ON raw_events (ip_address, "timestamp");

CREATE INDEX idx_raw_events_device_ts
    ON raw_events (device_id, "timestamp");

CREATE INDEX idx_raw_events_session_ts
    ON raw_events (session_id, "timestamp");

CREATE INDEX idx_raw_events_action_ts
    ON raw_events (action_type, "timestamp");

-- =============================================================================
-- 2. user_profiles
-- One row per account; append-only risk flags are stored here so joins are
-- cheap (single-row lookup).
-- =============================================================================
CREATE TABLE user_profiles (
    user_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    account_age_days INTEGER     NOT NULL DEFAULT 0
                                 CHECK (account_age_days >= 0),
    country          CHAR(2),                              -- ISO 3166-1 alpha-2
    is_flagged       BOOLEAN     NOT NULL DEFAULT FALSE,
    last_activity_at TIMESTAMPTZ
);

COMMENT ON TABLE user_profiles IS
  'Master record for each user account.  '
  'is_flagged is a soft-flag set by the risk pipeline; '
  'enforcement_actions holds the authoritative audit trail.';
COMMENT ON COLUMN user_profiles.country          IS 'ISO 3166-1 alpha-2 country code derived from registration or last known IP.';
COMMENT ON COLUMN user_profiles.account_age_days IS 'Computed column kept up-to-date by a scheduled job; used for cohort bucketing.';

CREATE INDEX idx_user_profiles_flagged
    ON user_profiles (is_flagged)
    WHERE is_flagged = TRUE;          -- partial index; only flagged rows

CREATE INDEX idx_user_profiles_country
    ON user_profiles (country);

CREATE INDEX idx_user_profiles_last_activity
    ON user_profiles (last_activity_at DESC);

-- =============================================================================
-- 3. aggregated_user_metrics
-- Pre-aggregated counters materialized by the risk pipeline for each user over
-- rolling or tumbling time windows.  Avoid recomputing these on every query.
-- =============================================================================
CREATE TABLE aggregated_user_metrics (
    metric_id         BIGSERIAL   PRIMARY KEY,
    user_id           UUID        NOT NULL REFERENCES user_profiles (user_id)
                                  ON DELETE CASCADE,
    window_start      TIMESTAMPTZ NOT NULL,
    window_end        TIMESTAMPTZ NOT NULL,
    action_count      INTEGER     NOT NULL DEFAULT 0 CHECK (action_count >= 0),
    unique_ips        INTEGER     NOT NULL DEFAULT 0 CHECK (unique_ips >= 0),
    unique_devices    INTEGER     NOT NULL DEFAULT 0 CHECK (unique_devices >= 0),
    -- Stored as 0.0–1.0
    success_rate      NUMERIC(5,4)          CHECK (success_rate BETWEEN 0 AND 1),
    enforcement_count INTEGER     NOT NULL DEFAULT 0 CHECK (enforcement_count >= 0),
    CONSTRAINT aum_window_order CHECK (window_start < window_end)
);

COMMENT ON TABLE aggregated_user_metrics IS
  'Per-user pre-aggregated metrics over discrete or sliding time windows.  '
  'Populated by the risk pipeline; powers dashboards and threshold checks.';

CREATE INDEX idx_aum_user_window
    ON aggregated_user_metrics (user_id, window_start, window_end);

CREATE INDEX idx_aum_window_start
    ON aggregated_user_metrics (window_start);

-- =============================================================================
-- 4. time_window_activity
-- Fine-grained burst detection.  Each row captures activity within a labelled
-- window type (e.g. "1min", "5min", "1hr") so burst scores can be compared
-- across granularities.
-- =============================================================================
CREATE TABLE time_window_activity (
    window_id    BIGSERIAL   PRIMARY KEY,
    user_id      UUID        NOT NULL REFERENCES user_profiles (user_id)
                             ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,
    -- e.g. '1min', '5min', '15min', '1hr', '24hr'
    window_type  TEXT        NOT NULL,
    action_count INTEGER     NOT NULL DEFAULT 0 CHECK (action_count >= 0),
    -- Normalised burst intensity score in [0, 1]; 1 = maximum observed burst
    burst_score  NUMERIC(6,4)         CHECK (burst_score BETWEEN 0 AND 1),
    CONSTRAINT twa_window_order CHECK (window_start < window_end)
);

COMMENT ON TABLE time_window_activity IS
  'Burst-level activity snapshots across multiple window granularities.  '
  'burst_score is a normalised intensity metric used for anomaly detection.';

CREATE INDEX idx_twa_user_start
    ON time_window_activity (user_id, window_start);

CREATE INDEX idx_twa_type_start
    ON time_window_activity (window_type, window_start);

CREATE INDEX idx_twa_burst_score
    ON time_window_activity (burst_score DESC)
    WHERE burst_score > 0.75;         -- partial index on high-burst rows

-- =============================================================================
-- 5. anomaly_scores
-- Output of the ML scoring pipeline.  Each model run appends a row; the
-- latest score per user is resolved via computed_at ordering.
-- =============================================================================
CREATE TABLE anomaly_scores (
    score_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES user_profiles (user_id)
                                    ON DELETE CASCADE,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    zscore_value        NUMERIC(8,4),    -- statistical z-score vs peer cohort
    isolation_score     NUMERIC(6,4)     CHECK (isolation_score BETWEEN 0 AND 1),
    combined_risk_score NUMERIC(6,4)     CHECK (combined_risk_score BETWEEN 0 AND 1),
    is_flagged          BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Semantic version string, e.g. 'v2.3.1'
    model_version       TEXT        NOT NULL
);

COMMENT ON TABLE anomaly_scores IS
  'Append-only ML model outputs.  '
  'combined_risk_score is the weighted blend of zscore and isolation_score.  '
  'Query using DISTINCT ON (user_id) ORDER BY computed_at DESC for latest score.';
COMMENT ON COLUMN anomaly_scores.isolation_score IS 'Isolation Forest anomaly score: higher = more anomalous.';

CREATE INDEX idx_anomaly_user_computed
    ON anomaly_scores (user_id, computed_at DESC);

CREATE INDEX idx_anomaly_flagged_computed
    ON anomaly_scores (is_flagged, computed_at DESC)
    WHERE is_flagged = TRUE;

CREATE INDEX idx_anomaly_risk_score
    ON anomaly_scores (combined_risk_score DESC);

-- =============================================================================
-- 6. enforcement_actions
-- Authoritative audit log of every enforcement decision (manual or automated).
-- =============================================================================
CREATE TABLE enforcement_actions (
    action_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES user_profiles (user_id)
                               ON DELETE CASCADE,
    -- e.g. 'suspend', 'rate_limit', 'captcha', 'ban', 'warning'
    action_type    TEXT        NOT NULL,
    triggered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trigger_reason TEXT        NOT NULL,
    resolved_at    TIMESTAMPTZ,
    -- e.g. 'confirmed_abuse', 'false_positive', 'appealed', 'expired'
    outcome        TEXT,
    CONSTRAINT ea_resolution_order CHECK (
        resolved_at IS NULL OR resolved_at >= triggered_at
    )
);

COMMENT ON TABLE enforcement_actions IS
  'Append-only audit log of enforcement decisions against user accounts.  '
  'resolved_at and outcome are populated when the action is closed.';

CREATE INDEX idx_ea_user_triggered
    ON enforcement_actions (user_id, triggered_at DESC);

CREATE INDEX idx_ea_triggered_at
    ON enforcement_actions (triggered_at DESC);

CREATE INDEX idx_ea_open_actions
    ON enforcement_actions (user_id, triggered_at)
    WHERE resolved_at IS NULL;        -- partial index; only open (unresolved) actions

-- =============================================================================
-- 7. abuse_clusters
-- Groups of users sharing behavioural or network characteristics that suggest
-- coordinated abuse.  Populated by the clustering pipeline.
-- =============================================================================
CREATE TABLE abuse_clusters (
    cluster_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cluster_size    INTEGER     NOT NULL CHECK (cluster_size > 0),
    avg_risk_score  NUMERIC(6,4)          CHECK (avg_risk_score BETWEEN 0 AND 1),
    -- Comma-separated or JSON array of shared IP addresses
    shared_ips      TEXT,
    -- Comma-separated or JSON array of shared device fingerprints
    shared_devices  TEXT,
    -- Human-readable cluster label, e.g. 'credential_stuffing', 'scraping_ring'
    cluster_label   TEXT
);

COMMENT ON TABLE abuse_clusters IS
  'Clusters of users exhibiting coordinated abuse behaviour.  '
  'shared_ips / shared_devices store serialised arrays; '
  'consider JSONB columns with GIN indexes for large-scale deployments.';

CREATE INDEX idx_clusters_detected
    ON abuse_clusters (detected_at DESC);

CREATE INDEX idx_clusters_label
    ON abuse_clusters (cluster_label);

CREATE INDEX idx_clusters_risk
    ON abuse_clusters (avg_risk_score DESC)
    WHERE avg_risk_score > 0.5;

-- =============================================================================
-- 8. threshold_history
-- Versioned audit trail of every risk-threshold change, enabling retrospective
-- analysis and compliance reporting.
-- =============================================================================
CREATE TABLE threshold_history (
    threshold_id        BIGSERIAL    PRIMARY KEY,
    metric_name         TEXT         NOT NULL,
    threshold_value     NUMERIC(10,4) NOT NULL,
    -- Measured on a validation dataset at the time of the change
    false_positive_rate NUMERIC(5,4)  CHECK (false_positive_rate BETWEEN 0 AND 1),
    false_negative_rate NUMERIC(5,4)  CHECK (false_negative_rate BETWEEN 0 AND 1),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Username or service account that made the change
    updated_by          TEXT         NOT NULL
);

COMMENT ON TABLE threshold_history IS
  'Append-only versioned log of risk-threshold configurations.  '
  'Enables point-in-time reconstruction of the thresholds active during any incident.';

CREATE INDEX idx_threshold_metric_updated
    ON threshold_history (metric_name, updated_at DESC);

CREATE INDEX idx_threshold_updated
    ON threshold_history (updated_at DESC);
