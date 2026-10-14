-- ============================================================================
-- Automated Fault Detection System (AFDS)
-- Supabase PostgreSQL Schema Migration 004
-- Feature: Packet Loss Percentage Monitoring & Telemetry Persistence
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Extend monitoring_history with packet-loss & round-trip time metrics
-- Backward-compatible: all columns are NULLABLE so older history remains valid
-- ----------------------------------------------------------------------------
ALTER TABLE monitoring_history 
    ADD COLUMN IF NOT EXISTS packets_sent INTEGER,
    ADD COLUMN IF NOT EXISTS packets_received INTEGER,
    ADD COLUMN IF NOT EXISTS packets_lost INTEGER,
    ADD COLUMN IF NOT EXISTS packet_loss_pct DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS min_rtt_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS max_rtt_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS avg_rtt_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS packet_loss_status TEXT;

-- Index for filtering and auditing packet loss
CREATE INDEX IF NOT EXISTS idx_history_packet_loss_pct 
    ON monitoring_history (packet_loss_pct);

CREATE INDEX IF NOT EXISTS idx_history_packet_loss_status 
    ON monitoring_history (packet_loss_status);

-- ----------------------------------------------------------------------------
-- 2. Update View: devices_with_status
-- Exposes latest packet loss percentage and probe counters on device objects
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW devices_with_status AS
SELECT 
    d.id,
    d.device_name,
    d.ip_address,
    d.port,
    d.description,
    d.monitoring_enabled,
    d.user_id,
    d.created_at,
    d.updated_at,
    h.overall_status,
    h.reachability_status,
    h.service_status,
    h.response_time_ms,
    h.packets_sent,
    h.packets_received,
    h.packets_lost,
    h.packet_loss_pct,
    h.min_rtt_ms,
    h.max_rtt_ms,
    h.avg_rtt_ms,
    h.packet_loss_status,
    h.fault_category,
    h.fault_details,
    h.checked_at AS last_checked
FROM devices d
LEFT JOIN LATERAL (
    SELECT 
        mh.overall_status,
        mh.reachability_status,
        mh.service_status,
        mh.response_time_ms,
        mh.packets_sent,
        mh.packets_received,
        mh.packets_lost,
        mh.packet_loss_pct,
        mh.min_rtt_ms,
        mh.max_rtt_ms,
        mh.avg_rtt_ms,
        mh.packet_loss_status,
        mh.fault_category,
        mh.fault_details,
        mh.checked_at
    FROM monitoring_history mh
    WHERE mh.device_id = d.id
    ORDER BY mh.checked_at DESC, mh.id DESC
    LIMIT 1
) h ON true;

-- ----------------------------------------------------------------------------
-- 3. Update View: monitoring_history_with_devices
-- Enriches history records with device metadata and packet-loss telemetry
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW monitoring_history_with_devices AS
SELECT 
    h.id,
    h.device_id,
    d.device_name,
    d.ip_address,
    d.port,
    d.user_id,
    h.checked_at,
    h.reachability_status,
    h.service_status,
    h.overall_status,
    h.response_time_ms,
    h.packets_sent,
    h.packets_received,
    h.packets_lost,
    h.packet_loss_pct,
    h.min_rtt_ms,
    h.max_rtt_ms,
    h.avg_rtt_ms,
    h.packet_loss_status,
    h.fault_category,
    h.fault_details
FROM monitoring_history h
JOIN devices d ON h.device_id = d.id;

-- ----------------------------------------------------------------------------
-- 4. Seed Default Packet Loss Monitoring Settings into application_settings
-- ----------------------------------------------------------------------------
INSERT INTO application_settings (setting_key, setting_value, updated_at)
VALUES
    ('ping_count', '20'::jsonb, NOW()),
    ('packet_loss_warning_pct', '5'::jsonb, NOW()),
    ('packet_loss_critical_pct', '10'::jsonb, NOW()),
    ('alert_on_packet_loss', '1'::jsonb, NOW())
ON CONFLICT (setting_key) DO NOTHING;
