-- ============================================================================
-- Automated Fault Detection System (AFDS)
-- Complete Supabase PostgreSQL Schema & Migrations
-- Copy and run this entire file in your Supabase SQL Editor in one click!
-- ============================================================================

-- Ensure pgcrypto extension is active for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. Table: devices
-- Network device inventory with user ownership and unique IP/Port constraints
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID, -- References auth.users(id) in Supabase Auth
    device_name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
    description TEXT,
    monitoring_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure user_id column exists if table was created previously
ALTER TABLE devices ADD COLUMN IF NOT EXISTS user_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_port_unique 
    ON devices (ip_address, COALESCE(port, -1));

CREATE INDEX IF NOT EXISTS idx_devices_user_id 
    ON devices (user_id);

CREATE INDEX IF NOT EXISTS idx_devices_name 
    ON devices (device_name);

CREATE INDEX IF NOT EXISTS idx_devices_monitoring_enabled 
    ON devices (monitoring_enabled);

-- ----------------------------------------------------------------------------
-- 2. Table: monitoring_history
-- Audit log of ICMP ping reachability and TCP socket status checks
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS monitoring_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reachability_status TEXT NOT NULL,
    service_status TEXT,
    overall_status TEXT NOT NULL CHECK (overall_status IN ('UP', 'DOWN', 'FAULT', 'UNKNOWN')),
    response_time_ms DOUBLE PRECISION,
    fault_category TEXT,
    fault_details TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_device_id 
    ON monitoring_history (device_id);

CREATE INDEX IF NOT EXISTS idx_history_checked_at 
    ON monitoring_history (checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_history_overall_status 
    ON monitoring_history (overall_status);

CREATE INDEX IF NOT EXISTS idx_history_fault_category 
    ON monitoring_history (fault_category);

CREATE INDEX IF NOT EXISTS idx_history_device_checked 
    ON monitoring_history (device_id, checked_at DESC);

-- ----------------------------------------------------------------------------
-- 3. Table: application_settings
-- System monitoring parameters (intervals, timeouts, worker concurrency)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS application_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    setting_key TEXT UNIQUE NOT NULL,
    setting_value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_settings_key 
    ON application_settings (setting_key);

-- ----------------------------------------------------------------------------
-- 4. Table: traceroute_history
-- Hop-by-hop route diagnostics for localizing network path breaks
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS traceroute_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_ip TEXT NOT NULL,
    total_hops INTEGER NOT NULL DEFAULT 0,
    destination_reached BOOLEAN NOT NULL DEFAULT FALSE,
    fault_hop INTEGER,
    fault_summary TEXT,
    hops_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_output TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traceroute_device_executed 
    ON traceroute_history (device_id, executed_at DESC);

-- ----------------------------------------------------------------------------
-- 5. Table: users
-- Fallback administrative table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT 'Network Administrator',
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email 
    ON users (LOWER(email));

-- ----------------------------------------------------------------------------
-- 6. Table: incidents
-- Tracks persistent incident lifecycle, diagnostic findings, and recovery
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id TEXT UNIQUE NOT NULL,
    user_id UUID,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    fault_category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'WARNING', 'INFO')),
    incident_status TEXT NOT NULL DEFAULT 'OPEN' CHECK (incident_status IN ('OPEN', 'RESOLVED')),
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_successful_check TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    error_details TEXT,
    diagnostic_summary TEXT,
    probable_cause TEXT,
    evidence JSONB DEFAULT '[]'::jsonb,
    confidence_level TEXT CHECK (confidence_level IN ('High', 'Medium', 'Low')),
    recommended_action TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_device_status ON incidents (device_id, incident_status);
CREATE INDEX IF NOT EXISTS idx_incidents_user_id ON incidents (user_id);
CREATE INDEX IF NOT EXISTS idx_incidents_detected_at ON incidents (first_detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (incident_status);

-- ----------------------------------------------------------------------------
-- 7. Table: notification_history
-- Audit log of email alerts dispatched with delivery status and retry logs
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('NEW_FAULT', 'RECOVERY', 'LATENCY_WARNING', 'TEST')),
    subject TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('SENT', 'FAILED', 'PENDING')),
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_notifications_incident ON notification_history (incident_id);
CREATE INDEX IF NOT EXISTS idx_notifications_attempted ON notification_history (attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_status ON notification_history (delivery_status);

-- ----------------------------------------------------------------------------
-- 8. Views for Real-Time Telemetry & Reporting
-- ----------------------------------------------------------------------------

-- View 1: devices_with_status (joins devices with their latest check result)
CREATE OR REPLACE VIEW devices_with_status AS
SELECT 
    d.id,
    d.user_id,
    d.device_name,
    d.ip_address,
    d.port,
    d.description,
    d.monitoring_enabled,
    d.created_at,
    d.updated_at,
    h.overall_status,
    h.reachability_status,
    h.service_status,
    h.response_time_ms,
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
        mh.fault_category,
        mh.fault_details,
        mh.checked_at
    FROM monitoring_history mh
    WHERE mh.device_id = d.id
    ORDER BY mh.checked_at DESC, mh.id DESC
    LIMIT 1
) h ON true;

-- View 2: monitoring_history_with_devices (enriches history records with device metadata)
CREATE OR REPLACE VIEW monitoring_history_with_devices AS
SELECT 
    h.id,
    h.device_id,
    d.user_id,
    d.device_name,
    d.ip_address,
    d.port,
    h.checked_at,
    h.reachability_status,
    h.service_status,
    h.overall_status,
    h.response_time_ms,
    h.fault_category,
    h.fault_details
FROM monitoring_history h
JOIN devices d ON h.device_id = d.id;

-- View 3: incidents_with_devices (enriches incident records with device metadata)
CREATE OR REPLACE VIEW incidents_with_devices AS
SELECT 
    i.id,
    i.incident_id,
    i.user_id,
    i.device_id,
    d.device_name,
    d.ip_address,
    d.port,
    i.fault_category,
    i.severity,
    i.incident_status,
    i.first_detected_at,
    i.last_observed_at,
    i.last_successful_check,
    i.recovered_at,
    i.error_details,
    i.diagnostic_summary,
    i.probable_cause,
    i.evidence,
    i.confidence_level,
    i.recommended_action,
    i.created_at,
    i.updated_at
FROM incidents i
JOIN devices d ON i.device_id = d.id;

-- ----------------------------------------------------------------------------
-- 9. Seed Initial Operational Settings
-- ----------------------------------------------------------------------------
INSERT INTO application_settings (setting_key, setting_value, updated_at)
VALUES
    ('monitor_interval', '30'::jsonb, NOW()),
    ('ping_timeout', '2'::jsonb, NOW()),
    ('tcp_timeout', '2'::jsonb, NOW()),
    ('ping_count', '1'::jsonb, NOW()),
    ('concurrency_limit', '5'::jsonb, NOW()),
    ('auto_monitoring', '1'::jsonb, NOW()),
    ('email_notifications_enabled', '0'::jsonb, NOW()),
    ('alert_recipient_email', '""'::jsonb, NOW()),
    ('alert_on_down', '1'::jsonb, NOW()),
    ('alert_on_fault', '1'::jsonb, NOW()),
    ('alert_on_latency', '1'::jsonb, NOW()),
    ('alert_on_recovery', '1'::jsonb, NOW()),
    ('latency_threshold_ms', '200'::jsonb, NOW()),
    ('packet_loss_threshold_pct', '50'::jsonb, NOW()),
    ('smtp_host', '""'::jsonb, NOW()),
    ('smtp_port', '587'::jsonb, NOW()),
    ('smtp_username', '""'::jsonb, NOW()),
    ('smtp_password', '""'::jsonb, NOW()),
    ('smtp_use_tls', '1'::jsonb, NOW()),
    ('alert_sender_email', '"netfault-alerts@local"'::jsonb, NOW()),
    ('netfault_public_url', '"http://127.0.0.1:5000"'::jsonb, NOW())
ON CONFLICT (setting_key) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 10. Automatic timestamp update triggers
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_devices_updated_at ON devices;
CREATE TRIGGER trigger_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_settings_updated_at ON application_settings;
CREATE TRIGGER trigger_settings_updated_at
    BEFORE UPDATE ON application_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_incidents_updated_at ON incidents;
CREATE TRIGGER trigger_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ----------------------------------------------------------------------------
-- 11. Row Level Security (RLS) Policies
-- ----------------------------------------------------------------------------
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE traceroute_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access on devices" ON devices;
CREATE POLICY "Service role full access on devices" ON devices
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on monitoring_history" ON monitoring_history;
CREATE POLICY "Service role full access on monitoring_history" ON monitoring_history
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on traceroute_history" ON traceroute_history;
CREATE POLICY "Service role full access on traceroute_history" ON traceroute_history
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on incidents" ON incidents;
CREATE POLICY "Service role full access on incidents" ON incidents
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on notification_history" ON notification_history;
CREATE POLICY "Service role full access on notification_history" ON notification_history
    FOR ALL TO service_role USING (true) WITH CHECK (true);
