-- ============================================================================
-- Automated Fault Detection System (AFDS)
-- Migration 003: Intelligent Incidents & Email Notification History
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: incidents
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
-- Table: notification_history
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
-- View: incidents_with_devices
-- Enriches incident records with human-readable device name, IP, and port
-- ----------------------------------------------------------------------------
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
-- Seed notification settings defaults into application_settings
-- ----------------------------------------------------------------------------
INSERT INTO application_settings (setting_key, setting_value, updated_at)
VALUES
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
-- Row Level Security (RLS)
-- ----------------------------------------------------------------------------
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access on incidents" ON incidents;
CREATE POLICY "Service role full access on incidents" ON incidents
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on notification_history" ON notification_history;
CREATE POLICY "Service role full access on notification_history" ON notification_history
    FOR ALL TO service_role USING (true) WITH CHECK (true);
