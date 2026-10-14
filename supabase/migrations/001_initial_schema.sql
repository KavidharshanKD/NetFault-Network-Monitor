-- ============================================================================
-- Automated Fault Detection System (AFDS)
-- Supabase PostgreSQL Initial Schema Migration
-- Migration 001: Initial Tables, Views, Indexes, Constraints, and Seed Data
-- ============================================================================

-- Ensure pgcrypto extension is available for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- Table 1: devices
-- Stores network device inventory, target IPs, optional TCP ports, and flags
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
    description TEXT,
    monitoring_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique index to prevent duplicate IP + Port registrations
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_port_unique 
    ON devices (ip_address, COALESCE(port, -1));

CREATE INDEX IF NOT EXISTS idx_devices_name 
    ON devices (device_name);

CREATE INDEX IF NOT EXISTS idx_devices_monitoring_enabled 
    ON devices (monitoring_enabled);

-- ----------------------------------------------------------------------------
-- Table 2: monitoring_history
-- Records every ICMP ping and TCP socket connectivity check
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
-- Table 3: application_settings
-- Key-value persistent operational parameters for the monitoring daemon
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
-- Table 4: traceroute_history
-- Localized network path diagnostic hops for pinpointing routing faults
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
-- Table 5: users
-- Application administration users (Email + Hashed Password, no Supabase Auth required)
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
-- View 1: devices_with_status
-- Joins devices with their single most recent monitoring_history record
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW devices_with_status AS
SELECT 
    d.id,
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

-- ----------------------------------------------------------------------------
-- View 2: monitoring_history_with_devices
-- Enriches history records with device metadata
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW monitoring_history_with_devices AS
SELECT 
    h.id,
    h.device_id,
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

-- ----------------------------------------------------------------------------
-- Seed Initial Application Settings (Idempotent: does not overwrite existing values)
-- ----------------------------------------------------------------------------
INSERT INTO application_settings (setting_key, setting_value, updated_at)
VALUES
    ('monitor_interval', '30'::jsonb, NOW()),
    ('ping_timeout', '2'::jsonb, NOW()),
    ('tcp_timeout', '2'::jsonb, NOW()),
    ('ping_count', '1'::jsonb, NOW()),
    ('concurrency_limit', '5'::jsonb, NOW()),
    ('auto_monitoring', '1'::jsonb, NOW())
ON CONFLICT (setting_key) DO NOTHING;

-- ----------------------------------------------------------------------------
-- Seed Default Administrator User
-- Default Credentials:
-- Email:    admin@supabase.local
-- Password: admin123
-- ----------------------------------------------------------------------------
INSERT INTO users (email, password_hash, full_name, role, created_at, updated_at)
VALUES (
    'admin@supabase.local',
    'scrypt:32768:8:1$cGn0M4MXX9oPibGZ$2e82f387803dde7ee4023efb75ad04655430be7d2505e93fa8f17dc88de9b04b4452aa8d660144f8cecee32cb289d5932cfe82b5c02bc778a78a1b004ca655b1',
    'Network Administrator',
    'admin',
    NOW(),
    NOW()
)
ON CONFLICT (LOWER(email)) DO NOTHING;

-- ----------------------------------------------------------------------------
-- Automatic timestamp update triggers
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
