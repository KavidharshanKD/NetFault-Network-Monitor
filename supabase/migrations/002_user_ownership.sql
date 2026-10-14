-- ============================================================================
-- Automated Fault Detection System (AFDS)
-- Supabase PostgreSQL Migration 002: User Ownership & Row-Level Security
-- ============================================================================

-- 1. Add user_id to devices table to associate devices with authenticated users.
-- References auth.users(id) when Supabase Auth is enabled, with CASCADE or SET NULL on delete.
ALTER TABLE devices 
    ADD COLUMN IF NOT EXISTS user_id UUID;

CREATE INDEX IF NOT EXISTS idx_devices_user_id 
    ON devices (user_id);

-- 2. Update view: devices_with_status to include user_id
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

-- 3. Update view: monitoring_history_with_devices to include user_id
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

-- 4. Row Level Security (RLS) Policies (Optional enforcement at PostgreSQL level)
-- When accessed via Supabase Client with User JWT, RLS restricts rows to auth.uid()
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE traceroute_history ENABLE ROW LEVEL SECURITY;

-- Allow service_role key full access
DROP POLICY IF EXISTS "Service role full access on devices" ON devices;
CREATE POLICY "Service role full access on devices" ON devices
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on monitoring_history" ON monitoring_history;
CREATE POLICY "Service role full access on monitoring_history" ON monitoring_history
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Users can select, insert, update, delete devices they own (or unowned devices during migration)
DROP POLICY IF EXISTS "Users can view and manage their own devices" ON devices;
CREATE POLICY "Users can view and manage their own devices" ON devices
    FOR ALL
    TO authenticated
    USING (auth.uid() = user_id OR user_id IS NULL)
    WITH CHECK (auth.uid() = user_id);

-- Users can view monitoring history for devices they own
DROP POLICY IF EXISTS "Users can view history for their own devices" ON monitoring_history;
CREATE POLICY "Users can view history for their own devices" ON monitoring_history
    FOR SELECT
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM devices d 
            WHERE d.id = monitoring_history.device_id 
              AND (d.user_id = auth.uid() OR d.user_id IS NULL)
        )
    );
