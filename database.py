"""
Database management module for Automated Fault Detection System.
Handles SQLite schema creation, foreign keys, device CRUD, history records, and system settings.
"""

import sqlite3
import logging
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

def get_db_connection(db_path=None):
    """
    Creates a new SQLite database connection with row factory enabled
    and foreign key constraints enforced.
    """
    path = db_path or Config.DATABASE_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path=None):
    """
    Initializes database tables, indexes, and default settings if they do not exist.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            # Devices table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Monitoring history table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reachability_status TEXT NOT NULL,
                    service_status TEXT NOT NULL,
                    overall_status TEXT NOT NULL,
                    response_time_ms REAL,
                    fault_details TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)

            # System settings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)

            # Useful indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_device ON monitoring_history(device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_checked ON monitoring_history(checked_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip_port ON devices(ip_address, port);")

            # Default settings seed
            default_settings = [
                ('monitor_interval', str(Config.DEFAULT_MONITOR_INTERVAL)),
                ('ping_timeout', str(Config.DEFAULT_PING_TIMEOUT)),
                ('tcp_timeout', str(Config.DEFAULT_TCP_TIMEOUT)),
                ('ping_count', str(Config.DEFAULT_PING_COUNT))
            ]
            for key, val in default_settings:
                conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (key, val))
    finally:
        conn.close()

# ---------------------------------------------------------
# Device CRUD operations
# ---------------------------------------------------------

def get_all_devices(db_path=None):
    """
    Retrieves all devices along with their latest monitoring history details.
    """
    conn = get_db_connection(db_path)
    try:
        query = """
            SELECT 
                d.id,
                d.device_name,
                d.ip_address,
                d.port,
                d.description,
                d.created_at,
                d.updated_at,
                h.overall_status,
                h.reachability_status,
                h.service_status,
                h.response_time_ms,
                h.fault_details,
                h.checked_at AS last_checked
            FROM devices d
            LEFT JOIN (
                SELECT mh1.*
                FROM monitoring_history mh1
                INNER JOIN (
                    SELECT device_id, MAX(id) AS max_id
                    FROM monitoring_history
                    GROUP BY device_id
                ) mh2 ON mh1.id = mh2.max_id
            ) h ON d.id = h.device_id
            ORDER BY d.id ASC;
        """
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_device_by_id(device_id, db_path=None):
    """
    Fetches a single device by ID with its latest status.
    """
    conn = get_db_connection(db_path)
    try:
        query = """
            SELECT 
                d.id,
                d.device_name,
                d.ip_address,
                d.port,
                d.description,
                d.created_at,
                d.updated_at,
                h.overall_status,
                h.reachability_status,
                h.service_status,
                h.response_time_ms,
                h.fault_details,
                h.checked_at AS last_checked
            FROM devices d
            LEFT JOIN (
                SELECT mh1.*
                FROM monitoring_history mh1
                INNER JOIN (
                    SELECT device_id, MAX(id) AS max_id
                    FROM monitoring_history
                    WHERE device_id = ?
                ) mh2 ON mh1.id = mh2.max_id
            ) h ON d.id = h.device_id
            WHERE d.id = ?;
        """
        row = conn.execute(query, (device_id, device_id)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def check_duplicate_device(ip_address, port=None, exclude_id=None, db_path=None):
    """
    Checks if a device with the same IP and port already exists.
    """
    conn = get_db_connection(db_path)
    try:
        if port is None:
            if exclude_id:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port IS NULL AND id != ?;"
                row = conn.execute(query, (ip_address, exclude_id)).fetchone()
            else:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port IS NULL;"
                row = conn.execute(query, (ip_address,)).fetchone()
        else:
            if exclude_id:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port = ? AND id != ?;"
                row = conn.execute(query, (ip_address, port, exclude_id)).fetchone()
            else:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port = ?;"
                row = conn.execute(query, (ip_address, port)).fetchone()
        return row is not None
    finally:
        conn.close()

def create_device(device_name, ip_address, port=None, description=None, db_path=None):
    """
    Registers a new network device.
    """
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO devices (device_name, ip_address, port, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (device_name.strip(), ip_address.strip(), port, description.strip() if description else None, now, now)
            )
            return cursor.lastrowid
    finally:
        conn.close()

def update_device(device_id, device_name, ip_address, port=None, description=None, db_path=None):
    """
    Updates an existing device's configuration.
    """
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                UPDATE devices
                SET device_name = ?, ip_address = ?, port = ?, description = ?, updated_at = ?
                WHERE id = ?;
                """,
                (device_name.strip(), ip_address.strip(), port, description.strip() if description else None, now, device_id)
            )
            return cursor.rowcount > 0
    finally:
        conn.close()

def delete_device(device_id, db_path=None):
    """
    Deletes a device and cascades deletion to monitoring_history.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM devices WHERE id = ?;", (device_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# ---------------------------------------------------------
# Monitoring History operations
# ---------------------------------------------------------

def record_monitoring_result(device_id, reachability_status, service_status, overall_status, response_time_ms=None, fault_details=None, db_path=None):
    """
    Inserts a new monitoring check record for a device into monitoring_history.
    """
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO monitoring_history (
                    device_id, checked_at, reachability_status, service_status, 
                    overall_status, response_time_ms, fault_details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    device_id,
                    now,
                    reachability_status,
                    service_status,
                    overall_status,
                    round(response_time_ms, 2) if response_time_ms is not None else None,
                    fault_details
                )
            )
            return cursor.lastrowid
    finally:
        conn.close()

def get_device_history(device_id, limit=20, db_path=None):
    """
    Retrieves the most recent monitoring history records for a specific device.
    """
    conn = get_db_connection(db_path)
    try:
        query = """
            SELECT id, device_id, checked_at, reachability_status, service_status,
                   overall_status, response_time_ms, fault_details
            FROM monitoring_history
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT ?;
        """
        rows = conn.execute(query, (device_id, limit)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_all_history(device_id=None, status=None, page=1, per_page=20, db_path=None):
    """
    Fetches paginated monitoring history records with optional filters by device and status.
    """
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params = []

        if device_id:
            conditions.append("h.device_id = ?")
            params.append(device_id)

        if status and status.upper() != 'ALL':
            conditions.append("h.overall_status = ?")
            params.append(status.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        offset = (max(1, page) - 1) * per_page
        query = f"""
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
                h.fault_details
            FROM monitoring_history h
            JOIN devices d ON h.device_id = d.id
            {where_clause}
            ORDER BY h.id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([per_page, offset])
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_history_count(device_id=None, status=None, db_path=None):
    """
    Returns the total number of history records matching optional filters.
    """
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params = []

        if device_id:
            conditions.append("h.device_id = ?")
            params.append(device_id)

        if status and status.upper() != 'ALL':
            conditions.append("h.overall_status = ?")
            params.append(status.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
            SELECT COUNT(*) AS total
            FROM monitoring_history h
            JOIN devices d ON h.device_id = d.id
            {where_clause};
        """
        row = conn.execute(query, tuple(params)).fetchone()
        return row['total'] if row else 0
    finally:
        conn.close()

# ---------------------------------------------------------
# System Settings operations
# ---------------------------------------------------------

def get_settings(db_path=None):
    """
    Reads all settings key-value pairs from the database.
    """
    conn = get_db_connection(db_path)
    try:
        rows = conn.execute("SELECT key, value FROM settings;").fetchall()
        settings_dict = {row['key']: row['value'] for row in rows}
        return {
            'monitor_interval': int(settings_dict.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL)),
            'ping_timeout': int(settings_dict.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT)),
            'tcp_timeout': int(settings_dict.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT)),
            'ping_count': int(settings_dict.get('ping_count', Config.DEFAULT_PING_COUNT))
        }
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return {
            'monitor_interval': Config.DEFAULT_MONITOR_INTERVAL,
            'ping_timeout': Config.DEFAULT_PING_TIMEOUT,
            'tcp_timeout': Config.DEFAULT_TCP_TIMEOUT,
            'ping_count': Config.DEFAULT_PING_COUNT
        }
    finally:
        conn.close()

def update_settings(monitor_interval, ping_timeout, tcp_timeout, ping_count, db_path=None):
    """
    Updates the system monitoring parameters in the settings table.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('monitor_interval', ?);", (str(monitor_interval),))
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_timeout', ?);", (str(ping_timeout),))
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('tcp_timeout', ?);", (str(tcp_timeout),))
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_count', ?);", (str(ping_count),))
            return True
    finally:
        conn.close()

# ---------------------------------------------------------
# Dashboard Summary Statistics
# ---------------------------------------------------------

def get_dashboard_summary(db_path=None):
    """
    Calculates summary card numbers from the latest status of each device:
    - Total Devices
    - Devices UP
    - Devices DOWN
    - Devices with FAULT
    - Average Response Time (across valid numeric response times)
    """
    devices = get_all_devices(db_path)
    total_devices = len(devices)
    up_count = 0
    down_count = 0
    fault_count = 0
    pending_count = 0
    valid_response_times = []

    for d in devices:
        status = d.get('overall_status')
        if status == 'UP':
            up_count += 1
        elif status == 'DOWN':
            down_count += 1
        elif status == 'FAULT':
            fault_count += 1
        else:
            pending_count += 1

        r_time = d.get('response_time_ms')
        if r_time is not None and isinstance(r_time, (int, float)):
            valid_response_times.append(r_time)

    avg_response_time = (
        round(sum(valid_response_times) / len(valid_response_times), 2)
        if valid_response_times else None
    )

    return {
        'total_devices': total_devices,
        'up_count': up_count,
        'down_count': down_count,
        'fault_count': fault_count,
        'pending_count': pending_count,
        'avg_response_time_ms': avg_response_time
    }
