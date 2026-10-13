"""
Database management module for Automated Fault Detection System.
Handles SQLite schema creation, migrations, device CRUD with search/filter/pagination,
monitoring history records, fault reporting analytics, and system settings.
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
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path=None):
    """
    Initializes database tables, indexes, schema migrations, and default settings.
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
                    monitoring_enabled INTEGER DEFAULT 1,
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
                    fault_category TEXT,
                    fault_details TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)

            # System settings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Traceroute hop-by-hop history table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traceroute_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    target_ip TEXT NOT NULL,
                    total_hops INTEGER NOT NULL DEFAULT 0,
                    destination_reached INTEGER NOT NULL DEFAULT 0,
                    fault_hop INTEGER,
                    fault_summary TEXT,
                    hops_json TEXT NOT NULL,
                    raw_output TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Schema Migration Checks
            # Check devices columns
            dev_columns = [row['name'] for row in conn.execute("PRAGMA table_info(devices);").fetchall()]
            if 'monitoring_enabled' not in dev_columns:
                conn.execute("ALTER TABLE devices ADD COLUMN monitoring_enabled INTEGER DEFAULT 1;")

            # Check monitoring_history columns
            hist_columns = [row['name'] for row in conn.execute("PRAGMA table_info(monitoring_history);").fetchall()]
            if 'fault_category' not in hist_columns:
                conn.execute("ALTER TABLE monitoring_history ADD COLUMN fault_category TEXT;")

            # Performance Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_device ON monitoring_history(device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_checked ON monitoring_history(checked_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_status ON monitoring_history(overall_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_category ON monitoring_history(fault_category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip_port ON devices(ip_address, port);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traceroute_device ON traceroute_history(device_id, executed_at DESC);")

            # Default settings seed
            default_settings = [
                ('monitor_interval', str(Config.DEFAULT_MONITOR_INTERVAL)),
                ('ping_timeout', str(Config.DEFAULT_PING_TIMEOUT)),
                ('tcp_timeout', str(Config.DEFAULT_TCP_TIMEOUT)),
                ('ping_count', str(Config.DEFAULT_PING_COUNT)),
                ('concurrency_limit', str(Config.DEFAULT_CONCURRENCY_LIMIT)),
                ('auto_monitoring', str(Config.DEFAULT_AUTO_MONITOR))
            ]
            for key, val in default_settings:
                conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (key, val))
    finally:
        conn.close()

# ---------------------------------------------------------
# Device CRUD operations
# ---------------------------------------------------------

def get_all_devices(search=None, status_filter=None, sort_by=None, sort_dir='asc', page=None, per_page=None, db_path=None):
    """
    Retrieves devices with their latest monitoring history details.
    Supports search (name/IP), status filtering, safe sorting, and pagination.
    """
    conn = get_db_connection(db_path)
    try:
        where_clauses = []
        params = []

        if search:
            s_clean = f"%{search.strip()}%"
            where_clauses.append("(d.device_name LIKE ? OR d.ip_address LIKE ?)")
            params.extend([s_clean, s_clean])

        if status_filter and status_filter.upper() != 'ALL':
            sf = status_filter.upper()
            if sf in ('UNKNOWN', 'UNCHECKED'):
                where_clauses.append("(h.overall_status IS NULL OR h.overall_status = 'UNKNOWN')")
            else:
                where_clauses.append("h.overall_status = ?")
                params.append(sf)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Safe sorting map
        sort_map = {
            'name': 'd.device_name',
            'ip': 'd.ip_address',
            'port': 'd.port',
            'status': 'h.overall_status',
            'last_checked': 'h.checked_at',
            'id': 'd.id'
        }
        order_col = sort_map.get((sort_by or '').lower(), 'd.id')
        order_direction = 'DESC' if (sort_dir or '').lower() == 'desc' else 'ASC'

        pagination_sql = ""
        if page is not None and per_page is not None:
            offset = (max(1, int(page)) - 1) * int(per_page)
            pagination_sql = f"LIMIT {int(per_page)} OFFSET {offset}"

        query = f"""
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
            LEFT JOIN (
                SELECT mh1.*
                FROM monitoring_history mh1
                INNER JOIN (
                    SELECT device_id, MAX(id) AS max_id
                    FROM monitoring_history
                    GROUP BY device_id
                ) mh2 ON mh1.id = mh2.max_id
            ) h ON d.id = h.device_id
            {where_sql}
            ORDER BY {order_col} {order_direction}
            {pagination_sql};
        """
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_devices_count(search=None, status_filter=None, db_path=None):
    """Returns total device count matching optional search and status filter."""
    conn = get_db_connection(db_path)
    try:
        where_clauses = []
        params = []

        if search:
            s_clean = f"%{search.strip()}%"
            where_clauses.append("(d.device_name LIKE ? OR d.ip_address LIKE ?)")
            params.extend([s_clean, s_clean])

        if status_filter and status_filter.upper() != 'ALL':
            sf = status_filter.upper()
            if sf in ('UNKNOWN', 'UNCHECKED'):
                where_clauses.append("(h.overall_status IS NULL OR h.overall_status = 'UNKNOWN')")
            else:
                where_clauses.append("h.overall_status = ?")
                params.append(sf)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        query = f"""
            SELECT COUNT(d.id) AS total
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
            {where_sql};
        """
        row = conn.execute(query, tuple(params)).fetchone()
        return row['total'] if row else 0
    finally:
        conn.close()

def get_device_by_id(device_id, db_path=None):
    """Fetches a single device by ID along with its latest monitoring status."""
    conn = get_db_connection(db_path)
    try:
        query = """
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
    """Checks whether a device with the identical IP and port already exists."""
    conn = get_db_connection(db_path)
    try:
        ip_clean = ip_address.strip()
        if port is None:
            if exclude_id:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port IS NULL AND id != ?;"
                row = conn.execute(query, (ip_clean, exclude_id)).fetchone()
            else:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port IS NULL;"
                row = conn.execute(query, (ip_clean,)).fetchone()
        else:
            if exclude_id:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port = ? AND id != ?;"
                row = conn.execute(query, (ip_clean, int(port), exclude_id)).fetchone()
            else:
                query = "SELECT id FROM devices WHERE ip_address = ? AND port = ?;"
                row = conn.execute(query, (ip_clean, int(port))).fetchone()
        return row is not None
    finally:
        conn.close()

def create_device(device_name, ip_address, port=None, description=None, monitoring_enabled=1, db_path=None):
    """Registers a new network device."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO devices (device_name, ip_address, port, description, monitoring_enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    device_name.strip(),
                    ip_address.strip(),
                    int(port) if port else None,
                    description.strip() if description else None,
                    1 if monitoring_enabled else 0,
                    now,
                    now
                )
            )
            return cursor.lastrowid
    finally:
        conn.close()

def update_device(device_id, device_name, ip_address, port=None, description=None, monitoring_enabled=1, db_path=None):
    """Updates an existing device configuration."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                UPDATE devices
                SET device_name = ?, ip_address = ?, port = ?, description = ?, monitoring_enabled = ?, updated_at = ?
                WHERE id = ?;
                """,
                (
                    device_name.strip(),
                    ip_address.strip(),
                    int(port) if port else None,
                    description.strip() if description else None,
                    1 if monitoring_enabled else 0,
                    now,
                    device_id
                )
            )
            return cursor.rowcount > 0
    finally:
        conn.close()

def toggle_device_monitoring(device_id, db_path=None):
    """Toggles monitoring_enabled between 1 and 0 for a device."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.execute(
                """
                UPDATE devices
                SET monitoring_enabled = CASE WHEN monitoring_enabled = 1 THEN 0 ELSE 1 END,
                    updated_at = ?
                WHERE id = ?;
                """,
                (now, device_id)
            )
            row = conn.execute("SELECT monitoring_enabled FROM devices WHERE id = ?;", (device_id,)).fetchone()
            return row['monitoring_enabled'] if row else None
    finally:
        conn.close()

def delete_device(device_id, db_path=None):
    """Deletes a device and cascades deletion to monitoring_history."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM devices WHERE id = ?;", (device_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# ---------------------------------------------------------
# Monitoring History Operations
# ---------------------------------------------------------

def record_monitoring_result(device_id, reachability_status, service_status, overall_status,
                             response_time_ms=None, fault_category=None, fault_details=None, db_path=None):
    """Inserts a new monitoring check record for a device."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO monitoring_history (
                    device_id, checked_at, reachability_status, service_status, 
                    overall_status, response_time_ms, fault_category, fault_details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    device_id,
                    now,
                    reachability_status,
                    service_status,
                    overall_status,
                    round(response_time_ms, 2) if response_time_ms is not None else None,
                    fault_category,
                    fault_details
                )
            )
            return cursor.lastrowid
    finally:
        conn.close()

def get_device_history(device_id, limit=25, db_path=None):
    """Retrieves the most recent monitoring history records for a specific device."""
    conn = get_db_connection(db_path)
    try:
        query = """
            SELECT id, device_id, checked_at, reachability_status, service_status,
                   overall_status, response_time_ms, fault_category, fault_details
            FROM monitoring_history
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT ?;
        """
        rows = conn.execute(query, (device_id, limit)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_all_history(device_id=None, status=None, date_from=None, date_to=None, page=1, per_page=20, db_path=None):
    """Fetches paginated monitoring history records with optional filters."""
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params = []

        if device_id:
            conditions.append("h.device_id = ?")
            params.append(int(device_id))

        if status and status.upper() != 'ALL':
            conditions.append("h.overall_status = ?")
            params.append(status.upper())

        if date_from:
            conditions.append("h.checked_at >= ?")
            params.append(f"{date_from} 00:00:00")

        if date_to:
            conditions.append("h.checked_at <= ?")
            params.append(f"{date_to} 23:59:59")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        offset = (max(1, int(page)) - 1) * int(per_page)
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
                h.fault_category,
                h.fault_details
            FROM monitoring_history h
            JOIN devices d ON h.device_id = d.id
            {where_clause}
            ORDER BY h.id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([int(per_page), offset])
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_history_count(device_id=None, status=None, date_from=None, date_to=None, db_path=None):
    """Returns the total number of history records matching optional filters."""
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params = []

        if device_id:
            conditions.append("h.device_id = ?")
            params.append(int(device_id))

        if status and status.upper() != 'ALL':
            conditions.append("h.overall_status = ?")
            params.append(status.upper())

        if date_from:
            conditions.append("h.checked_at >= ?")
            params.append(f"{date_from} 00:00:00")

        if date_to:
            conditions.append("h.checked_at <= ?")
            params.append(f"{date_to} 23:59:59")

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

def get_recent_faults(limit=5, db_path=None):
    """Retrieves recent fault occurrences (overall_status in FAULT, DOWN)."""
    conn = get_db_connection(db_path)
    try:
        query = """
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
            JOIN devices d ON h.device_id = d.id
            WHERE h.overall_status IN ('FAULT', 'DOWN')
            ORDER BY h.id DESC
            LIMIT ?;
        """
        rows = conn.execute(query, (limit,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_recent_checks(limit=6, db_path=None):
    """Retrieves recent monitoring checks across all devices."""
    conn = get_db_connection(db_path)
    try:
        query = """
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
            JOIN devices d ON h.device_id = d.id
            ORDER BY h.id DESC
            LIMIT ?;
        """
        rows = conn.execute(query, (limit,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

# ---------------------------------------------------------
# Fault Reports & Analytics
# ---------------------------------------------------------

def get_fault_reports(device_id=None, category=None, status=None, db_path=None):
    """
    Computes fault summaries across devices:
    - Device name and IP
    - Fault category
    - Fault description
    - First observed time
    - Last observed time
    - Consecutive failed checks
    - Current device status
    - Latest response time
    """
    conn = get_db_connection(db_path)
    try:
        conditions = ["h.overall_status IN ('FAULT', 'DOWN')"]
        params = []

        if device_id:
            conditions.append("h.device_id = ?")
            params.append(int(device_id))

        if category and category.upper() != 'ALL':
            conditions.append("h.fault_category = ?")
            params.append(category.upper())

        if status and status.upper() != 'ALL':
            conditions.append("h.overall_status = ?")
            params.append(status.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}"

        query = f"""
            SELECT 
                d.id AS device_id,
                d.device_name,
                d.ip_address,
                d.port,
                h.fault_category,
                h.fault_details,
                h.overall_status AS fault_status,
                h.checked_at AS last_observed,
                h.response_time_ms,
                (
                    SELECT MIN(h_sub.checked_at) 
                    FROM monitoring_history h_sub 
                    WHERE h_sub.device_id = d.id AND h_sub.overall_status = h.overall_status
                ) AS first_observed,
                (
                    SELECT COUNT(*)
                    FROM monitoring_history h_cnt
                    WHERE h_cnt.device_id = d.id AND h_cnt.overall_status IN ('FAULT', 'DOWN')
                ) AS total_failures
            FROM monitoring_history h
            JOIN devices d ON h.device_id = d.id
            INNER JOIN (
                SELECT device_id, MAX(id) AS max_id
                FROM monitoring_history
                WHERE overall_status IN ('FAULT', 'DOWN')
                GROUP BY device_id
            ) latest_fault ON h.id = latest_fault.max_id
            {where_clause}
            ORDER BY h.id DESC;
        """
        rows = conn.execute(query, tuple(params)).fetchall()
        reports = []
        for r in rows:
            rep = dict(r)
            # Calculate consecutive failed checks from recent history
            dev_hists = conn.execute(
                "SELECT overall_status FROM monitoring_history WHERE device_id = ? ORDER BY id DESC LIMIT 10;",
                (rep['device_id'],)
            ).fetchall()
            consecutive = 0
            for dh in dev_hists:
                if dh['overall_status'] in ('FAULT', 'DOWN'):
                    consecutive += 1
                else:
                    break
            rep['consecutive_failures'] = max(1, consecutive)
            reports.append(rep)
        return reports
    finally:
        conn.close()

def get_history_timeseries(device_id=None, limit=20, db_path=None):
    """
    Retrieves chronological data points for Chart.js:
    - Labels (checked timestamps)
    - Response times (numeric only, excluding failures)
    - Status distribution breakdown
    """
    conn = get_db_connection(db_path)
    try:
        if device_id:
            query = """
                SELECT checked_at, response_time_ms, overall_status
                FROM monitoring_history
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?;
            """
            rows = conn.execute(query, (device_id, limit)).fetchall()
        else:
            query = """
                SELECT checked_at, response_time_ms, overall_status
                FROM monitoring_history
                ORDER BY id DESC
                LIMIT ?;
            """
            rows = conn.execute(query, (limit,)).fetchall()

        # Reverse so they appear chronologically (oldest to newest)
        rows = list(reversed(rows))
        labels = [r['checked_at'].split()[-1] if ' ' in r['checked_at'] else r['checked_at'] for r in rows]
        response_times = [r['response_time_ms'] for r in rows]
        statuses = [r['overall_status'] for r in rows]

        return {
            'labels': labels,
            'response_times': response_times,
            'statuses': statuses,
            'count': len(rows)
        }
    finally:
        conn.close()

# ---------------------------------------------------------
# System Settings operations
# ---------------------------------------------------------

def get_settings(db_path=None):
    """Reads all configuration settings from the database with defaults."""
    conn = get_db_connection(db_path)
    try:
        rows = conn.execute("SELECT key, value FROM settings;").fetchall()
        s_map = {row['key']: row['value'] for row in rows}
        return {
            'monitor_interval': int(s_map.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL)),
            'ping_timeout': int(s_map.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT)),
            'tcp_timeout': int(s_map.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT)),
            'ping_count': int(s_map.get('ping_count', Config.DEFAULT_PING_COUNT)),
            'concurrency_limit': int(s_map.get('concurrency_limit', Config.DEFAULT_CONCURRENCY_LIMIT)),
            'auto_monitoring': int(s_map.get('auto_monitoring', Config.DEFAULT_AUTO_MONITOR))
        }
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return {
            'monitor_interval': Config.DEFAULT_MONITOR_INTERVAL,
            'ping_timeout': Config.DEFAULT_PING_TIMEOUT,
            'tcp_timeout': Config.DEFAULT_TCP_TIMEOUT,
            'ping_count': Config.DEFAULT_PING_COUNT,
            'concurrency_limit': Config.DEFAULT_CONCURRENCY_LIMIT,
            'auto_monitoring': Config.DEFAULT_AUTO_MONITOR
        }
    finally:
        conn.close()

def update_settings(monitor_interval, ping_timeout, tcp_timeout, ping_count, concurrency_limit=None, auto_monitoring=None, db_path=None):
    """Updates system monitoring parameters in the settings table."""
    conn = get_db_connection(db_path)
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('monitor_interval', ?, ?);", (str(monitor_interval), now))
            conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('ping_timeout', ?, ?);", (str(ping_timeout), now))
            conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('tcp_timeout', ?, ?);", (str(tcp_timeout), now))
            conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('ping_count', ?, ?);", (str(ping_count), now))
            if concurrency_limit is not None:
                conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('concurrency_limit', ?, ?);", (str(concurrency_limit), now))
            if auto_monitoring is not None:
                conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('auto_monitoring', ?, ?);", (str(auto_monitoring), now))
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
    - Average Response Time (excluding failed/null measurements)
    """
    devices = get_all_devices(db_path=db_path)
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

# ---------------------------------------------------------
# Traceroute Hop-by-Hop Persistence
# ---------------------------------------------------------

def save_traceroute(device_id, target_ip, total_hops, destination_reached, fault_hop, fault_summary, hops_json, raw_output, db_path=None):
    """
    Persists a hop-by-hop traceroute execution result into traceroute_history.
    Returns the newly inserted record ID.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO traceroute_history 
            (device_id, target_ip, total_hops, destination_reached, fault_hop, fault_summary, hops_json, raw_output)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            device_id, target_ip, total_hops,
            1 if destination_reached else 0,
            fault_hop, fault_summary, hops_json, raw_output
        ))
        trace_id = cur.lastrowid
        conn.commit()
        return trace_id
    finally:
        conn.close()

def get_device_traceroutes(device_id, limit=5, db_path=None):
    """
    Retrieves the most recent traceroute execution records for a device.
    """
    conn = get_db_connection(db_path)
    try:
        rows = conn.execute("""
            SELECT * FROM traceroute_history
            WHERE device_id = ?
            ORDER BY executed_at DESC, id DESC
            LIMIT ?;
        """, (device_id, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_traceroute_by_id(trace_id, db_path=None):
    """
    Retrieves a single traceroute record by ID.
    """
    conn = get_db_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM traceroute_history WHERE id = ?;", (trace_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

