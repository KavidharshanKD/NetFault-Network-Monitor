"""
Database module for NetFault.
Manages SQLite operations, schema creation, device records, and monitoring history.
"""

import sqlite3
import os
from config import Config

def get_db_connection():
    """
    Creates and returns a new SQLite database connection.
    row_factory is set to sqlite3.Row for convenient dict-like column access.
    Foreign keys are explicitly enabled.
    """
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """
    Initializes database tables if they do not already exist.
    Creates devices and monitoring_results tables with appropriate indices.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table: devices
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            tcp_port INTEGER,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Table: monitoring_results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitoring_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            response_time REAL,
            fault_info TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)
    
    # Indices for performance
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_monitoring_device_id 
        ON monitoring_results(device_id)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_monitoring_checked_at 
        ON monitoring_results(checked_at DESC)
    """)
    
    conn.commit()
    conn.close()

def add_device(device_name, ip_address, tcp_port=None, description=""):
    """
    Inserts a new device into the devices table.
    Returns the newly created device id.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (device_name, ip_address, tcp_port, description)
        VALUES (?, ?, ?, ?)
    """, (device_name.strip(), ip_address.strip(), tcp_port, description.strip() if description else ""))
    device_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return device_id

def update_device(device_id, device_name, ip_address, tcp_port=None, description=""):
    """
    Updates an existing device by ID.
    Returns True if updated, False otherwise.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE devices
        SET device_name = ?, ip_address = ?, tcp_port = ?, description = ?
        WHERE id = ?
    """, (device_name.strip(), ip_address.strip(), tcp_port, description.strip() if description else "", device_id))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0

def delete_device(device_id):
    """
    Deletes a device and cascades to delete all its monitoring results.
    Returns True if deleted, False otherwise.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0

def get_all_devices():
    """
    Returns all registered devices as a list of dictionaries.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_device_by_id(device_id):
    """
    Returns a single device by ID as a dictionary, or None if not found.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def save_monitoring_result(device_id, status, response_time, fault_info):
    """
    Records a monitoring probe result in monitoring_results table.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO monitoring_results (device_id, status, response_time, fault_info, checked_at)
        VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
    """, (device_id, status, response_time, fault_info))
    result_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return result_id

def get_all_devices_with_latest_status():
    """
    Retrieves all devices joined with their latest monitoring status.
    Uses a subquery to fetch the latest monitoring result per device.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
        SELECT 
            d.id,
            d.device_name,
            d.ip_address,
            d.tcp_port,
            d.description,
            d.created_at,
            m.status,
            m.response_time,
            m.fault_info,
            m.checked_at AS last_checked
        FROM devices d
        LEFT JOIN monitoring_results m ON m.id = (
            SELECT id FROM monitoring_results 
            WHERE device_id = d.id 
            ORDER BY checked_at DESC, id DESC 
            LIMIT 1
        )
        ORDER BY d.id ASC
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_stats():
    """
    Calculates summary counts for Total, UP, DOWN, FAULT, and PENDING devices.
    PENDING represents devices that have not yet been checked.
    """
    devices_with_status = get_all_devices_with_latest_status()
    total = len(devices_with_status)
    up_count = sum(1 for d in devices_with_status if d.get('status') == 'UP')
    down_count = sum(1 for d in devices_with_status if d.get('status') == 'DOWN')
    fault_count = sum(1 for d in devices_with_status if d.get('status') == 'FAULT')
    pending_count = sum(1 for d in devices_with_status if d.get('status') is None)
    
    return {
        "total_devices": total,
        "up_devices": up_count,
        "down_devices": down_count,
        "fault_devices": fault_count,
        "pending_devices": pending_count
    }

def get_monitoring_history(device_id=None, status=None, limit=100):
    """
    Retrieves history logs with device names.
    Supports optional filtering by device_id and status.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    conditions = []
    params = []
    
    if device_id:
        conditions.append("m.device_id = ?")
        params.append(device_id)
        
    if status and status.upper() in ['UP', 'DOWN', 'FAULT']:
        conditions.append("m.status = ?")
        params.append(status.upper())
        
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    
    query = f"""
        SELECT 
            m.id,
            m.device_id,
            d.device_name,
            d.ip_address,
            d.tcp_port,
            m.status,
            m.response_time,
            m.fault_info,
            m.checked_at
        FROM monitoring_results m
        JOIN devices d ON m.device_id = d.id
        {where_clause}
        ORDER BY m.checked_at DESC, m.id DESC
        LIMIT ?
    """
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_monitoring_history(device_id=None):
    """
    Clears monitoring records. If device_id is provided, only deletes for that device.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if device_id:
        cursor.execute("DELETE FROM monitoring_results WHERE device_id = ?", (device_id,))
    else:
        cursor.execute("DELETE FROM monitoring_results")
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected
