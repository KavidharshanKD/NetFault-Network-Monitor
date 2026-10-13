"""
Services Module for Automated Fault Detection System.
Provides helper services for CSV data export, system diagnostics, and chart analytics.
"""

import io
import csv
import sys
import platform
import sqlite3
import os
import importlib.metadata
from datetime import datetime
from config import Config
import database

def generate_history_csv(device_id=None, status=None, date_from=None, date_to=None):
    """
    Generates a secure, RFC 4180-compliant CSV string containing monitoring audit records.
    """
    records = database.get_all_history(
        device_id=device_id,
        status=status,
        date_from=date_from,
        date_to=date_to,
        page=1,
        per_page=10000
    )

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Record ID",
        "Timestamp",
        "Device Name",
        "IP Address",
        "Port",
        "Reachability Status",
        "Service Status",
        "Overall Status",
        "Response Time (ms)",
        "Fault Category",
        "Diagnostic Details"
    ])

    for r in records:
        writer.writerow([
            r['id'],
            r['checked_at'],
            r['device_name'],
            r['ip_address'],
            r['port'] if r['port'] is not None else "N/A",
            r['reachability_status'],
            r['service_status'],
            r['overall_status'],
            r['response_time_ms'] if r['response_time_ms'] is not None else "N/A",
            r['fault_category'] or "NONE",
            r['fault_details'] or ""
        ])

    return output.getvalue()

def generate_faults_csv(device_id=None, category=None, status=None):
    """
    Generates CSV string containing fault reports with failure counts and observations.
    """
    reports = database.get_fault_reports(device_id=device_id, category=category, status=status)

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Device ID",
        "Device Name",
        "IP Address",
        "Port",
        "Fault Category",
        "Overall Status",
        "Consecutive Failures",
        "Total Recorded Failures",
        "First Observed",
        "Last Observed",
        "Latest Response Time (ms)",
        "Diagnostic Details"
    ])

    for rep in reports:
        writer.writerow([
            rep['device_id'],
            rep['device_name'],
            rep['ip_address'],
            rep['port'] if rep['port'] is not None else "N/A",
            rep['fault_category'] or "NONE",
            rep['fault_status'],
            rep.get('consecutive_failures', 1),
            rep.get('total_failures', 1),
            rep.get('first_observed', ""),
            rep.get('last_observed', ""),
            rep['response_time_ms'] if rep['response_time_ms'] is not None else "N/A",
            rep['fault_details'] or ""
        ])

    return output.getvalue()

def get_system_diagnostics(scheduler_instance=None):
    """
    Retrieves real system operational diagnostics:
    - Application info & start time
    - Python runtime & platform details
    - SQLite database path, size, and table counts
    - Scheduler state and interval configuration
    """
    try:
        flask_ver = importlib.metadata.version("flask")
    except Exception:
        import flask
        flask_ver = getattr(flask, '__version__', '3.x')

    db_path = Config.DATABASE_PATH
    db_size_kb = 0.0
    if os.path.exists(db_path):
        db_size_kb = round(os.path.getsize(db_path) / 1024.0, 2)

    total_devices = database.get_devices_count()
    total_history = database.get_history_count()
    settings = database.get_settings()

    scheduler_running = scheduler_instance.is_running() if scheduler_instance else False
    last_cycle = scheduler_instance.get_last_cycle_time() if scheduler_instance else None

    start_time = getattr(Config, 'APP_START_TIME', datetime.now())
    uptime_delta = datetime.now() - start_time
    hours, remainder = divmod(int(uptime_delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_formatted = f"{hours}h {minutes}m {seconds}s"

    return {
        'app_name': Config.APP_NAME,
        'app_version': Config.APP_VERSION,
        'python_version': sys.version.split()[0],
        'flask_version': flask_ver,
        'sqlite_version': sqlite3.sqlite_version,
        'os_platform': f"{platform.system()} {platform.release()} ({platform.machine()})",
        'database_path': db_path,
        'database_size_kb': db_size_kb,
        'total_devices': total_devices,
        'total_history_records': total_history,
        'scheduler_running': scheduler_running,
        'scheduler_last_cycle': last_cycle or "No cycles completed yet",
        'configured_interval': settings.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL),
        'concurrency_limit': settings.get('concurrency_limit', Config.DEFAULT_CONCURRENCY_LIMIT),
        'auto_monitoring': bool(settings.get('auto_monitoring', 1)),
        'app_start_time': start_time.strftime("%Y-%m-%d %H:%M:%S"),
        'app_uptime': uptime_formatted
    }
