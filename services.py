"""
Services Module for Automated Fault Detection System (AFDS).
Provides helper services for CSV data export, system diagnostics, and Supabase analytics.
"""

import io
import csv
import sys
import platform
import os
import importlib.metadata
from datetime import datetime
from config import Config
import database

def generate_history_csv_from_records(records):
    """Generates RFC 4180-compliant CSV string from a list of history records."""
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
        "Packet Loss (%)",
        "Packets Sent",
        "Packets Received",
        "Packets Lost",
        "Response Time (ms)",
        "Fault Category",
        "Diagnostic Details"
    ])

    for r in records:
        writer.writerow([
            r.get('id', ''),
            r.get('checked_at', ''),
            r.get('device_name', ''),
            r.get('ip_address', ''),
            r.get('port') if r.get('port') is not None else "N/A",
            r.get('reachability_status', ''),
            r.get('service_status', ''),
            r.get('overall_status', ''),
            f"{r.get('packet_loss_pct'):.2f}%" if r.get('packet_loss_pct') is not None else "N/A",
            r.get('packets_sent') if r.get('packets_sent') is not None else "N/A",
            r.get('packets_received') if r.get('packets_received') is not None else "N/A",
            r.get('packets_lost') if r.get('packets_lost') is not None else "N/A",
            r.get('response_time_ms') if r.get('response_time_ms') is not None else "N/A",
            r.get('fault_category') or "NONE",
            r.get('fault_details') or ""
        ])

    return output.getvalue()

def generate_history_csv(device_id=None, status=None, date_from=None, date_to=None, user_id=None):
    """
    Generates a secure, RFC 4180-compliant CSV string containing monitoring audit records from Supabase.
    """
    records = database.get_all_history(
        device_id=device_id,
        status=status,
        date_from=date_from,
        date_to=date_to,
        page=1,
        per_page=10000,
        user_id=user_id
    )
    return generate_history_csv_from_records(records)

def generate_faults_csv_from_reports(reports):
    """Generates CSV string from a list of fault report summaries."""
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
            rep.get('device_id', ''),
            rep.get('device_name', ''),
            rep.get('ip_address', ''),
            rep.get('port') if rep.get('port') is not None else "N/A",
            rep.get('fault_category') or "NONE",
            rep.get('fault_status', ''),
            rep.get('consecutive_failures', 1),
            rep.get('total_failures', 1),
            rep.get('first_observed', ""),
            rep.get('last_observed', ""),
            rep.get('response_time_ms') if rep.get('response_time_ms') is not None else "N/A",
            rep.get('fault_details') or ""
        ])

    return output.getvalue()

def generate_faults_csv(device_id=None, category=None, status=None, user_id=None):
    """
    Generates CSV string containing fault reports with failure counts and observations from Supabase.
    """
    reports = database.get_fault_reports(device_id=device_id, category=category, status=status, user_id=user_id)
    return generate_faults_csv_from_reports(reports)

def get_system_diagnostics(scheduler_instance=None):
    """
    Retrieves real system operational diagnostics:
    - Application info & start time
    - Python runtime & platform details
    - Supabase PostgreSQL connection status and masked endpoint
    - Total devices and audit records in Supabase
    - Scheduler state and interval configuration
    """
    try:
        flask_ver = importlib.metadata.version("flask")
    except Exception:
        import flask
        flask_ver = getattr(flask, '__version__', '3.x')

    # Supabase connection status check
    supabase_configured = database.is_supabase_configured()
    raw_url = getattr(Config, 'SUPABASE_URL', '') or ''
    if raw_url and '://' in raw_url:
        parts = raw_url.split('://', 1)
        host = parts[1].split('/')[0]
        if len(host) > 12:
            masked_host = host[:6] + '****' + host[-10:]
        else:
            masked_host = '****'
        masked_url = f"{parts[0]}://{masked_host}"
    else:
        masked_url = "Not configured in .env"

    database_status = "Connected (Ready)" if supabase_configured else "Action Required (Set .env credentials)"

    try:
        total_devices = database.get_devices_count()
        total_history = database.get_history_count()
        settings = database.get_settings()
    except Exception as e:
        total_devices = 0
        total_history = 0
        settings = {}
        database_status = f"Connection error: {str(e)[:60]}"

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
        'database_type': "Supabase PostgreSQL",
        'database_status': database_status,
        'supabase_url': masked_url,
        'supabase_configured': supabase_configured,
        'os_platform': f"{platform.system()} {platform.release()} ({platform.machine()})",
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
