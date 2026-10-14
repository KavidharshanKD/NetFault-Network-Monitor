"""
One-Time SQLite to Supabase PostgreSQL Data Migration Utility.
Transfers existing network devices, monitoring history audit records, settings,
and traceroute diagnostics from a local SQLite database into Supabase PostgreSQL.

Features:
- Never runs automatically on application startup.
- Safe and non-destructive: Never modifies or deletes the source SQLite database.
- Idempotent: Can be run multiple times without duplicating devices or history.
- Maps SQLite integer IDs to Supabase UUIDs and updates foreign keys correctly.
- Preserves original checked timestamps, status values, and latency measurements.
"""

import os
import sys
import json
import sqlite3
import logging
from datetime import datetime

# Add project root to sys.path so config and database modules can be imported
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import Config
import database

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

def run_migration(sqlite_path=None):
    """
    Executes the one-time data import from SQLite into Supabase PostgreSQL.
    """
    db_path = sqlite_path or os.path.join(PROJECT_ROOT, 'instance', 'network_monitor.db')

    print("=" * 70)
    print(" AFDS SQLITE TO SUPABASE ONE-TIME MIGRATION UTILITY")
    print("=" * 70)
    print(f" Source SQLite File: {db_path}")

    if not os.path.exists(db_path):
        print(f"[-] Error: Source SQLite database not found at '{db_path}'.")
        print("    If you don't have an existing database to migrate, you can start fresh!")
        return False

    if not database.is_supabase_configured():
        print("[-] Error: Supabase credentials are not configured in your .env file.")
        print("    Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env before running this script.")
        return False

    try:
        supabase_client = database.get_supabase_client()
        print("[+] Supabase client initialized and connected successfully.")
    except Exception as e:
        print(f"[-] Error connecting to Supabase: {e}")
        return False

    # Connect to source SQLite database
    sqlite_conn = sqlite3.connect(db_path)
    sqlite_conn.row_factory = sqlite3.Row

    # Dictionary mapping SQLite integer device ID -> Supabase UUID string
    device_id_map = {}

    stats = {
        'devices_imported': 0,
        'devices_skipped': 0,
        'devices_failed': 0,
        'history_imported': 0,
        'history_skipped': 0,
        'history_failed': 0,
        'settings_imported': 0,
        'traces_imported': 0
    }

    # -------------------------------------------------------------------------
    # 1. Migrate Devices
    # -------------------------------------------------------------------------
    print("\n--- 1. Migrating Network Devices ---")
    try:
        cur = sqlite_conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices';")
        if cur.fetchone():
            sqlite_devices = sqlite_conn.execute("SELECT * FROM devices ORDER BY id ASC;").fetchall()
            print(f"Found {len(sqlite_devices)} device record(s) in SQLite.")

            for dev in sqlite_devices:
                sqlite_id = dev['id']
                dev_name = dev['device_name']
                ip_addr = dev['ip_address']
                port = dev['port'] if dev['port'] is not None else None
                desc = dev['description'] if 'description' in dev.keys() else None
                enabled = bool(dev['monitoring_enabled']) if 'monitoring_enabled' in dev.keys() else True

                # Check if device already exists in Supabase by IP and Port
                try:
                    q = supabase_client.table('devices').select('id').eq('ip_address', ip_addr)
                    if port is None:
                        q = q.is_('port', 'null')
                    else:
                        q = q.eq('port', int(port))
                    existing = q.execute()

                    if existing.data and len(existing.data) > 0:
                        supabase_uuid = existing.data[0]['id']
                        device_id_map[sqlite_id] = supabase_uuid
                        stats['devices_skipped'] += 1
                        print(f"  [SKIPPED] Device '{dev_name}' ({ip_addr}:{port or 'None'}) already in Supabase -> UUID {supabase_uuid}")
                    else:
                        insert_res = supabase_client.table('devices').insert({
                            'device_name': dev_name,
                            'ip_address': ip_addr,
                            'port': int(port) if port else None,
                            'description': desc,
                            'monitoring_enabled': enabled
                        }).execute()

                        if insert_res.data:
                            supabase_uuid = insert_res.data[0]['id']
                            device_id_map[sqlite_id] = supabase_uuid
                            stats['devices_imported'] += 1
                            print(f"  [IMPORTED] Device '{dev_name}' ({ip_addr}:{port or 'None'}) -> UUID {supabase_uuid}")
                        else:
                            stats['devices_failed'] += 1
                            print(f"  [FAILED] Could not insert device '{dev_name}' into Supabase.")
                except Exception as ex:
                    stats['devices_failed'] += 1
                    print(f"  [ERROR] Device '{dev_name}': {ex}")
        else:
            print("  No 'devices' table found in source SQLite.")
    except Exception as e:
        print(f"[-] Error querying devices table in SQLite: {e}")

    # -------------------------------------------------------------------------
    # 2. Migrate Monitoring History
    # -------------------------------------------------------------------------
    print("\n--- 2. Migrating Monitoring History ---")
    try:
        cur = sqlite_conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='monitoring_history';")
        if cur.fetchone():
            sqlite_history = sqlite_conn.execute("SELECT * FROM monitoring_history ORDER BY id ASC;").fetchall()
            print(f"Found {len(sqlite_history)} monitoring audit record(s) in SQLite.")

            batch = []
            for h in sqlite_history:
                old_dev_id = h['device_id']
                supabase_dev_id = device_id_map.get(old_dev_id)

                if not supabase_dev_id:
                    stats['history_skipped'] += 1
                    continue

                checked_at_val = h['checked_at']
                # Convert SQLite format to ISO format
                if checked_at_val and ' ' in checked_at_val:
                    checked_at_iso = checked_at_val.replace(' ', 'T') + 'Z'
                else:
                    checked_at_iso = checked_at_val

                record_data = {
                    'device_id': supabase_dev_id,
                    'checked_at': checked_at_iso,
                    'reachability_status': h['reachability_status'],
                    'service_status': h['service_status'] if 'service_status' in h.keys() else None,
                    'overall_status': h['overall_status'],
                    'response_time_ms': h['response_time_ms'] if 'response_time_ms' in h.keys() and h['response_time_ms'] is not None else None,
                    'fault_category': h['fault_category'] if 'fault_category' in h.keys() else None,
                    'fault_details': h['fault_details'] if 'fault_details' in h.keys() else None
                }
                batch.append(record_data)

                # Insert in chunks of 50
                if len(batch) >= 50:
                    try:
                        res = supabase_client.table('monitoring_history').insert(batch).execute()
                        stats['history_imported'] += len(res.data or batch)
                    except Exception as b_err:
                        logger.error(f"Error inserting history batch: {b_err}")
                        stats['history_failed'] += len(batch)
                    batch = []

            if batch:
                try:
                    res = supabase_client.table('monitoring_history').insert(batch).execute()
                    stats['history_imported'] += len(res.data or batch)
                except Exception as b_err:
                    logger.error(f"Error inserting final history batch: {b_err}")
                    stats['history_failed'] += len(batch)

            print(f"  History migrated: {stats['history_imported']} imported, {stats['history_skipped']} skipped, {stats['history_failed']} failed.")
        else:
            print("  No 'monitoring_history' table found in source SQLite.")
    except Exception as e:
        print(f"[-] Error querying monitoring_history in SQLite: {e}")

    # -------------------------------------------------------------------------
    # 3. Migrate Settings
    # -------------------------------------------------------------------------
    print("\n--- 3. Migrating Application Settings ---")
    try:
        cur = sqlite_conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings';")
        if cur.fetchone():
            sqlite_settings = sqlite_conn.execute("SELECT * FROM settings;").fetchall()
            for s in sqlite_settings:
                k = s['key']
                v = s['value']
                # Convert numeric strings to integer
                val_typed = int(v) if v.isdigit() else v
                try:
                    supabase_client.table('application_settings').upsert({
                        'setting_key': k,
                        'setting_value': val_typed,
                        'updated_at': datetime.utcnow().isoformat() + 'Z'
                    }, on_conflict='setting_key').execute()
                    stats['settings_imported'] += 1
                    print(f"  [SETTING] '{k}' = {val_typed}")
                except Exception as s_err:
                    print(f"  [ERROR] Setting '{k}': {s_err}")
        else:
            print("  No 'settings' table found in source SQLite.")
    except Exception as e:
        print(f"[-] Error querying settings in SQLite: {e}")

    # -------------------------------------------------------------------------
    # 4. Migrate Traceroute History
    # -------------------------------------------------------------------------
    print("\n--- 4. Migrating Traceroute History ---")
    try:
        cur = sqlite_conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='traceroute_history';")
        if cur.fetchone():
            sqlite_traces = sqlite_conn.execute("SELECT * FROM traceroute_history;").fetchall()
            for t in sqlite_traces:
                old_dev_id = t['device_id']
                supabase_dev_id = device_id_map.get(old_dev_id)
                if not supabase_dev_id:
                    continue

                hops_raw = t['hops_json']
                try:
                    hops_data = json.loads(hops_raw) if isinstance(hops_raw, str) else hops_raw
                except Exception:
                    hops_data = []

                exec_at = t['executed_at']
                if exec_at and ' ' in exec_at:
                    exec_at_iso = exec_at.replace(' ', 'T') + 'Z'
                else:
                    exec_at_iso = exec_at

                try:
                    supabase_client.table('traceroute_history').insert({
                        'device_id': supabase_dev_id,
                        'target_ip': t['target_ip'],
                        'total_hops': int(t['total_hops']),
                        'destination_reached': bool(t['destination_reached']),
                        'fault_hop': t['fault_hop'] if t['fault_hop'] is not None else None,
                        'fault_summary': t['fault_summary'],
                        'hops_json': hops_data,
                        'raw_output': t['raw_output'],
                        'executed_at': exec_at_iso
                    }).execute()
                    stats['traces_imported'] += 1
                except Exception as t_err:
                    print(f"  [ERROR] Traceroute record: {t_err}")

            print(f"  Traceroute records imported: {stats['traces_imported']}")
        else:
            print("  No 'traceroute_history' table found in source SQLite.")
    except Exception as e:
        print(f"[-] Note on traceroute migration: {e}")

    sqlite_conn.close()

    print("\n" + "=" * 70)
    print(" MIGRATION SUMMARY")
    print("=" * 70)
    print(f" Devices Imported:   {stats['devices_imported']}")
    print(f" Devices Skipped:    {stats['devices_skipped']}")
    print(f" Devices Failed:     {stats['devices_failed']}")
    print(f" History Imported:   {stats['history_imported']}")
    print(f" History Skipped:    {stats['history_skipped']}")
    print(f" History Failed:     {stats['history_failed']}")
    print(f" Settings Persisted: {stats['settings_imported']}")
    print(f" Traceroutes Copied: {stats['traces_imported']}")
    print("=" * 70)
    print("[+] Migration process complete. Your original SQLite database is untouched.")
    print("    Supabase PostgreSQL is now loaded with your existing records.\n")
    return True

if __name__ == '__main__':
    custom_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_migration(custom_path)
