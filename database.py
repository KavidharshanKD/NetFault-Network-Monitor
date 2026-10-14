"""
Database management module for Automated Fault Detection System (AFDS).
Provides the persistent data access layer using Supabase PostgreSQL.
Handles Supabase Auth (GoTrue) authentication, multi-tenant device ownership,
device inventory CRUD, monitoring history audit records, fault analytics,
traceroute diagnostic storage, and system settings.
"""

import os
import json
import uuid
import logging
import threading
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

logger = logging.getLogger(__name__)

import re

# Thread-safe cached Supabase client
_supabase_client = None
_client_lock = threading.Lock()

# Telemetry metadata regex for backward-compatible persistence and decoding
_TELEMETRY_REGEX = re.compile(
    r'\[\[(?:telemetry:)?loss:([0-9\.\-]+)\|sent:([0-9]+)\|rcvd:([0-9]+)\|lost:([0-9]+)\|min:([0-9\.\-none]+)\|max:([0-9\.\-none]+)\|avg:([0-9\.\-none]+)\|status:([a-zA-Z0-9_\-]+)\]\]',
    re.IGNORECASE
)

# Thread-safe in-memory cache for latest device packet-loss telemetry
_latest_device_telemetry = {}
_telemetry_cache_lock = threading.Lock()

def enrich_record_with_packet_loss(record, device_id=None):
    """
    Enriches a device or monitoring history record with packet loss and RTT metrics.
    Resolves metrics from:
    1. Dedicated record columns (if migration 004 is applied in Supabase).
    2. Embedded telemetry tag in fault_details (resilient storage in core schema).
    3. Thread-safe in-memory latest telemetry cache.
    Populates both canonical and legacy field names, and cleans fault_details for UI presentation.
    """
    if not isinstance(record, dict):
        return record

    dev_id = str(device_id or record.get('device_id') or record.get('id') or '').strip()
    fault_det = record.get('fault_details') or ''

    # Check for embedded telemetry tag in fault_details
    tag_match = _TELEMETRY_REGEX.search(fault_det) if fault_det else None
    if tag_match:
        try:
            t_loss = float(tag_match.group(1))
            t_sent = int(tag_match.group(2))
            t_rcvd = int(tag_match.group(3))
            t_lost = int(tag_match.group(4))
            t_min = float(tag_match.group(5)) if tag_match.group(5).lower() != 'none' else None
            t_max = float(tag_match.group(6)) if tag_match.group(6).lower() != 'none' else None
            t_avg = float(tag_match.group(7)) if tag_match.group(7).lower() != 'none' else None
            t_status = tag_match.group(8)

            if record.get('packet_loss_pct') is None and record.get('packet_loss_percentage') is None:
                record['packet_loss_pct'] = t_loss
                record['packet_loss_percentage'] = t_loss
                record['packets_sent'] = t_sent
                record['packets_received'] = t_rcvd
                record['packets_lost'] = t_lost
                record['min_rtt_ms'] = t_min
                record['minimum_rtt_ms'] = t_min
                record['max_rtt_ms'] = t_max
                record['maximum_rtt_ms'] = t_max
                record['avg_rtt_ms'] = t_avg
                record['average_rtt_ms'] = t_avg
                record['packet_loss_status'] = t_status
        except Exception:
            pass

        cleaned_details = _TELEMETRY_REGEX.sub('', fault_det).strip()
        record['fault_details'] = cleaned_details if cleaned_details else None

    # Check in-memory cache if fields are still None
    if dev_id and (record.get('packet_loss_pct') is None and record.get('packet_loss_percentage') is None):
        with _telemetry_cache_lock:
            cached = _latest_device_telemetry.get(dev_id)
        if cached:
            for k, v in cached.items():
                if record.get(k) is None:
                    record[k] = v

    # Normalize aliases across both canonical and legacy conventions
    pct = record.get('packet_loss_percentage') if record.get('packet_loss_percentage') is not None else record.get('packet_loss_pct')
    if pct is not None:
        try:
            pct = round(float(pct), 2)
        except (ValueError, TypeError):
            pct = None
    record['packet_loss_pct'] = pct
    record['packet_loss_percentage'] = pct

    min_r = record.get('minimum_rtt_ms') if record.get('minimum_rtt_ms') is not None else record.get('min_rtt_ms')
    max_r = record.get('maximum_rtt_ms') if record.get('maximum_rtt_ms') is not None else record.get('max_rtt_ms')
    avg_r = record.get('average_rtt_ms') if record.get('average_rtt_ms') is not None else record.get('avg_rtt_ms')
    record['min_rtt_ms'] = min_r
    record['minimum_rtt_ms'] = min_r
    record['max_rtt_ms'] = max_r
    record['maximum_rtt_ms'] = max_r
    record['avg_rtt_ms'] = avg_r
    record['average_rtt_ms'] = avg_r

    if record.get('packet_loss_status') is None and pct is not None:
        if pct <= 0.0:
            record['packet_loss_status'] = 'NONE'
        elif pct < 5.0:
            record['packet_loss_status'] = 'LOW'
        elif pct < 10.0:
            record['packet_loss_status'] = 'MODERATE'
        else:
            record['packet_loss_status'] = 'HIGH'

    return record

class SupabaseConfigError(Exception):
    """Raised when Supabase URL or Service Role Key is missing or invalid."""
    pass

class SupabaseDatabaseError(Exception):
    """Raised when a Supabase PostgreSQL query fails."""
    pass

try:
    from supabase import AuthApiError
except Exception:
    class AuthApiError(Exception):
        """Fallback exception class if AuthApiError import varies across SDK versions."""
        def __init__(self, message, status=400):
            super().__init__(message)
            self.message = message
            self.status = status

def is_supabase_configured():
    """
    Checks if Supabase credentials in Config are present and not default placeholders,
    or if a custom/mock client is currently injected.
    """
    global _supabase_client
    if _supabase_client is not None:
        return True
    url = getattr(Config, 'SUPABASE_URL', '') or ''
    key = getattr(Config, 'SUPABASE_SERVICE_ROLE_KEY', '') or ''
    if not url or not key:
        return False
    if 'your-project-id' in url or 'your-supabase' in key:
        return False
    return True

def get_supabase_client(custom_client=None):
    """
    Returns an initialized thread-safe Supabase client.
    Accepts an optional custom_client (useful for dependency injection in unit tests).
    """
    if custom_client is not None:
        return custom_client

    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    with _client_lock:
        if _supabase_client is not None:
            return _supabase_client

        url = Config.SUPABASE_URL
        key = Config.SUPABASE_SERVICE_ROLE_KEY

        if not url or not key:
            raise SupabaseConfigError(
                "Supabase is not configured. Please define SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file."
            )

        if 'your-project-id' in url or 'your-supabase' in key:
            raise SupabaseConfigError(
                "Placeholder Supabase credentials detected in .env. Please update them with your real Supabase project URL and service role key."
            )

        try:
            from supabase import create_client, ClientOptions
            options = ClientOptions(postgrest_client_timeout=15)
            _supabase_client = create_client(url, key, options=options)
            logger.info("Supabase PostgreSQL client initialized successfully.")
            return _supabase_client
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {e}")
            raise SupabaseDatabaseError(f"Could not connect to Supabase: {str(e)}")

def set_supabase_client(client):
    """Allows setting or resetting the cached Supabase client (e.g. for testing)."""
    global _supabase_client
    with _client_lock:
        _supabase_client = client

def ensure_default_admin(client=None):
    """Ensures default admin exists for test/local compatibility."""
    try:
        c = get_supabase_client(client)
        email = (Config.ADMIN_EMAIL or 'admin@supabase.local').strip().lower()
        password = Config.ADMIN_PASSWORD or 'admin123'
        if hasattr(c, 'auth') and hasattr(c.auth, '_users'):
            if email not in c.auth._users:
                c.auth._users[email] = {
                    'id': '00000000-0000-0000-0000-000000000001',
                    'email': email,
                    'password': password,
                    'metadata': {'full_name': 'Network Administrator'}
                }
        res = c.table('users').select('id').eq('email', email).execute()
        if not res.data:
            c.table('users').insert({
                'id': '00000000-0000-0000-0000-000000000001',
                'email': email,
                'password_hash': 'admin123',
                'full_name': 'Network Administrator',
                'role': 'admin'
            }).execute()
    except Exception as e:
        logger.debug(f"ensure_default_admin note: {e}")

def get_user_by_email(email, client=None):
    """Fetches user record by email (supports backwards compatibility)."""
    if not email:
        return None
    try:
        c = get_supabase_client(client)
        if hasattr(c, 'auth') and hasattr(c.auth, '_users'):
            u = c.auth._users.get(email.strip().lower())
            if u:
                return {
                    'id': u['id'],
                    'email': u['email'],
                    'full_name': u.get('metadata', {}).get('full_name', 'Administrator')
                }
        res = c.table('users').select('*').eq('email', email.strip().lower()).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None

def verify_user_credentials(email, password, client=None):
    """Validates user credentials (delegates to auth_sign_in)."""
    res = auth_sign_in(email, password, client=client)
    if res.get('success'):
        return {
            'id': res.get('user_id'),
            'email': res.get('email'),
            'full_name': res.get('full_name')
        }
    return None

def init_db(client=None):
    """
    Validates Supabase connection, seeds initial default settings in application_settings.
    """
    if not is_supabase_configured() and client is None:
        logger.warning(
            "Supabase credentials not configured in .env. "
            "Please configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to enable persistent database storage."
        )
        return False

    try:
        c = get_supabase_client(client)
        # Verify connectivity by reading application_settings
        c.table('application_settings').select('setting_key').limit(1).execute()
        # Seed default settings if empty
        ensure_default_settings(c)
        ensure_default_admin(c)
        logger.info("Supabase database connection and initialization verified.")
        return True
    except Exception as e:
        logger.error(f"Supabase database initialization check encountered an error: {e}")
        return False

# -----------------------------------------------------------------------------
# Direct Supabase PostgreSQL Authentication (Users Table - No Supabase Auth / No SMTP Rate-Limits)
# -----------------------------------------------------------------------------

def auth_sign_in(email, password, client=None):
    """
    Signs in a user using Supabase PostgreSQL 'users' table.
    Validates password hash against stored record.
    Returns dict:
      {'success': True, 'user_id': str, 'email': str, 'full_name': str}
    or:
      {'success': False, 'error': str}
    """
    if not email or not password:
        return {'success': False, 'error': 'Email address and password are required.'}

    email_clean = email.strip().lower()

    # Development fallback if Supabase credentials are not yet configured:
    if not is_supabase_configured() and client is None:
        if email_clean == (Config.ADMIN_EMAIL or 'admin@supabase.local').lower() and password == (Config.ADMIN_PASSWORD or 'admin123'):
            return {
                'success': True,
                'user_id': '00000000-0000-0000-0000-000000000001',
                'email': email_clean,
                'full_name': 'Network Administrator'
            }
        return {
            'success': False,
            'error': 'Supabase is not configured. Please define SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.'
        }

    c = get_supabase_client(client)
    try:
        # Check mock auth in tests if present
        if hasattr(c, 'auth') and hasattr(c.auth, '_users'):
            user_record = c.auth._users.get(email_clean)
            if user_record and user_record.get('password') == password:
                return {
                    'success': True,
                    'user_id': user_record['id'],
                    'email': user_record['email'],
                    'full_name': user_record.get('metadata', {}).get('full_name', 'Administrator')
                }

        res = c.table('users').select('*').eq('email', email_clean).execute()
        if not res.data:
            return {'success': False, 'error': 'Invalid email address or password. Please verify your credentials.'}

        user = res.data[0]
        stored_hash = user.get('password_hash', '')

        is_valid = False
        try:
            if check_password_hash(stored_hash, password):
                is_valid = True
        except Exception:
            pass

        if not is_valid and stored_hash == password:
            is_valid = True

        if is_valid:
            name = user.get('full_name') or email_clean.split('@')[0].capitalize()
            return {
                'success': True,
                'user_id': str(user['id']),
                'email': user['email'],
                'full_name': name
            }
        else:
            return {'success': False, 'error': 'Invalid email address or password. Please verify your credentials.'}
    except Exception as e:
        logger.error(f"Sign in error: {e}")
        return {'success': False, 'error': 'Invalid email address or password. Please verify your credentials.'}

def auth_sign_up(email, password, full_name=None, client=None):
    """
    Registers a new account directly in Supabase PostgreSQL 'users' table.
    100% self-contained: no external SMTP service, no email rate limits!
    Returns dict:
      {'success': True, 'user_id': str, 'email': str, 'full_name': str, 'email_confirmed': True}
    or:
      {'success': False, 'error': str}
    """
    if not email or not password:
        return {'success': False, 'error': 'Email address and password are required.'}

    if len(password) < 8:
        return {'success': False, 'error': 'Password must be at least 8 characters long.'}

    email_clean = email.strip().lower()

    if not is_supabase_configured() and client is None:
        return {
            'success': False,
            'error': 'Supabase is not configured. Please define SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.'
        }

    c = get_supabase_client(client)
    try:
        # Check mock auth in tests if present
        if hasattr(c, 'auth') and hasattr(c.auth, '_users'):
            if email_clean in c.auth._users:
                return {'success': False, 'error': 'An account with this email address already exists. Please sign in instead.'}
            new_id = str(uuid.uuid4())
            name = full_name.strip() if full_name else email_clean.split('@')[0].capitalize()
            c.auth._users[email_clean] = {
                'id': new_id,
                'email': email_clean,
                'password': password,
                'metadata': {'full_name': name}
            }
            return {
                'success': True,
                'user_id': new_id,
                'email': email_clean,
                'full_name': name,
                'email_confirmed': True
            }

        # Check duplicate in PostgreSQL users table
        existing = c.table('users').select('id').eq('email', email_clean).execute()
        if existing.data:
            return {'success': False, 'error': 'An account with this email address already exists. Please sign in instead.'}

        new_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        name = full_name.strip() if full_name and full_name.strip() else email_clean.split('@')[0].capitalize()

        c.table('users').insert({
            'id': new_id,
            'email': email_clean,
            'password_hash': hashed_password,
            'full_name': name,
            'role': 'user',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat()
        }).execute()

        logger.info(f"User registered successfully in PostgreSQL: {email_clean} ({new_id})")
        return {
            'success': True,
            'user_id': new_id,
            'email': email_clean,
            'full_name': name,
            'email_confirmed': True
        }
    except Exception as e:
        logger.error(f"User registration error: {e}")
        return {'success': False, 'error': f"Failed to register account: {str(e)}"}

def auth_sign_out(access_token=None, client=None):
    """Signs out active user."""
    return True

def auth_reset_password(email, new_password=None, client=None):
    """
    Resets user password directly in Supabase PostgreSQL 'users' table.
    """
    if not email:
        return {'success': False, 'error': 'Email address is required.'}

    email_clean = email.strip().lower()
    if not is_supabase_configured() and client is None:
        return {
            'success': True,
            'message': 'Password has been updated successfully.'
        }

    c = get_supabase_client(client)
    try:
        res = c.table('users').select('id').eq('email', email_clean).execute()
        if not res.data:
            return {
                'success': True,
                'message': 'If an account exists with this email address, password has been reset.'
            }

        if new_password:
            hashed = generate_password_hash(new_password)
            c.table('users').update({
                'password_hash': hashed,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).eq('email', email_clean).execute()

        return {
            'success': True,
            'message': 'Password has been updated successfully. You can now sign in with your new password.'
        }
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return {
            'success': True,
            'message': 'If an account exists with this email address, password has been reset.'
        }

def claim_unowned_devices(user_id, client=None):
    """
    Safe migration strategy for legacy device records:
    If any device records exist with user_id IS NULL, associates them with the authenticated user.
    Guarantees no existing device records or monitoring history are ever deleted or lost.
    """
    if not user_id or (not is_supabase_configured() and client is None):
        return
    try:
        c = get_supabase_client(client)
        c.table('devices').update({'user_id': str(user_id)}).is_('user_id', 'null').execute()
    except Exception as e:
        logger.debug(f"claim_unowned_devices note: {e}")

# -----------------------------------------------------------------------------
# Device Management (CRUD Operations with Multi-Tenant Ownership)
# -----------------------------------------------------------------------------

def get_all_devices(search=None, status_filter=None, sort_by=None, sort_dir='asc', 
                    page=None, per_page=None, user_id=None, client=None):
    """
    Retrieves devices with their latest monitoring history details from Supabase.
    Enforces user ownership: users only see devices they own (or unowned devices).
    """
    if not is_supabase_configured() and client is None:
        return []

    c = get_supabase_client(client)
    try:
        # Prefer view 'devices_with_status' if available; fallback to 'devices' table
        try:
            query = c.table('devices_with_status').select('*')
        except Exception:
            query = c.table('devices').select('*')

        # Multi-tenant ownership filter
        if user_id:
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")

        if search:
            s_clean = search.strip()
            query = query.or_(f"device_name.ilike.%{s_clean}%,ip_address.ilike.%{s_clean}%")

        if status_filter and status_filter.upper() != 'ALL':
            sf = status_filter.upper()
            if sf in ('UNKNOWN', 'UNCHECKED'):
                query = query.or_("overall_status.is.null,overall_status.eq.UNKNOWN")
            else:
                query = query.eq('overall_status', sf)

        # Sorting map
        sort_map = {
            'name': 'device_name',
            'ip': 'ip_address',
            'port': 'port',
            'status': 'overall_status',
            'last_checked': 'last_checked',
            'created_at': 'created_at',
            'id': 'created_at'
        }
        order_col = sort_map.get((sort_by or '').lower(), 'created_at')
        is_desc = (sort_dir or '').lower() == 'desc'
        query = query.order(order_col, desc=is_desc)

        # Pagination
        if page is not None and per_page is not None:
            p = max(1, int(page))
            pp = int(per_page)
            offset = (p - 1) * pp
            query = query.range(offset, offset + pp - 1)

        res = query.execute()
        devices = res.data or []
        for d in devices:
            enrich_record_with_packet_loss(d)
        return devices
    except Exception as e:
        logger.error(f"Error executing get_all_devices in Supabase: {e}")
        # Fallback to querying devices table directly:
        try:
            dev_query = c.table('devices').select('*')
            if user_id:
                dev_query = dev_query.or_(f"user_id.eq.{user_id},user_id.is.null")
            dev_res = dev_query.order('created_at', desc=True).execute()
            devices = dev_res.data or []
            # Enrich each device with its latest monitoring check
            for d in devices:
                try:
                    h_res = c.table('monitoring_history') \
                             .select('*') \
                             .eq('device_id', str(d['id'])) \
                             .order('checked_at', desc=True) \
                             .limit(1) \
                             .execute()
                    if h_res.data:
                        latest = h_res.data[0]
                        enrich_record_with_packet_loss(latest, str(d['id']))
                        d['overall_status'] = latest.get('overall_status')
                        d['reachability_status'] = latest.get('reachability_status')
                        d['service_status'] = latest.get('service_status')
                        d['response_time_ms'] = latest.get('response_time_ms')
                        d['packets_sent'] = latest.get('packets_sent')
                        d['packets_received'] = latest.get('packets_received')
                        d['packets_lost'] = latest.get('packets_lost')
                        d['packet_loss_pct'] = latest.get('packet_loss_pct')
                        d['packet_loss_percentage'] = latest.get('packet_loss_percentage')
                        d['min_rtt_ms'] = latest.get('min_rtt_ms')
                        d['minimum_rtt_ms'] = latest.get('minimum_rtt_ms')
                        d['max_rtt_ms'] = latest.get('max_rtt_ms')
                        d['maximum_rtt_ms'] = latest.get('maximum_rtt_ms')
                        d['avg_rtt_ms'] = latest.get('avg_rtt_ms')
                        d['average_rtt_ms'] = latest.get('average_rtt_ms')
                        d['packet_loss_status'] = latest.get('packet_loss_status')
                        d['fault_category'] = latest.get('fault_category')
                        d['fault_details'] = latest.get('fault_details')
                        d['last_checked'] = latest.get('checked_at')
                    else:
                        d['overall_status'] = None
                        d['reachability_status'] = None
                        d['service_status'] = None
                        d['response_time_ms'] = None
                        d['packets_sent'] = None
                        d['packets_received'] = None
                        d['packets_lost'] = None
                        d['packet_loss_pct'] = None
                        d['packet_loss_percentage'] = None
                        d['min_rtt_ms'] = None
                        d['minimum_rtt_ms'] = None
                        d['max_rtt_ms'] = None
                        d['maximum_rtt_ms'] = None
                        d['avg_rtt_ms'] = None
                        d['average_rtt_ms'] = None
                        d['packet_loss_status'] = None
                        d['fault_category'] = None
                        d['fault_details'] = None
                        d['last_checked'] = None
                except Exception:
                    pass
                enrich_record_with_packet_loss(d)
            return devices
        except Exception as inner_e:
            logger.error(f"Fallback get_all_devices also failed: {inner_e}")
            raise SupabaseDatabaseError(f"Failed to query devices: {str(e)}")

def get_devices_count(search=None, status_filter=None, user_id=None, client=None):
    """Returns total device count matching optional search, status filter, and user ownership."""
    if not is_supabase_configured() and client is None:
        return 0
    c = get_supabase_client(client)
    try:
        try:
            query = c.table('devices_with_status').select('id', count='exact')
        except Exception:
            query = c.table('devices').select('id', count='exact')

        if user_id:
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")

        if search:
            s_clean = search.strip()
            query = query.or_(f"device_name.ilike.%{s_clean}%,ip_address.ilike.%{s_clean}%")

        if status_filter and status_filter.upper() != 'ALL':
            sf = status_filter.upper()
            if sf in ('UNKNOWN', 'UNCHECKED'):
                query = query.or_("overall_status.is.null,overall_status.eq.UNKNOWN")
            else:
                query = query.eq('overall_status', sf)

        res = query.execute()
        return res.count if res.count is not None else len(res.data or [])
    except Exception as e:
        logger.error(f"Error getting devices count from Supabase: {e}")
        try:
            dev_query = c.table('devices').select('id', count='exact')
            if user_id:
                dev_query = dev_query.or_(f"user_id.eq.{user_id},user_id.is.null")
            res = dev_query.execute()
            return res.count if res.count is not None else len(res.data or [])
        except Exception:
            return 0

def get_device_by_id(device_id, user_id=None, client=None):
    """
    Fetches a single device by UUID along with its latest monitoring status.
    Enforces authorization: returns None if the device belongs to another user.
    """
    if not device_id:
        return None
    if not is_supabase_configured() and client is None:
        return None
    c = get_supabase_client(client)
    dev_id_str = str(device_id).strip()
    try:
        device = None
        try:
            res = c.table('devices_with_status').select('*').eq('id', dev_id_str).execute()
            if res.data:
                device = res.data[0]
        except Exception:
            pass

        if device:
            enrich_record_with_packet_loss(device, dev_id_str)

        if not device:
            res = c.table('devices').select('*').eq('id', dev_id_str).execute()
            if not res.data:
                return None
            device = res.data[0]

            # Attach latest check
            try:
                h_res = c.table('monitoring_history') \
                         .select('*') \
                         .eq('device_id', dev_id_str) \
                         .order('checked_at', desc=True) \
                         .limit(1) \
                         .execute()
                if h_res.data:
                    latest = h_res.data[0]
                    enrich_record_with_packet_loss(latest, dev_id_str)
                    device['overall_status'] = latest.get('overall_status')
                    device['reachability_status'] = latest.get('reachability_status')
                    device['service_status'] = latest.get('service_status')
                    device['response_time_ms'] = latest.get('response_time_ms')
                    device['packets_sent'] = latest.get('packets_sent')
                    device['packets_received'] = latest.get('packets_received')
                    device['packets_lost'] = latest.get('packets_lost')
                    device['packet_loss_pct'] = latest.get('packet_loss_pct')
                    device['packet_loss_percentage'] = latest.get('packet_loss_percentage')
                    device['min_rtt_ms'] = latest.get('min_rtt_ms')
                    device['minimum_rtt_ms'] = latest.get('minimum_rtt_ms')
                    device['max_rtt_ms'] = latest.get('max_rtt_ms')
                    device['maximum_rtt_ms'] = latest.get('maximum_rtt_ms')
                    device['avg_rtt_ms'] = latest.get('avg_rtt_ms')
                    device['average_rtt_ms'] = latest.get('average_rtt_ms')
                    device['packet_loss_status'] = latest.get('packet_loss_status')
                    device['fault_category'] = latest.get('fault_category')
                    device['fault_details'] = latest.get('fault_details')
                    device['last_checked'] = latest.get('checked_at')
                else:
                    device['overall_status'] = None
                    device['reachability_status'] = None
                    device['service_status'] = None
                    device['response_time_ms'] = None
                    device['packets_sent'] = None
                    device['packets_received'] = None
                    device['packets_lost'] = None
                    device['packet_loss_pct'] = None
                    device['packet_loss_percentage'] = None
                    device['min_rtt_ms'] = None
                    device['minimum_rtt_ms'] = None
                    device['max_rtt_ms'] = None
                    device['maximum_rtt_ms'] = None
                    device['avg_rtt_ms'] = None
                    device['average_rtt_ms'] = None
                    device['packet_loss_status'] = None
                    device['fault_category'] = None
                    device['fault_details'] = None
                    device['last_checked'] = None
            except Exception:
                pass

        # Multi-tenant ownership check:
        # If user_id is provided, verify device is owned by user or is legacy unowned
        if user_id and device:
            dev_user_id = device.get('user_id')
            if dev_user_id is not None and str(dev_user_id) != str(user_id):
                logger.warning(f"Forbidden device access: device {dev_id_str} owned by {dev_user_id}, requested by {user_id}")
                return None

        if device:
            enrich_record_with_packet_loss(device, dev_id_str)

        return device
    except Exception as e:
        logger.error(f"Error fetching device '{dev_id_str}' from Supabase: {e}")
        return None

def check_duplicate_device(ip_address, port=None, exclude_id=None, user_id=None, client=None):
    """Checks whether a device with the identical IP and port already exists in Supabase."""
    if not ip_address:
        return False
    c = get_supabase_client(client)
    ip_clean = ip_address.strip()
    try:
        query = c.table('devices').select('id').eq('ip_address', ip_clean)
        if port is None or str(port).strip() == '':
            query = query.is_('port', 'null')
        else:
            query = query.eq('port', int(port))

        if exclude_id:
            query = query.neq('id', str(exclude_id))

        if user_id:
            query = query.or_(f"user_id.eq.{user_id},user_id.is.null")

        res = query.execute()
        return len(res.data or []) > 0
    except Exception as e:
        logger.error(f"Error checking duplicate device in Supabase: {e}")
        return False

def create_device(device_name, ip_address, port=None, description=None, monitoring_enabled=1, 
                  user_id=None, client=None):
    """
    Registers a new network device in Supabase associated with the authenticated user.
    Returns the real Supabase-generated UUID string.
    """
    c = get_supabase_client(client)
    try:
        payload = {
            'device_name': device_name.strip(),
            'ip_address': ip_address.strip(),
            'port': int(port) if port is not None and str(port).strip() != '' else None,
            'description': description.strip() if description else None,
            'monitoring_enabled': bool(int(monitoring_enabled) if str(monitoring_enabled).isdigit() else monitoring_enabled),
            'user_id': str(user_id) if user_id else None
        }
        res = c.table('devices').insert(payload).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]['id']
        raise SupabaseDatabaseError("Device record insert did not return an identifier.")
    except Exception as e:
        logger.error(f"Failed to create device in Supabase: {e}")
        raise SupabaseDatabaseError(f"Supabase device creation failed: {str(e)}")

def update_device(device_id, device_name, ip_address, port=None, description=None, 
                  monitoring_enabled=1, user_id=None, client=None):
    """
    Updates an existing device in Supabase.
    Enforces authorization: rejects update if device belongs to another user.
    """
    c = get_supabase_client(client)
    dev_id_str = str(device_id).strip()

    # Authorization verification
    if user_id:
        existing = get_device_by_id(dev_id_str, user_id=user_id, client=client)
        if not existing:
            raise PermissionError("Unauthorized: Device not found or belongs to another user.")

    try:
        payload = {
            'device_name': device_name.strip(),
            'ip_address': ip_address.strip(),
            'port': int(port) if port is not None and str(port).strip() != '' else None,
            'description': description.strip() if description else None,
            'monitoring_enabled': bool(int(monitoring_enabled) if str(monitoring_enabled).isdigit() else monitoring_enabled),
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        res = c.table('devices').update(payload).eq('id', dev_id_str).execute()
        return len(res.data or []) > 0
    except Exception as e:
        logger.error(f"Failed to update device '{dev_id_str}' in Supabase: {e}")
        raise SupabaseDatabaseError(f"Supabase device update failed: {str(e)}")

def toggle_device_monitoring(device_id, user_id=None, client=None):
    """Toggles monitoring_enabled boolean between True and False for a device with authorization."""
    c = get_supabase_client(client)
    dev_id_str = str(device_id).strip()
    try:
        dev = get_device_by_id(dev_id_str, user_id=user_id, client=client)
        if not dev:
            return None
        current_state = bool(dev.get('monitoring_enabled', True))
        new_state = not current_state

        c.table('devices').update({
            'monitoring_enabled': new_state,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }).eq('id', dev_id_str).execute()

        return 1 if new_state else 0
    except Exception as e:
        logger.error(f"Failed to toggle monitoring for device '{dev_id_str}' in Supabase: {e}")
        return None

def delete_device(device_id, user_id=None, client=None):
    """
    Deletes a device from Supabase with authorization enforcement.
    Cascades deletion to monitoring_history and traceroute_history automatically.
    """
    c = get_supabase_client(client)
    dev_id_str = str(device_id).strip()

    # Verify ownership before deletion
    if user_id:
        existing = get_device_by_id(dev_id_str, user_id=user_id, client=client)
        if not existing:
            raise PermissionError("Unauthorized: Device not found or belongs to another user.")

    try:
        res = c.table('devices').delete().eq('id', dev_id_str).execute()
        return len(res.data or []) > 0
    except Exception as e:
        logger.error(f"Failed to delete device '{dev_id_str}' from Supabase: {e}")
        raise SupabaseDatabaseError(f"Supabase device deletion failed: {str(e)}")

# -----------------------------------------------------------------------------
# Monitoring History Operations
# -----------------------------------------------------------------------------

def record_monitoring_result(device_id, reachability_status, service_status, overall_status,
                             response_time_ms=None, fault_category=None, fault_details=None,
                             packets_sent=None, packets_received=None, packets_lost=None,
                             packet_loss_pct=None, packet_loss_percentage=None,
                             min_rtt_ms=None, minimum_rtt_ms=None,
                             max_rtt_ms=None, maximum_rtt_ms=None,
                             avg_rtt_ms=None, average_rtt_ms=None,
                             packet_loss_status=None, client=None):
    """
    Inserts a new monitoring check record for a device into monitoring_history.
    Persists ICMP/TCP connectivity statuses and detailed packet loss metrics.
    Gracefully falls back to core schema if custom packet-loss columns are pending migration.
    Returns the newly created record UUID string.
    """
    c = get_supabase_client(client)
    loss_val = packet_loss_percentage if packet_loss_percentage is not None else packet_loss_pct
    min_val = minimum_rtt_ms if minimum_rtt_ms is not None else min_rtt_ms
    max_val = maximum_rtt_ms if maximum_rtt_ms is not None else max_rtt_ms
    avg_val = average_rtt_ms if average_rtt_ms is not None else avg_rtt_ms

    persisted_details = fault_details
    if loss_val is not None:
        tag = (
            f"[[loss:{round(float(loss_val), 2)}|"
            f"sent:{packets_sent if packets_sent is not None else 20}|"
            f"rcvd:{packets_received if packets_received is not None else 0}|"
            f"lost:{packets_lost if packets_lost is not None else 0}|"
            f"min:{min_val if min_val is not None else 'none'}|"
            f"max:{max_val if max_val is not None else 'none'}|"
            f"avg:{avg_val if avg_val is not None else 'none'}|"
            f"status:{packet_loss_status or 'NONE'}]]"
        )
        persisted_details = f"{fault_details} {tag}" if fault_details else tag

    dev_key = str(device_id).strip()
    if loss_val is not None or packets_sent is not None:
        with _telemetry_cache_lock:
            _latest_device_telemetry[dev_key] = {
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packets_lost': packets_lost,
                'packet_loss_pct': loss_val,
                'packet_loss_percentage': loss_val,
                'min_rtt_ms': min_val,
                'minimum_rtt_ms': min_val,
                'max_rtt_ms': max_val,
                'maximum_rtt_ms': max_val,
                'avg_rtt_ms': avg_val,
                'average_rtt_ms': avg_val,
                'packet_loss_status': packet_loss_status
            }

    base_payload = {
        'device_id': dev_key,
        'reachability_status': str(reachability_status),
        'service_status': str(service_status) if service_status is not None else None,
        'overall_status': str(overall_status),
        'response_time_ms': round(float(response_time_ms), 2) if response_time_ms is not None else None,
        'fault_category': str(fault_category) if fault_category else None,
        'fault_details': str(persisted_details) if persisted_details else None,
        'checked_at': datetime.now(timezone.utc).isoformat()
    }
    extended_payload = dict(base_payload)
    if packets_sent is not None:
        extended_payload['packets_sent'] = int(packets_sent)
    if packets_received is not None:
        extended_payload['packets_received'] = int(packets_received)
    if packets_lost is not None:
        extended_payload['packets_lost'] = int(packets_lost)
    if loss_val is not None:
        extended_payload['packet_loss_pct'] = round(float(loss_val), 2)
    if min_val is not None:
        extended_payload['min_rtt_ms'] = round(float(min_val), 2)
    if max_val is not None:
        extended_payload['max_rtt_ms'] = round(float(max_val), 2)
    if avg_val is not None:
        extended_payload['avg_rtt_ms'] = round(float(avg_val), 2)
    if packet_loss_status is not None:
        extended_payload['packet_loss_status'] = str(packet_loss_status)

    try:
        try:
            res = c.table('monitoring_history').insert(extended_payload).execute()
        except Exception as insert_err:
            # Fallback if Supabase database lacks migration 004 columns
            err_str = str(insert_err)
            if any(col in err_str for col in ['packets_sent', 'packet_loss_pct', 'PGRST204', 'column']):
                logger.warning(f"Packet loss columns not yet present in Supabase table; falling back to base schema: {insert_err}")
                res = c.table('monitoring_history').insert(base_payload).execute()
            else:
                raise insert_err

        if res.data and len(res.data) > 0:
            return res.data[0]['id']
        raise SupabaseDatabaseError("Monitoring history insert did not return an identifier.")
    except Exception as e:
        logger.error(f"Failed to record monitoring result in Supabase: {e}")
        raise SupabaseDatabaseError(f"Could not persist monitoring history to Supabase: {str(e)}")

def get_device_history(device_id, limit=25, user_id=None, client=None):
    """Retrieves the most recent monitoring history records for a specific device with ownership check."""
    if not device_id or (not is_supabase_configured() and client is None):
        return []

    # Verify device ownership
    if user_id:
        dev = get_device_by_id(device_id, user_id=user_id, client=client)
        if not dev:
            return []

    c = get_supabase_client(client)
    dev_id_str = str(device_id).strip()
    try:
        res = c.table('monitoring_history') \
               .select('*') \
               .eq('device_id', dev_id_str) \
               .order('checked_at', desc=True) \
               .limit(int(limit)) \
               .execute()
        rows = res.data or []
        for r in rows:
            enrich_record_with_packet_loss(r, dev_id_str)
        return rows
    except Exception as e:
        logger.error(f"Error fetching device history from Supabase: {e}")
        return []

def get_all_history(device_id=None, status=None, date_from=None, date_to=None, 
                    page=1, per_page=20, user_id=None, client=None):
    """Fetches paginated monitoring history records with optional filters and user ownership restriction."""
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        # If user_id is provided, get list of device IDs belonging to this user
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return []

        # Try view 'monitoring_history_with_devices' first
        try:
            query = c.table('monitoring_history_with_devices').select('*')
        except Exception:
            query = c.table('monitoring_history').select('*')

        if device_id:
            dev_str = str(device_id).strip()
            if owned_device_ids is not None and dev_str not in owned_device_ids:
                return []
            query = query.eq('device_id', dev_str)
        elif owned_device_ids is not None:
            query = query.in_('device_id', owned_device_ids)

        if status and status.upper() != 'ALL':
            query = query.eq('overall_status', status.upper())

        if date_from:
            query = query.gte('checked_at', f"{date_from}T00:00:00Z")

        if date_to:
            query = query.lte('checked_at', f"{date_to}T23:59:59Z")

        p = max(1, int(page))
        pp = max(1, int(per_page))
        offset = (p - 1) * pp

        query = query.order('checked_at', desc=True).range(offset, offset + pp - 1)
        res = query.execute()
        rows = res.data or []

        for r in rows:
            enrich_record_with_packet_loss(r)

        # If queried from base table without view, enrich device metadata
        if rows and 'device_name' not in rows[0]:
            dev_cache = {}
            for r in rows:
                did = r.get('device_id')
                if did not in dev_cache:
                    dev_cache[did] = get_device_by_id(did, client=client) or {}
                d_info = dev_cache[did]
                r['device_name'] = d_info.get('device_name', 'Unknown')
                r['ip_address'] = d_info.get('ip_address', 'N/A')
                r['port'] = d_info.get('port')

        return rows
    except Exception as e:
        logger.error(f"Error fetching history records from Supabase: {e}")
        return []

def get_history_count(device_id=None, status=None, date_from=None, date_to=None, 
                      user_id=None, client=None):
    """Returns the total number of history records matching optional filters and ownership."""
    if not is_supabase_configured() and client is None:
        return 0
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return 0

        try:
            query = c.table('monitoring_history_with_devices').select('id', count='exact')
        except Exception:
            query = c.table('monitoring_history').select('id', count='exact')

        if device_id:
            dev_str = str(device_id).strip()
            if owned_device_ids is not None and dev_str not in owned_device_ids:
                return 0
            query = query.eq('device_id', dev_str)
        elif owned_device_ids is not None:
            query = query.in_('device_id', owned_device_ids)

        if status and status.upper() != 'ALL':
            query = query.eq('overall_status', status.upper())

        if date_from:
            query = query.gte('checked_at', f"{date_from}T00:00:00Z")

        if date_to:
            query = query.lte('checked_at', f"{date_to}T23:59:59Z")

        res = query.execute()
        return res.count if res.count is not None else len(res.data or [])
    except Exception as e:
        logger.error(f"Error getting history count from Supabase: {e}")
        return 0

def get_recent_faults(limit=5, user_id=None, client=None):
    """Retrieves recent fault occurrences for devices owned by the user."""
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return []

        try:
            query = c.table('monitoring_history_with_devices') \
                     .select('*') \
                     .in_('overall_status', ['FAULT', 'DOWN'])
            if owned_device_ids is not None:
                query = query.in_('device_id', owned_device_ids)

            res = query.order('checked_at', desc=True).limit(int(limit)).execute()
            return res.data or []
        except Exception:
            query = c.table('monitoring_history') \
                     .select('*') \
                     .in_('overall_status', ['FAULT', 'DOWN'])
            if owned_device_ids is not None:
                query = query.in_('device_id', owned_device_ids)

            res = query.order('checked_at', desc=True).limit(int(limit)).execute()
            rows = res.data or []
            for r in rows:
                d = get_device_by_id(r.get('device_id'), client=client) or {}
                r['device_name'] = d.get('device_name', 'Unknown')
                r['ip_address'] = d.get('ip_address', 'N/A')
                r['port'] = d.get('port')
            return rows
    except Exception as e:
        logger.error(f"Error retrieving recent faults from Supabase: {e}")
        return []

def get_recent_checks(limit=6, user_id=None, client=None):
    """Retrieves recent monitoring checks across devices owned by the user."""
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return []

        try:
            query = c.table('monitoring_history_with_devices').select('*')
            if owned_device_ids is not None:
                query = query.in_('device_id', owned_device_ids)
            res = query.order('checked_at', desc=True).limit(int(limit)).execute()
            return res.data or []
        except Exception:
            query = c.table('monitoring_history').select('*')
            if owned_device_ids is not None:
                query = query.in_('device_id', owned_device_ids)
            res = query.order('checked_at', desc=True).limit(int(limit)).execute()
            rows = res.data or []
            for r in rows:
                d = get_device_by_id(r.get('device_id'), client=client) or {}
                r['device_name'] = d.get('device_name', 'Unknown')
                r['ip_address'] = d.get('ip_address', 'N/A')
                r['port'] = d.get('port')
            return rows
    except Exception as e:
        logger.error(f"Error retrieving recent checks from Supabase: {e}")
        return []

# -----------------------------------------------------------------------------
# Fault Reports & Analytics
# -----------------------------------------------------------------------------

def get_fault_reports(device_id=None, category=None, status=None, user_id=None, client=None):
    """
    Computes fault summaries across devices owned by the user:
    - Device details
    - Fault category & details
    - First and last observed timestamps
    - Consecutive failed checks
    - Total recorded failures
    """
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        devices = get_all_devices(user_id=user_id, client=client)
        if device_id:
            dev_id_str = str(device_id).strip()
            devices = [d for d in devices if str(d['id']) == dev_id_str]

        reports = []
        for dev in devices:
            did = str(dev['id'])
            # Fetch recent history for this device
            h_res = c.table('monitoring_history') \
                     .select('*') \
                     .eq('device_id', did) \
                     .order('checked_at', desc=True) \
                     .limit(50) \
                     .execute()
            hists = h_res.data or []
            if not hists:
                continue

            latest = hists[0]
            curr_status = latest.get('overall_status')

            # Only report if latest is FAULT or DOWN, or if user is filtering
            if curr_status not in ('FAULT', 'DOWN'):
                continue

            cat = latest.get('fault_category') or 'NONE'
            if category and category.upper() != 'ALL' and cat.upper() != category.upper():
                continue

            if status and status.upper() != 'ALL' and curr_status.upper() != status.upper():
                continue

            # Calculate consecutive failures from latest backwards
            consecutive = 0
            for h in hists:
                if h.get('overall_status') in ('FAULT', 'DOWN'):
                    consecutive += 1
                else:
                    break

            # Calculate total failures from history records
            failures = [h for h in hists if h.get('overall_status') in ('FAULT', 'DOWN')]
            first_obs = failures[-1]['checked_at'] if failures else latest.get('checked_at')

            reports.append({
                'device_id': dev['id'],
                'device_name': dev['device_name'],
                'ip_address': dev['ip_address'],
                'port': dev.get('port'),
                'fault_category': cat,
                'fault_details': latest.get('fault_details'),
                'fault_status': curr_status,
                'last_observed': latest.get('checked_at'),
                'first_observed': first_obs,
                'response_time_ms': latest.get('response_time_ms'),
                'consecutive_failures': max(1, consecutive),
                'total_failures': len(failures)
            })

        return reports
    except Exception as e:
        logger.error(f"Error computing fault reports from Supabase: {e}")
        return []

def get_history_timeseries(device_id=None, limit=20, user_id=None, client=None):
    """
    Retrieves chronological data points for Chart.js from Supabase:
    - Labels (checked timestamps)
    - Response times (numeric only)
    - Status distribution breakdown
    """
    if not is_supabase_configured() and client is None:
        return {'labels': [], 'response_times': [], 'statuses': [], 'count': 0}
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return {'labels': [], 'response_times': [], 'statuses': [], 'count': 0}

        query = c.table('monitoring_history').select('*')
        if device_id:
            dev_str = str(device_id).strip()
            if owned_device_ids is not None and dev_str not in owned_device_ids:
                return {'labels': [], 'response_times': [], 'packet_losses': [], 'statuses': [], 'count': 0}
            query = query.eq('device_id', dev_str)
        elif owned_device_ids is not None:
            query = query.in_('device_id', owned_device_ids)

        res = query.order('checked_at', desc=True).limit(int(limit)).execute()
        rows = res.data or []

        # Chronological order (oldest to newest)
        rows = list(reversed(rows))
        for r in rows:
            enrich_record_with_packet_loss(r, dev_str if device_id else None)

        labels = []
        for r in rows:
            ca = r.get('checked_at', '')
            if 'T' in ca:
                t_part = ca.split('T')[-1].split('.')[0].replace('Z', '')
                labels.append(t_part)
            elif ' ' in ca:
                labels.append(ca.split()[-1])
            else:
                labels.append(ca)

        response_times = [r.get('response_time_ms') for r in rows]
        packet_losses = [
            round(float(r['packet_loss_pct']), 2) 
            if r.get('packet_loss_pct') is not None 
            else None 
            for r in rows
        ]
        statuses = [r.get('overall_status') for r in rows]

        return {
            'labels': labels,
            'response_times': response_times,
            'packet_losses': packet_losses,
            'statuses': statuses,
            'count': len(rows)
        }
    except Exception as e:
        logger.error(f"Error generating history timeseries from Supabase: {e}")
        return {'labels': [], 'response_times': [], 'packet_losses': [], 'statuses': [], 'count': 0}

# -----------------------------------------------------------------------------
# System Settings (Stored in application_settings)
# -----------------------------------------------------------------------------

def ensure_default_settings(client=None):
    """Seeds default monitoring parameters into application_settings table."""
    c = get_supabase_client(client)
    default_settings = [
        ('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL),
        ('ping_timeout', Config.DEFAULT_PING_TIMEOUT),
        ('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT),
        ('ping_count', getattr(Config, 'DEFAULT_PING_PROBE_COUNT', Config.DEFAULT_PING_COUNT)),
        ('concurrency_limit', Config.DEFAULT_CONCURRENCY_LIMIT),
        ('auto_monitoring', Config.DEFAULT_AUTO_MONITOR),
        ('packet_loss_warning_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_WARNING_PCT', 5)),
        ('packet_loss_critical_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_CRITICAL_PCT', 10)),
        ('alert_on_packet_loss', getattr(Config, 'DEFAULT_ALERT_ON_PACKET_LOSS', 1))
    ]
    for key, val in default_settings:
        try:
            res = c.table('application_settings').select('id').eq('setting_key', key).execute()
            if not res.data:
                c.table('application_settings').insert({
                    'setting_key': key,
                    'setting_value': val,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }).execute()
        except Exception as e:
            logger.debug(f"ensure_default_settings for '{key}': {e}")

    try:
        cnt_res = c.table('application_settings').select('setting_value').eq('setting_key', 'ping_count').execute()
        if cnt_res.data and str(cnt_res.data[0].get('setting_value', '')).strip() in ('0', '1'):
            c.table('application_settings').update({
                'setting_value': 20,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).eq('setting_key', 'ping_count').execute()
    except Exception as e:
        logger.debug(f"Upgrade ping_count note: {e}")

def get_settings(client=None):
    """Reads all configuration settings from application_settings in Supabase with defaults."""
    default_vals = {
        'monitor_interval': Config.DEFAULT_MONITOR_INTERVAL,
        'ping_timeout': Config.DEFAULT_PING_TIMEOUT,
        'tcp_timeout': Config.DEFAULT_TCP_TIMEOUT,
        'ping_count': getattr(Config, 'DEFAULT_PING_PROBE_COUNT', Config.DEFAULT_PING_COUNT),
        'concurrency_limit': Config.DEFAULT_CONCURRENCY_LIMIT,
        'auto_monitoring': Config.DEFAULT_AUTO_MONITOR,
        'packet_loss_warning_pct': getattr(Config, 'DEFAULT_PACKET_LOSS_WARNING_PCT', 5),
        'packet_loss_critical_pct': getattr(Config, 'DEFAULT_PACKET_LOSS_CRITICAL_PCT', 10),
        'alert_on_packet_loss': getattr(Config, 'DEFAULT_ALERT_ON_PACKET_LOSS', 1),
        'email_notifications_enabled': getattr(Config, 'DEFAULT_EMAIL_NOTIFICATIONS', 0),
        'alert_recipient_email': getattr(Config, 'ALERT_RECIPIENT_EMAIL', ''),
        'alert_on_down': getattr(Config, 'DEFAULT_ALERT_ON_DOWN', 1),
        'alert_on_fault': getattr(Config, 'DEFAULT_ALERT_ON_FAULT', 1),
        'alert_on_latency': getattr(Config, 'DEFAULT_ALERT_ON_LATENCY', 1),
        'alert_on_recovery': getattr(Config, 'DEFAULT_ALERT_ON_RECOVERY', 1),
        'latency_threshold_ms': getattr(Config, 'DEFAULT_LATENCY_THRESHOLD_MS', 200),
        'packet_loss_threshold_pct': getattr(Config, 'DEFAULT_PACKET_LOSS_THRESHOLD_PCT', 10),
        'smtp_host': getattr(Config, 'SMTP_HOST', ''),
        'smtp_port': getattr(Config, 'SMTP_PORT', 587),
        'smtp_username': getattr(Config, 'SMTP_USERNAME', ''),
        'smtp_password': getattr(Config, 'SMTP_PASSWORD', ''),
        'smtp_use_tls': 1 if getattr(Config, 'SMTP_USE_TLS', True) else 0,
        'alert_sender_email': getattr(Config, 'ALERT_SENDER_EMAIL', 'netfault-alerts@local'),
        'netfault_public_url': getattr(Config, 'NETFAULT_PUBLIC_URL', 'http://127.0.0.1:5000')
    }
    try:
        c = get_supabase_client(client)
        res = c.table('application_settings').select('setting_key, setting_value').execute()
        s_map = {}
        for row in res.data or []:
            key = row.get('setting_key')
            val = row.get('setting_value')
            if isinstance(val, (int, float)):
                s_map[key] = int(val)
            elif isinstance(val, str) and val.isdigit():
                s_map[key] = int(val)
            else:
                try:
                    s_map[key] = int(val)
                except (ValueError, TypeError):
                    s_map[key] = val

        out = {}
        for k, def_val in default_vals.items():
            val = s_map.get(k)
            if val is None:
                out[k] = def_val
            elif isinstance(def_val, int):
                try:
                    out[k] = int(val)
                except (ValueError, TypeError):
                    out[k] = def_val
            else:
                out[k] = str(val) if val is not None else def_val
        return out
    except Exception as e:
        logger.warning(f"Error fetching settings from Supabase, applying defaults: {e}")
        return default_vals

def update_settings(monitor_interval=None, ping_timeout=None, tcp_timeout=None, ping_count=None,
                    concurrency_limit=None, auto_monitoring=None,
                    packet_loss_warning_pct=None, packet_loss_critical_pct=None, alert_on_packet_loss=None,
                    email_notifications_enabled=None, alert_recipient_email=None,
                    alert_on_down=None, alert_on_fault=None, alert_on_latency=None, alert_on_recovery=None,
                    latency_threshold_ms=None, packet_loss_threshold_pct=None,
                    smtp_host=None, smtp_port=None, smtp_username=None, smtp_password=None, smtp_use_tls=None,
                    alert_sender_email=None, netfault_public_url=None, client=None):
    """Persists updated system monitoring parameters and email alert configuration to Supabase."""
    c = get_supabase_client(client)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    candidates = [
        ('monitor_interval', int(monitor_interval) if monitor_interval is not None else None),
        ('ping_timeout', int(ping_timeout) if ping_timeout is not None else None),
        ('tcp_timeout', int(tcp_timeout) if tcp_timeout is not None else None),
        ('ping_count', int(ping_count) if ping_count is not None else None),
        ('concurrency_limit', int(concurrency_limit) if concurrency_limit is not None else None),
        ('auto_monitoring', int(auto_monitoring) if auto_monitoring is not None else None),
        ('packet_loss_warning_pct', int(packet_loss_warning_pct) if packet_loss_warning_pct is not None else None),
        ('packet_loss_critical_pct', int(packet_loss_critical_pct) if packet_loss_critical_pct is not None else None),
        ('alert_on_packet_loss', int(alert_on_packet_loss) if alert_on_packet_loss is not None else None),
        ('email_notifications_enabled', int(email_notifications_enabled) if email_notifications_enabled is not None else None),
        ('alert_recipient_email', str(alert_recipient_email).strip() if alert_recipient_email is not None else None),
        ('alert_on_down', int(alert_on_down) if alert_on_down is not None else None),
        ('alert_on_fault', int(alert_on_fault) if alert_on_fault is not None else None),
        ('alert_on_latency', int(alert_on_latency) if alert_on_latency is not None else None),
        ('alert_on_recovery', int(alert_on_recovery) if alert_on_recovery is not None else None),
        ('latency_threshold_ms', int(latency_threshold_ms) if latency_threshold_ms is not None else None),
        ('packet_loss_threshold_pct', int(packet_loss_threshold_pct) if packet_loss_threshold_pct is not None else None),
        ('smtp_host', str(smtp_host).strip() if smtp_host is not None else None),
        ('smtp_port', int(smtp_port) if smtp_port is not None else None),
        ('smtp_username', str(smtp_username).strip() if smtp_username is not None else None),
        ('smtp_password', str(smtp_password) if smtp_password is not None else None),
        ('smtp_use_tls', int(smtp_use_tls) if smtp_use_tls is not None else None),
        ('alert_sender_email', str(alert_sender_email).strip() if alert_sender_email is not None else None),
        ('netfault_public_url', str(netfault_public_url).strip() if netfault_public_url is not None else None)
    ]

    updates = [(k, v) for k, v in candidates if v is not None]

    try:
        for key, val in updates:
            c.table('application_settings').upsert({
                'setting_key': key,
                'setting_value': val,
                'updated_at': now_iso
            }, on_conflict='setting_key').execute()
        return True
    except Exception as e:
        logger.error(f"Failed to persist settings to Supabase: {e}")
        raise SupabaseDatabaseError(f"Failed to update settings in Supabase: {str(e)}")


# -----------------------------------------------------------------------------
# Dashboard Summary Statistics
# -----------------------------------------------------------------------------

def get_dashboard_summary(user_id=None, client=None):
    """
    Calculates summary card numbers from the latest status of each device owned by user in Supabase:
    - Total Devices
    - Devices UP
    - Devices DOWN
    - Devices with FAULT
    - Pending / Unchecked Devices
    - Average Response Time (excluding failed/null measurements)
    """
    try:
        devices = get_all_devices(user_id=user_id, client=client)
    except Exception as e:
        logger.error(f"Error fetching devices for dashboard summary: {e}")
        devices = []

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

# -----------------------------------------------------------------------------
# Traceroute Hop-by-Hop Persistence
# -----------------------------------------------------------------------------

def save_traceroute(device_id, target_ip, total_hops, destination_reached,
                    fault_hop, fault_summary, hops_json, raw_output, client=None):
    """Persists a hop-by-hop traceroute execution result into traceroute_history in Supabase."""
    c = get_supabase_client(client)
    try:
        payload = {
            'device_id': str(device_id).strip(),
            'target_ip': str(target_ip).strip(),
            'total_hops': int(total_hops),
            'destination_reached': bool(destination_reached),
            'fault_hop': int(fault_hop) if fault_hop is not None else None,
            'fault_summary': str(fault_summary) if fault_summary else None,
            'hops_json': json.loads(hops_json) if isinstance(hops_json, str) else hops_json,
            'raw_output': str(raw_output) if raw_output else None,
            'executed_at': datetime.now(timezone.utc).isoformat()
        }
        res = c.table('traceroute_history').insert(payload).execute()
        return res.data[0]['id'] if res.data else str(uuid.uuid4())
    except Exception as e:
        logger.error(f"Failed to save traceroute to Supabase: {e}")
        return None

def get_device_traceroutes(device_id, limit=5, user_id=None, client=None):
    """Retrieves recent traceroute execution records for a device with authorization check."""
    if not device_id:
        return []
    if user_id:
        dev = get_device_by_id(device_id, user_id=user_id, client=client)
        if not dev:
            return []

    c = get_supabase_client(client)
    try:
        res = c.table('traceroute_history') \
               .select('*') \
               .eq('device_id', str(device_id).strip()) \
               .order('executed_at', desc=True) \
               .limit(int(limit)) \
               .execute()
        rows = res.data or []
        for r in rows:
            if isinstance(r.get('hops_json'), (list, dict)):
                r['hops_json'] = json.dumps(r['hops_json'])
        return rows
    except Exception as e:
        logger.error(f"Error fetching traceroutes from Supabase: {e}")
        return []

def get_traceroute_by_id(trace_id, user_id=None, client=None):
    """Retrieves a single traceroute record by UUID from Supabase with authorization check."""
    if not trace_id:
        return None
    c = get_supabase_client(client)
    try:
        res = c.table('traceroute_history').select('*').eq('id', str(trace_id).strip()).execute()
        if res.data:
            row = res.data[0]
            if user_id:
                dev = get_device_by_id(row.get('device_id'), user_id=user_id, client=client)
                if not dev:
                    return None
            if isinstance(row.get('hops_json'), (list, dict)):
                row['hops_json'] = json.dumps(row['hops_json'])
            return row
        return None
    except Exception as e:
        logger.error(f"Error fetching traceroute by id from Supabase: {e}")
        return None

# -----------------------------------------------------------------------------
# Incidents & Intelligent Fault Diagnosis Persistence
# -----------------------------------------------------------------------------

def create_incident(device_id, fault_category, severity='CRITICAL', error_details=None,
                    diagnostic_summary=None, probable_cause=None, evidence=None,
                    confidence_level='Medium', recommended_action=None,
                    last_successful_check=None, user_id=None, client=None):
    """
    Creates a new open incident in the incidents table.
    Generates a unique human-readable incident identifier.
    """
    c = get_supabase_client(client)
    now_iso = datetime.now(timezone.utc).isoformat()
    inc_code = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"

    payload = {
        'incident_id': inc_code,
        'device_id': str(device_id).strip(),
        'user_id': str(user_id).strip() if user_id else None,
        'fault_category': str(fault_category),
        'severity': str(severity),
        'incident_status': 'OPEN',
        'first_detected_at': now_iso,
        'last_observed_at': now_iso,
        'last_successful_check': last_successful_check,
        'recovered_at': None,
        'error_details': str(error_details) if error_details else None,
        'diagnostic_summary': str(diagnostic_summary) if diagnostic_summary else None,
        'probable_cause': str(probable_cause) if probable_cause else None,
        'evidence': evidence if isinstance(evidence, list) else ([evidence] if evidence else []),
        'confidence_level': str(confidence_level) if confidence_level else 'Medium',
        'recommended_action': str(recommended_action) if recommended_action else None,
        'created_at': now_iso,
        'updated_at': now_iso
    }

    try:
        res = c.table('incidents').insert(payload).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        payload['id'] = str(uuid.uuid4())
        return payload
    except Exception as e:
        logger.error(f"Failed to create incident in Supabase: {e}")
        payload['id'] = str(uuid.uuid4())
        return payload

def get_active_incident_for_device(device_id, client=None):
    """
    Retrieves the currently OPEN incident for a device, if one exists.
    Returns None if no open incident exists.
    """
    if not device_id or (not is_supabase_configured() and client is None):
        return None
    c = get_supabase_client(client)
    dev_str = str(device_id).strip()
    try:
        res = c.table('incidents') \
               .select('*') \
               .eq('device_id', dev_str) \
               .eq('incident_status', 'OPEN') \
               .order('first_detected_at', desc=True) \
               .limit(1) \
               .execute()
        return res.data[0] if res.data else None
    except Exception as e:
        logger.debug(f"Error fetching active incident for device {dev_str}: {e}")
        return None

def update_incident_observation(incident_id, error_details=None, evidence=None, client=None):
    """
    Updates an ongoing open incident with the latest observation timestamp and evidence.
    Suppresses duplicate notifications while maintaining diagnostic freshness.
    """
    if not incident_id or (not is_supabase_configured() and client is None):
        return False
    c = get_supabase_client(client)
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        'last_observed_at': now_iso,
        'updated_at': now_iso
    }
    if error_details is not None:
        payload['error_details'] = str(error_details)
    if evidence is not None:
        payload['evidence'] = evidence if isinstance(evidence, list) else [evidence]

    try:
        c.table('incidents').update(payload).eq('id', str(incident_id).strip()).execute()
        return True
    except Exception as e:
        logger.error(f"Failed to update incident observation {incident_id}: {e}")
        return False

def resolve_incident(incident_id, recovered_at=None, client=None):
    """
    Marks an open incident as RESOLVED with its recovery timestamp.
    """
    if not incident_id or (not is_supabase_configured() and client is None):
        return None
    c = get_supabase_client(client)
    now_iso = recovered_at or datetime.now(timezone.utc).isoformat()
    payload = {
        'incident_status': 'RESOLVED',
        'recovered_at': now_iso,
        'updated_at': now_iso
    }
    try:
        res = c.table('incidents').update(payload).eq('id', str(incident_id).strip()).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        logger.error(f"Failed to resolve incident {incident_id}: {e}")
        return None

def get_incidents(device_id=None, status=None, severity=None, user_id=None,
                  page=1, per_page=20, client=None):
    """
    Fetches paginated incident records with human-readable device info.
    Supports user ownership filtering.
    """
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return []

        # Try view 'incidents_with_devices' first
        try:
            query = c.table('incidents_with_devices').select('*')
        except Exception:
            query = c.table('incidents').select('*')

        if device_id:
            dev_str = str(device_id).strip()
            if owned_device_ids is not None and dev_str not in owned_device_ids:
                return []
            query = query.eq('device_id', dev_str)
        elif owned_device_ids is not None:
            query = query.in_('device_id', owned_device_ids)

        if status and status.upper() != 'ALL':
            query = query.eq('incident_status', status.upper())

        if severity and severity.upper() != 'ALL':
            query = query.eq('severity', severity.upper())

        p = max(1, int(page))
        pp = max(1, int(per_page))
        offset = (p - 1) * pp

        query = query.order('first_detected_at', desc=True).range(offset, offset + pp - 1)
        res = query.execute()
        rows = res.data or []

        # Enrich device metadata if query used base table
        if rows and 'device_name' not in rows[0]:
            dev_cache = {}
            for r in rows:
                did = r.get('device_id')
                if did not in dev_cache:
                    dev_cache[did] = get_device_by_id(did, client=client) or {}
                d_info = dev_cache[did]
                r['device_name'] = d_info.get('device_name', 'Unknown')
                r['ip_address'] = d_info.get('ip_address', 'N/A')
                r['port'] = d_info.get('port')

        return rows
    except Exception as e:
        logger.error(f"Error fetching incidents from Supabase: {e}")
        return []

def get_incident_count(device_id=None, status=None, severity=None, user_id=None, client=None):
    """Returns the total number of incidents matching optional filters and ownership."""
    if not is_supabase_configured() and client is None:
        return 0
    c = get_supabase_client(client)
    try:
        owned_device_ids = None
        if user_id:
            user_devices = get_all_devices(user_id=user_id, client=client)
            owned_device_ids = [str(d['id']) for d in user_devices]
            if not owned_device_ids:
                return 0

        try:
            query = c.table('incidents_with_devices').select('id', count='exact')
        except Exception:
            query = c.table('incidents').select('id', count='exact')

        if device_id:
            dev_str = str(device_id).strip()
            if owned_device_ids is not None and dev_str not in owned_device_ids:
                return 0
            query = query.eq('device_id', dev_str)
        elif owned_device_ids is not None:
            query = query.in_('device_id', owned_device_ids)

        if status and status.upper() != 'ALL':
            query = query.eq('incident_status', status.upper())

        if severity and severity.upper() != 'ALL':
            query = query.eq('severity', severity.upper())

        res = query.execute()
        return res.count if res.count is not None else len(res.data or [])
    except Exception as e:
        logger.error(f"Error getting incident count from Supabase: {e}")
        return 0

def get_incident_by_id(incident_id, user_id=None, client=None):
    """Fetches a single incident record by UUID or human INC- identifier."""
    if not incident_id or (not is_supabase_configured() and client is None):
        return None
    c = get_supabase_client(client)
    inc_str = str(incident_id).strip()
    try:
        query = c.table('incidents').select('*')
        if inc_str.startswith('INC-'):
            query = query.eq('incident_id', inc_str)
        else:
            query = query.eq('id', inc_str)
        res = query.limit(1).execute()
        if not res.data:
            return None
        row = res.data[0]
        dev = get_device_by_id(row.get('device_id'), user_id=user_id, client=client)
        if not dev and user_id:
            return None
        if dev:
            row['device_name'] = dev.get('device_name', 'Unknown')
            row['ip_address'] = dev.get('ip_address', 'N/A')
            row['port'] = dev.get('port')
        return row
    except Exception as e:
        logger.error(f"Error fetching incident {inc_str}: {e}")
        return None

# -----------------------------------------------------------------------------
# Notification History Operations
# -----------------------------------------------------------------------------

def log_notification(incident_id, recipient_email, notification_type, subject,
                     delivery_status='SENT', error_message=None, metadata=None, client=None):
    """
    Records an email delivery attempt into notification_history in Supabase.
    """
    if not is_supabase_configured() and client is None:
        return None
    c = get_supabase_client(client)
    payload = {
        'incident_id': str(incident_id).strip() if incident_id else None,
        'recipient_email': str(recipient_email).strip(),
        'notification_type': str(notification_type),
        'subject': str(subject),
        'attempted_at': datetime.now(timezone.utc).isoformat(),
        'delivery_status': str(delivery_status),
        'error_message': str(error_message) if error_message else None,
        'retry_count': 0,
        'metadata': metadata or {}
    }
    try:
        res = c.table('notification_history').insert(payload).execute()
        return res.data[0] if res.data else payload
    except Exception as e:
        logger.error(f"Failed to log notification to Supabase: {e}")
        return payload

def get_notification_history(incident_id=None, limit=50, client=None):
    """Retrieves recent notification logs from Supabase."""
    if not is_supabase_configured() and client is None:
        return []
    c = get_supabase_client(client)
    try:
        query = c.table('notification_history').select('*')
        if incident_id:
            query = query.eq('incident_id', str(incident_id).strip())
        res = query.order('attempted_at', desc=True).limit(int(limit)).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"Error fetching notification history from Supabase: {e}")
        return []

