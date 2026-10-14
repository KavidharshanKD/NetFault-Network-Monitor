"""
Automated Fault Detection System (AFDS) - Flask Web Application.
Provides dashboard, device administration, history records, fault diagnostics,
real-time API triggers, Supabase Auth integration, multi-tenant device ownership,
and session management.
"""

import os
import sys
import secrets
import hmac
import json
import logging
import re
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify,
    session, Response, abort
)
from config import Config
import database
import monitoring
from scheduler import scheduler
import services
import fault_diagnosis
import notifications

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE_PATH, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_app(config_object=Config):
    """Application factory for Flask."""
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # Initialize Supabase schema verification and seed default settings
    with app.app_context():
        try:
            database.init_db()
        except Exception as e:
            logger.warning(f"Note: Database initialization check: {e}")

    # -------------------------------------------------------------------------
    # Authentication & Session Management
    # -------------------------------------------------------------------------

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if app.config.get('LOGIN_DISABLED'):
                return f(*args, **kwargs)
            if 'user_id' not in session:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required. Please log in.'}), 401
                return redirect(url_for('login', next=request.full_path))
            return f(*args, **kwargs)
        return decorated_function

    # -------------------------------------------------------------------------
    # CSRF Protection Helpers
    # -------------------------------------------------------------------------

    def generate_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']

    def validate_csrf_token():
        if app.config.get('TESTING') or app.config.get('WTF_CSRF_ENABLED') is False:
            return True
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if not token and request.is_json:
            token = request.json.get('csrf_token')
        session_token = session.get('csrf_token')
        if not token or not session_token or not hmac.compare_digest(token, session_token):
            return False
        return True

    @app.context_processor
    def inject_csrf_and_globals():
        return {
            'csrf_token': generate_csrf_token,
            'app_name': Config.APP_NAME,
            'app_version': Config.APP_VERSION,
            'scheduler_running': scheduler.is_running(),
            'last_cycle_time': scheduler.get_last_cycle_time(),
            'current_user': session.get('user_email'),
            'current_user_name': session.get('user_name', 'Administrator'),
            'supabase_configured': database.is_supabase_configured()
        }

    # -------------------------------------------------------------------------
    # Supabase Auth Routes (Sign In, Create Account, Reset Password, Sign Out)
    # -------------------------------------------------------------------------

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """User sign-in using Supabase Auth (GoTrue)."""
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        next_url = request.args.get('next') or request.form.get('next') or url_for('dashboard')
        active_panel = request.args.get('panel', 'signin')

        if request.method == 'POST':
            if not validate_csrf_token():
                err_msg = "Security token validation failed. Please refresh and try again."
                if request.is_json:
                    return jsonify({'success': False, 'error': err_msg}), 400
                flash(err_msg, 'error')
                return render_template('login.html', next=next_url, active_panel='signin'), 400

            if request.is_json:
                data = request.get_json() or {}
                email = data.get('email', '').strip().lower()
                password = data.get('password', '').strip()
                remember_me = bool(data.get('remember_me', False))
            else:
                email = request.form.get('email', '').strip().lower()
                password = request.form.get('password', '').strip()
                remember_me = bool(request.form.get('remember_me'))

            if not email or not password:
                err_msg = "Please enter both email address and password."
                if request.is_json:
                    return jsonify({'success': False, 'error': err_msg}), 400
                flash(err_msg, 'error')
                return render_template('login.html', email=email, next=next_url, active_panel='signin'), 400

            auth_res = database.auth_sign_in(email, password)

            if auth_res.get('success'):
                session.clear()
                session.permanent = remember_me
                session['user_id'] = str(auth_res['user_id'])
                session['user_email'] = auth_res['email']
                session['user_name'] = auth_res.get('full_name') or 'Administrator'
                if auth_res.get('access_token'):
                    session['access_token'] = auth_res['access_token']

                # Adopt any legacy unowned devices to this user so data is seamlessly preserved
                database.claim_unowned_devices(session['user_id'])

                if request.is_json:
                    return jsonify({
                        'success': True,
                        'redirect': next_url,
                        'user': {
                            'email': session['user_email'],
                            'name': session['user_name']
                        }
                    })

                flash(f"Welcome back, {session['user_name']}!", 'success')
                return redirect(next_url)
            else:
                err_msg = auth_res.get('error', 'Authentication failed.')
                if request.is_json:
                    return jsonify({'success': False, 'error': err_msg}), 401
                flash(err_msg, 'error')
                return render_template('login.html', email=email, next=next_url, active_panel='signin'), 401

        return render_template('login.html', next=next_url, active_panel=active_panel)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User account registration using Supabase Auth (GoTrue)."""
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'GET':
            return redirect(url_for('login', panel='register'))

        if not validate_csrf_token():
            err_msg = "Security token validation failed. Please refresh and try again."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 400
            flash(err_msg, 'error')
            return render_template('login.html', active_panel='register'), 400

        if request.is_json:
            data = request.get_json() or {}
            full_name = data.get('full_name', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '').strip()
            confirm_password = data.get('confirm_password', '').strip()
        else:
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

        # Server-side validations
        if not full_name:
            err = "Full name is required."
            if request.is_json:
                return jsonify({'success': False, 'error': err}), 400
            flash(err, 'error')
            return render_template('login.html', full_name=full_name, email=email, active_panel='register'), 400

        if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            err = "Please enter a valid email address."
            if request.is_json:
                return jsonify({'success': False, 'error': err}), 400
            flash(err, 'error')
            return render_template('login.html', full_name=full_name, email=email, active_panel='register'), 400

        if len(password) < 8:
            err = "Password must be at least 8 characters long."
            if request.is_json:
                return jsonify({'success': False, 'error': err}), 400
            flash(err, 'error')
            return render_template('login.html', full_name=full_name, email=email, active_panel='register'), 400

        if password != confirm_password:
            err = "Passwords do not match."
            if request.is_json:
                return jsonify({'success': False, 'error': err}), 400
            flash(err, 'error')
            return render_template('login.html', full_name=full_name, email=email, active_panel='register'), 400

        auth_res = database.auth_sign_up(email, password, full_name=full_name)

        if auth_res.get('success'):
            session.clear()
            session['user_id'] = str(auth_res['user_id'])
            session['user_email'] = auth_res['email']
            session['user_name'] = auth_res.get('full_name') or full_name

            database.claim_unowned_devices(session['user_id'])

            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': f"Account created! Welcome, {session['user_name']}.",
                    'redirect': url_for('dashboard')
                })
            flash(f"Account created! Welcome, {session['user_name']}.", 'success')
            return redirect(url_for('dashboard'))
        else:
            err_msg = auth_res.get('error', 'Registration failed.')
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 400
            flash(err_msg, 'error')
            return render_template('login.html', full_name=full_name, email=email, active_panel='register'), 400

    @app.route('/forgot-password', methods=['POST'])
    def forgot_password():
        """Resets user password in Supabase PostgreSQL."""
        if not validate_csrf_token():
            err_msg = "Security token validation failed."
            if request.is_json:
                return jsonify({'success': False, 'error': err_msg}), 400
            flash(err_msg, 'error')
            return redirect(url_for('login'))

        if request.is_json:
            data = request.get_json() or {}
            email = data.get('email', '').strip().lower()
            new_password = data.get('new_password', '').strip()
        else:
            email = request.form.get('email', '').strip().lower()
            new_password = request.form.get('new_password', '').strip()

        if not email:
            err = "Please enter your registered email address."
            if request.is_json:
                return jsonify({'success': False, 'error': err}), 400
            flash(err, 'error')
            return redirect(url_for('login'))

        res = database.auth_reset_password(email, new_password=new_password or None)

        msg = res.get('message', 'If an account exists with this email address, password has been updated.')
        if request.is_json:
            return jsonify({'success': True, 'message': msg})

        flash(msg, 'info')
        return redirect(url_for('login'))

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        """Logs out the active administrator session from Supabase Auth and Flask."""
        token = session.get('access_token')
        database.auth_sign_out(access_token=token)
        session.clear()
        flash("You have been signed out successfully.", 'info')
        return redirect(url_for('login'))

    # -------------------------------------------------------------------------
    # Frontend Page Routes (Protected by user-ownership session)
    # -------------------------------------------------------------------------

    @app.route('/')
    @login_required
    def dashboard():
        """Central network monitoring dashboard displaying user-specific devices and telemetry."""
        user_id = session.get('user_id')
        summary = database.get_dashboard_summary(user_id=user_id)
        devices = database.get_all_devices(user_id=user_id)
        recent_faults = database.get_recent_faults(limit=5, user_id=user_id)
        recent_checks = database.get_recent_checks(limit=6, user_id=user_id)
        scheduler_running = scheduler.is_running()
        last_cycle = scheduler.get_last_cycle_time()

        return render_template(
            'dashboard.html',
            summary=summary,
            devices=devices,
            recent_faults=recent_faults,
            recent_checks=recent_checks,
            scheduler_running=scheduler_running,
            last_cycle=last_cycle
        )

    @app.route('/devices')
    @login_required
    def device_list():
        """Device inventory page with search, status filters, sorting, and user-isolated pagination."""
        user_id = session.get('user_id')
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', 'ALL').strip()
        sort_by = request.args.get('sort', 'name').strip()
        sort_dir = request.args.get('dir', 'asc').strip()
        page_raw = request.args.get('page', '1').strip()

        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1

        per_page = 10
        total_devices = database.get_devices_count(search=search, status_filter=status_filter, user_id=user_id)
        total_pages = max(1, (total_devices + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        devices = database.get_all_devices(
            search=search,
            status_filter=status_filter,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page,
            per_page=per_page,
            user_id=user_id
        )

        return render_template(
            'devices.html',
            devices=devices,
            search=search,
            status_filter=status_filter,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page,
            total_pages=total_pages,
            total_devices=total_devices
        )

    @app.route('/devices/add', methods=['GET', 'POST'])
    @login_required
    def add_device():
        """Form and handler for registering a new network device in Supabase owned by user."""
        user_id = session.get('user_id')

        if request.method == 'POST':
            if not validate_csrf_token():
                flash("Security token validation failed. Please try again.", 'error')
                return render_template('add_device.html'), 400

            device_name = request.form.get('device_name', '').strip()
            ip_address = request.form.get('ip_address', '').strip()
            port_raw = request.form.get('port', '').strip()
            description = request.form.get('description', '').strip()
            monitoring_enabled = 1 if request.form.get('monitoring_enabled') in ('1', 'on', 'true', True) else 0

            errors = []

            if not device_name:
                errors.append("Device name is required.")

            is_valid_ip, ip_err, _ = monitoring.validate_ip_address(ip_address)
            if not is_valid_ip:
                errors.append(ip_err)

            is_valid_port, port_err, port_val = monitoring.validate_port(port_raw if port_raw else None)
            if not is_valid_port:
                errors.append(port_err)

            if is_valid_ip and not errors:
                if database.check_duplicate_device(ip_address, port_val, user_id=user_id):
                    errors.append(f"A device with IP '{ip_address}' and port '{port_val or 'None'}' is already registered in your inventory.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                return render_template(
                    'add_device.html',
                    device_name=device_name,
                    ip_address=ip_address,
                    port=port_raw,
                    description=description,
                    monitoring_enabled=monitoring_enabled
                ), 400

            try:
                dev_id = database.create_device(
                    device_name=device_name,
                    ip_address=ip_address,
                    port=port_val,
                    description=description or None,
                    monitoring_enabled=monitoring_enabled,
                    user_id=user_id
                )

                # Perform initial non-blocking check
                scheduler.check_single_device(dev_id)

                flash(f"Device '{device_name}' successfully added and initial check performed.", 'success')
                return redirect(url_for('device_list'))
            except Exception as e:
                flash(f"Failed to add device to Supabase: {str(e)}", 'error')
                return render_template(
                    'add_device.html',
                    device_name=device_name,
                    ip_address=ip_address,
                    port=port_raw,
                    description=description,
                    monitoring_enabled=monitoring_enabled
                ), 500

        return render_template('add_device.html')

    @app.route('/devices/<device_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_device(device_id):
        """Form and handler for editing an existing device with ownership verification."""
        user_id = session.get('user_id')
        device = database.get_device_by_id(device_id, user_id=user_id)
        if not device:
            flash("Device not found or you do not have permission to modify it.", 'error')
            return redirect(url_for('device_list'))

        if request.method == 'POST':
            if not validate_csrf_token():
                flash("Security token validation failed. Please try again.", 'error')
                return render_template('edit_device.html', device=device), 400

            device_name = request.form.get('device_name', '').strip()
            ip_address = request.form.get('ip_address', '').strip()
            port_raw = request.form.get('port', '').strip()
            description = request.form.get('description', '').strip()
            monitoring_enabled = 1 if request.form.get('monitoring_enabled') in ('1', 'on', 'true', True) else 0

            errors = []

            if not device_name:
                errors.append("Device name is required.")

            is_valid_ip, ip_err, _ = monitoring.validate_ip_address(ip_address)
            if not is_valid_ip:
                errors.append(ip_err)

            is_valid_port, port_err, port_val = monitoring.validate_port(port_raw if port_raw else None)
            if not is_valid_port:
                errors.append(port_err)

            if is_valid_ip and not errors:
                if database.check_duplicate_device(ip_address, port_val, exclude_id=device_id, user_id=user_id):
                    errors.append(f"Another device already uses IP '{ip_address}' and port '{port_val or 'None'}'.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                return render_template('edit_device.html', device=device), 400

            try:
                database.update_device(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    port=port_val,
                    description=description or None,
                    monitoring_enabled=monitoring_enabled,
                    user_id=user_id
                )

                scheduler.check_single_device(device_id)

                flash(f"Device '{device_name}' updated successfully in Supabase.", 'success')
                return redirect(url_for('device_details', device_id=device_id))
            except PermissionError:
                flash("Unauthorized: You do not have permission to edit this device.", 'error')
                return redirect(url_for('device_list'))
            except Exception as e:
                flash(f"Failed to update device: {str(e)}", 'error')
                return render_template('edit_device.html', device=device), 500

        return render_template('edit_device.html', device=device)

    @app.route('/devices/<device_id>/delete', methods=['POST'])
    @login_required
    def delete_device(device_id):
        """Deletes a device from Supabase with ownership enforcement."""
        user_id = session.get('user_id')
        if not validate_csrf_token():
            flash("Security token validation failed.", 'error')
            return redirect(url_for('device_list'))

        device = database.get_device_by_id(device_id, user_id=user_id)
        if device:
            try:
                database.delete_device(device_id, user_id=user_id)
                flash(f"Device '{device['device_name']}' and its history have been permanently deleted.", 'success')
            except PermissionError:
                flash("Unauthorized: You do not have permission to delete this device.", 'error')
            except Exception as e:
                flash(f"Could not delete device from Supabase: {str(e)}", 'error')
        else:
            flash("Device not found.", 'error')
        return redirect(url_for('device_list'))

    @app.route('/devices/<device_id>/toggle', methods=['POST'])
    @login_required
    def toggle_device(device_id):
        """Toggles monitoring state for a device owned by the user."""
        user_id = session.get('user_id')
        if not validate_csrf_token():
            flash("Security token validation failed.", 'error')
            return redirect(url_for('device_list'))

        new_val = database.toggle_device_monitoring(device_id, user_id=user_id)
        if new_val is None:
            flash("Device not found or unauthorized.", 'error')
            return redirect(url_for('device_list'))

        state_str = "enabled" if new_val == 1 else "disabled"
        flash(f"Monitoring {state_str} for device.", 'success')
        return redirect(request.referrer or url_for('device_list'))

    @app.route('/devices/<device_id>')
    @login_required
    def device_details(device_id):
        """Detailed view for an individual network device owned by user."""
        user_id = session.get('user_id')
        device = database.get_device_by_id(device_id, user_id=user_id)
        if not device:
            flash("Device not found or unauthorized.", 'error')
            return redirect(url_for('device_list'))

        history = database.get_device_history(device_id, limit=25, user_id=user_id)
        timeseries = database.get_history_timeseries(device_id=device_id, limit=15, user_id=user_id)
        traceroutes = database.get_device_traceroutes(device_id, limit=5, user_id=user_id)
        active_incident = database.get_active_incident_for_device(device_id)
        device_incidents = database.get_incidents(device_id=device_id, user_id=user_id, page=1, per_page=5)
        for t in traceroutes:
            try:
                t['hops'] = json.loads(t['hops_json']) if isinstance(t.get('hops_json'), str) else t.get('hops_json', [])
            except Exception:
                t['hops'] = []
            t['total_hops'] = len(t['hops']) if t['hops'] else t.get('total_hops', 0)
            t['responding_hops'] = sum(1 for h in t['hops'] if h.get('status') != 'TIMED_OUT' and h.get('ip') != '*')
            t['non_responsive_hops'] = sum(1 for h in t['hops'] if h.get('status') == 'TIMED_OUT' or h.get('ip') == '*')
            target_ip_clean = str(device.get('ip_address', '')).strip()
            t['destination_hop'] = next((h.get('hop') for h in t['hops'] if str(h.get('ip', '')).strip() == target_ip_clean), None)
        return render_template(
            'device_details.html',
            device=device,
            history=history,
            timeseries=timeseries,
            traceroutes=traceroutes,
            active_incident=active_incident,
            incidents=device_incidents
        )

    @app.route('/history')
    @login_required
    def history_view():
        """Chronological monitoring history table with filters, pagination, and user isolation."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id', '').strip()
        status_filter = request.args.get('status', 'ALL').strip().upper()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        page_raw = request.args.get('page', '1').strip()

        device_id = device_id_raw if device_id_raw else None
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1

        per_page = 20
        total_records = database.get_history_count(
            device_id=device_id,
            status=status_filter,
            date_from=date_from or None,
            date_to=date_to or None,
            user_id=user_id
        )
        total_pages = max(1, (total_records + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        history_records = database.get_all_history(
            device_id=device_id,
            status=status_filter,
            date_from=date_from or None,
            date_to=date_to or None,
            page=page,
            per_page=per_page,
            user_id=user_id
        )
        all_devices = database.get_all_devices(user_id=user_id)

        return render_template(
            'history.html',
            history=history_records,
            devices=all_devices,
            selected_device_id=device_id,
            selected_status=status_filter,
            date_from=date_from,
            date_to=date_to,
            page=page,
            total_pages=total_pages,
            total_records=total_records
        )

    @app.route('/faults')
    @login_required
    def faults_view():
        """Fault reports and investigation view for user's devices."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id', '').strip()
        category = request.args.get('category', 'ALL').strip()
        status = request.args.get('status', 'ALL').strip()

        device_id = device_id_raw if device_id_raw else None
        reports = database.get_fault_reports(device_id=device_id, category=category, status=status, user_id=user_id)
        incidents = database.get_incidents(
            device_id=device_id,
            status=status if status in ('OPEN', 'RESOLVED') else None,
            severity=category if category in ('CRITICAL', 'HIGH', 'WARNING', 'INFO') else None,
            user_id=user_id,
            page=1,
            per_page=50
        )
        for inc in incidents:
            inc['fault_localization'] = fault_diagnosis.get_localization_for_incident(inc)

        devices = database.get_all_devices(user_id=user_id)

        return render_template(
            'faults.html',
            reports=reports,
            incidents=incidents,
            devices=devices,
            selected_device_id=device_id,
            selected_category=category,
            selected_status=status
        )

    @app.route('/faults/export')
    @login_required
    def export_faults():
        """Exports filtered fault reports as CSV from user's Supabase records."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id', '').strip()
        category = request.args.get('category', 'ALL').strip()
        status = request.args.get('status', 'ALL').strip()
        device_id = device_id_raw if device_id_raw else None

        reports = database.get_fault_reports(device_id=device_id, category=category, status=status, user_id=user_id)
        csv_data = services.generate_faults_csv_from_reports(reports)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=fault_reports.csv"}
        )

    @app.route('/history/export')
    @login_required
    def export_history():
        """Exports filtered monitoring audit log as CSV for user's devices."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id', '').strip()
        status = request.args.get('status', 'ALL').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        device_id = device_id_raw if device_id_raw else None

        records = database.get_all_history(
            device_id=device_id,
            status=status,
            date_from=date_from or None,
            date_to=date_to or None,
            page=1,
            per_page=1000,
            user_id=user_id
        )
        csv_data = services.generate_history_csv_from_records(records)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=monitoring_history.csv"}
        )

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings_view():
        """Configuration page for monitoring parameters persisted to Supabase."""
        if request.method == 'POST':
            if not validate_csrf_token():
                flash("Security token validation failed. Please try again.", 'error')
                return render_template('settings.html', settings=database.get_settings()), 400

            errors = []
            try:
                monitor_interval = int(request.form.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL))
                ping_timeout = int(request.form.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT))
                tcp_timeout = int(request.form.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT))
                ping_count = int(request.form.get('ping_count', Config.DEFAULT_PING_COUNT))
                concurrency_limit = int(request.form.get('concurrency_limit', Config.DEFAULT_CONCURRENCY_LIMIT))
                auto_monitoring = 1 if request.form.get('auto_monitoring') in ('1', 'on', 'true', True) else 0

                # Email notification parameters
                email_notifications_enabled = 1 if request.form.get('email_notifications_enabled') in ('1', 'on', 'true', True) else 0
                alert_recipient_email = request.form.get('alert_recipient_email', '').strip()
                alert_on_down = 1 if request.form.get('alert_on_down') in ('1', 'on', 'true', True) else 0
                alert_on_fault = 1 if request.form.get('alert_on_fault') in ('1', 'on', 'true', True) else 0
                alert_on_latency = 1 if request.form.get('alert_on_latency') in ('1', 'on', 'true', True) else 0
                alert_on_packet_loss = 1 if request.form.get('alert_on_packet_loss') in ('1', 'on', 'true', True) else 0
                alert_on_recovery = 1 if request.form.get('alert_on_recovery') in ('1', 'on', 'true', True) else 0
                latency_threshold_ms = int(request.form.get('latency_threshold_ms', Config.DEFAULT_LATENCY_THRESHOLD_MS))
                packet_loss_warning_pct = int(request.form.get('packet_loss_warning_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_WARNING_PCT', 5)))
                packet_loss_critical_pct = int(request.form.get('packet_loss_critical_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_CRITICAL_PCT', 10)))
                packet_loss_threshold_pct = packet_loss_critical_pct

                if not (Config.MIN_MONITOR_INTERVAL <= monitor_interval <= Config.MAX_MONITOR_INTERVAL):
                    errors.append(f"Interval must be between {Config.MIN_MONITOR_INTERVAL} and {Config.MAX_MONITOR_INTERVAL} seconds.")

                if not (Config.MIN_PING_TIMEOUT <= ping_timeout <= Config.MAX_PING_TIMEOUT):
                    errors.append(f"Ping timeout must be between {Config.MIN_PING_TIMEOUT} and {Config.MAX_PING_TIMEOUT} seconds.")

                if not (Config.MIN_TCP_TIMEOUT <= tcp_timeout <= Config.MAX_TCP_TIMEOUT):
                    errors.append(f"TCP timeout must be between {Config.MIN_TCP_TIMEOUT} and {Config.MAX_TCP_TIMEOUT} seconds.")

                if not (Config.MIN_PING_COUNT <= ping_count <= Config.MAX_PING_COUNT):
                    errors.append(f"Ping attempts must be between {Config.MIN_PING_COUNT} and {Config.MAX_PING_COUNT}.")

                if not (Config.MIN_CONCURRENCY_LIMIT <= concurrency_limit <= Config.MAX_CONCURRENCY_LIMIT):
                    errors.append(f"Concurrency limit must be between {Config.MIN_CONCURRENCY_LIMIT} and {Config.MAX_CONCURRENCY_LIMIT}.")

                if not (Config.MIN_PACKET_LOSS_THRESHOLD_PCT <= packet_loss_warning_pct <= Config.MAX_PACKET_LOSS_THRESHOLD_PCT):
                    errors.append(f"Packet loss warning threshold must be between {Config.MIN_PACKET_LOSS_THRESHOLD_PCT}% and {Config.MAX_PACKET_LOSS_THRESHOLD_PCT}%.")

                if not (Config.MIN_PACKET_LOSS_THRESHOLD_PCT <= packet_loss_critical_pct <= Config.MAX_PACKET_LOSS_THRESHOLD_PCT):
                    errors.append(f"Packet loss critical threshold must be between {Config.MIN_PACKET_LOSS_THRESHOLD_PCT}% and {Config.MAX_PACKET_LOSS_THRESHOLD_PCT}%.")

                if packet_loss_warning_pct > packet_loss_critical_pct:
                    errors.append("Packet loss warning threshold cannot exceed critical threshold.")

                if email_notifications_enabled and alert_recipient_email:
                    # Validate comma-separated emails
                    for em in alert_recipient_email.split(','):
                        em_clean = em.strip()
                        if em_clean and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", em_clean):
                            errors.append(f"Invalid alert recipient email address: '{em_clean}'.")

            except (ValueError, TypeError):
                errors.append("All numeric configuration fields must be valid numbers.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                return render_template('settings.html', settings=database.get_settings()), 400

            try:
                database.update_settings(
                    monitor_interval=monitor_interval,
                    ping_timeout=ping_timeout,
                    tcp_timeout=tcp_timeout,
                    ping_count=ping_count,
                    concurrency_limit=concurrency_limit,
                    auto_monitoring=auto_monitoring,
                    packet_loss_warning_pct=packet_loss_warning_pct,
                    packet_loss_critical_pct=packet_loss_critical_pct,
                    alert_on_packet_loss=alert_on_packet_loss,
                    email_notifications_enabled=email_notifications_enabled,
                    alert_recipient_email=alert_recipient_email,
                    alert_on_down=alert_on_down,
                    alert_on_fault=alert_on_fault,
                    alert_on_latency=alert_on_latency,
                    alert_on_recovery=alert_on_recovery,
                    latency_threshold_ms=latency_threshold_ms,
                    packet_loss_threshold_pct=packet_loss_threshold_pct
                )
                flash("Settings and notification preferences updated successfully.", 'success')
                return redirect(url_for('settings_view'))
            except Exception as e:
                flash(f"Failed to persist settings in Supabase: {str(e)}", 'error')
                return render_template('settings.html', settings=database.get_settings()), 500

        current_settings = database.get_settings()
        return render_template('settings.html', settings=current_settings)

    @app.route('/system')
    @login_required
    def system_view():
        """System Information and architecture diagnostics page."""
        diagnostics = services.get_system_diagnostics(scheduler)
        return render_template('system.html', diag=diagnostics)

    # -------------------------------------------------------------------------
    # REST / JSON API Endpoints (Asynchronous Dashboard & User-Scoped Telemetry)
    # -------------------------------------------------------------------------

    @app.route('/api/summary')
    @login_required
    def api_summary():
        """Returns JSON dashboard counts and average response time for user's devices."""
        user_id = session.get('user_id')
        return jsonify(database.get_dashboard_summary(user_id=user_id))

    @app.route('/api/devices')
    @login_required
    def api_devices():
        """Returns JSON array of devices with latest monitoring states owned by user."""
        user_id = session.get('user_id')
        return jsonify(database.get_all_devices(user_id=user_id))

    @app.route('/api/devices/<device_id>/check', methods=['POST'])
    @login_required
    def api_check_device(device_id):
        """Triggers immediate monitoring check for an individual device with ownership check."""
        user_id = session.get('user_id')
        device = database.get_device_by_id(device_id, user_id=user_id)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found or unauthorized'}), 404

        result = scheduler.check_single_device(device_id)
        updated_device = database.get_device_by_id(device_id, user_id=user_id)
        return jsonify({
            'success': True,
            'result': result,
            'device': updated_device
        })

    @app.route('/api/check-all', methods=['POST'])
    @login_required
    def api_check_all():
        """Triggers immediate monitoring check for all registered devices."""
        user_id = session.get('user_id')
        results = scheduler.check_all_devices(only_enabled=False)
        summary = database.get_dashboard_summary(user_id=user_id)
        devices = database.get_all_devices(user_id=user_id)
        return jsonify({
            'success': True,
            'checked_count': len(results),
            'summary': summary,
            'devices': devices
        })

    @app.route('/api/scheduler/start', methods=['POST'])
    @login_required
    def api_scheduler_start():
        """Starts background periodic monitoring worker."""
        started = scheduler.start()
        return jsonify({
            'success': True,
            'running': scheduler.is_running(),
            'message': 'Background monitoring started.' if started else 'Scheduler is already running.'
        })

    @app.route('/api/scheduler/stop', methods=['POST'])
    @login_required
    def api_scheduler_stop():
        """Stops background periodic monitoring worker."""
        stopped = scheduler.stop()
        return jsonify({
            'success': True,
            'running': scheduler.is_running(),
            'message': 'Background monitoring stopped.' if stopped else 'Scheduler was not running.'
        })

    @app.route('/api/scheduler/status')
    @login_required
    def api_scheduler_status():
        """Returns current scheduler operational status."""
        settings = database.get_settings()
        return jsonify({
            'running': scheduler.is_running(),
            'last_cycle': scheduler.get_last_cycle_time(),
            'interval': settings.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL),
            'auto_monitoring': bool(settings.get('auto_monitoring', 1))
        })

    @app.route('/api/history')
    @login_required
    def api_history():
        """Returns JSON array of history records from Supabase owned by user."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id')
        status = request.args.get('status')
        limit = min(100, int(request.args.get('limit', 20)))
        device_id = device_id_raw.strip() if device_id_raw else None
        records = database.get_all_history(device_id=device_id, status=status, page=1, per_page=limit, user_id=user_id)
        return jsonify({'success': True, 'records': records})

    @app.route('/api/faults')
    @login_required
    def api_faults():
        """Returns JSON array of active/recent faults for user's devices."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id')
        device_id = device_id_raw.strip() if device_id_raw else None
        reports = database.get_fault_reports(device_id=device_id, user_id=user_id)
        return jsonify({'success': True, 'faults': reports})

    @app.route('/api/chart/history')
    @login_required
    def api_chart_history():
        """Returns time-series metrics formatted for Chart.js from user's devices."""
        user_id = session.get('user_id')
        device_id_raw = request.args.get('device_id')
        device_id = device_id_raw.strip() if device_id_raw else None
        data = database.get_history_timeseries(device_id=device_id, limit=20, user_id=user_id)
        return jsonify(data)

    @app.route('/api/devices/<device_id>/traceroute', methods=['POST'])
    @login_required
    def api_device_traceroute(device_id):
        """
        Executes a hop-by-hop traceroute to localize packet loss or routing breaks.
        Verifies device ownership before running.
        """
        user_id = session.get('user_id')
        if not validate_csrf_token():
            return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400

        device = database.get_device_by_id(device_id, user_id=user_id)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found or unauthorized'}), 404

        max_hops = min(30, max(5, int(request.json.get('max_hops', 15) if request.is_json else 15)))
        timeout_ms = min(5000, max(500, int(request.json.get('timeout_ms', 2000) if request.is_json else 2000)))

        trace_result = monitoring.run_traceroute(
            target_ip=device['ip_address'],
            max_hops=max_hops,
            timeout_ms=timeout_ms
        )

        trace_id = database.save_traceroute(
            device_id=device['id'],
            target_ip=device['ip_address'],
            total_hops=trace_result['total_hops'],
            destination_reached=trace_result['destination_reached'],
            fault_hop=trace_result['fault_hop'],
            fault_summary=trace_result['fault_summary'],
            hops_json=json.dumps(trace_result['hops']),
            raw_output=trace_result['raw_output']
        )

        return jsonify({
            'success': True,
            'trace_id': trace_id,
            'result': trace_result
        })

    @app.route('/api/devices/<device_id>/traceroutes')
    @login_required
    def api_device_traceroute_history(device_id):
        """Returns recent traceroute history for a device owned by user."""
        user_id = session.get('user_id')
        device = database.get_device_by_id(device_id, user_id=user_id)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found or unauthorized'}), 404

        limit = min(20, int(request.args.get('limit', 5)))
        traces = database.get_device_traceroutes(device_id, limit=limit, user_id=user_id)
        for t in traces:
            try:
                t['hops'] = json.loads(t['hops_json']) if isinstance(t.get('hops_json'), str) else t.get('hops_json', [])
            except Exception:
                t['hops'] = []
        return jsonify({'success': True, 'traceroutes': traces})

    @app.route('/api/settings/test-email', methods=['POST'])
    @login_required
    def api_test_email():
        """Sends an immediate diagnostic test email and returns delivery feedback."""
        if not validate_csrf_token():
            return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400

        data = request.get_json() if request.is_json else request.form
        recipient = data.get('recipient_email', '').strip() if data else ''
        if not recipient:
            current_settings = database.get_settings()
            recipient_field = current_settings.get('alert_recipient_email', '')
            recipient = recipient_field.split(',')[0].strip() if recipient_field else ''

        if not recipient:
            return jsonify({'success': False, 'error': 'Please provide an alert recipient email address.'}), 400

        ok, msg = notifications.send_test_email(recipient_email=recipient)
        status_code = 200 if ok else 400
        return jsonify({'success': ok, 'message': msg}), status_code

    @app.route('/api/incidents/<incident_id>')
    @login_required
    def api_incident_details(incident_id):
        """Returns full diagnostic evidence and notification history for an incident."""
        user_id = session.get('user_id')
        incident = database.get_incident_by_id(incident_id, user_id=user_id)
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404

        incident['fault_localization'] = fault_diagnosis.get_localization_for_incident(incident)
        notifications_log = database.get_notification_history(incident_id=incident.get('id'), limit=20)
        return jsonify({
            'success': True,
            'incident': incident,
            'notifications': notifications_log
        })

    @app.route('/api/incidents')
    @login_required
    def api_incidents_list():
        """Returns paginated incidents list for user's devices."""
        user_id = session.get('user_id')
        dev_id = request.args.get('device_id', '').strip() or None
        status = request.args.get('status', 'ALL').strip()
        severity = request.args.get('severity', 'ALL').strip()
        page = max(1, int(request.args.get('page', 1)))

        incidents = database.get_incidents(
            device_id=dev_id,
            status=status,
            severity=severity,
            user_id=user_id,
            page=page,
            per_page=20
        )
        total = database.get_incident_count(
            device_id=dev_id,
            status=status,
            severity=severity,
            user_id=user_id
        )
        return jsonify({
            'success': True,
            'incidents': incidents,
            'total': total,
            'page': page
        })


    # -------------------------------------------------------------------------
    # Error Handlers
    # -------------------------------------------------------------------------

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal Server Error: {error}")
        return render_template('500.html'), 500

    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    print("=" * 65)
    print(" AUTOMATED FAULT DETECTION SYSTEM (AFDS)")
    print(" Powered by Supabase PostgreSQL Database & Supabase Auth")
    print(f" Web Interface: http://{host}:{port}")
    print("=" * 65)
    app.run(host=host, port=port, debug=False)
