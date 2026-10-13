"""
Automated Fault Detection System - Flask Web Application.
Provides dashboard, device administration, history records, fault diagnostics,
real-time API triggers, and configuration controls.
"""

import os
import sys
import secrets
import hmac
import logging
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify,
    session, Response, abort
)
from config import Config
import database
import monitoring
from scheduler import scheduler
import services

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

    # Initialize database schemas and default settings
    with app.app_context():
        database.init_db()

    # ---------------------------------------------------------
    # CSRF Protection Helpers
    # ---------------------------------------------------------

    def generate_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']

    def validate_csrf_token():
        if app.config.get('TESTING') or app.config.get('WTF_CSRF_ENABLED') is False:
            return True
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
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
            'last_cycle_time': scheduler.get_last_cycle_time()
        }

    # ---------------------------------------------------------
    # Frontend Page Routes
    # ---------------------------------------------------------

    @app.route('/')
    def dashboard():
        """Central network monitoring dashboard."""
        summary = database.get_dashboard_summary()
        devices = database.get_all_devices()
        recent_faults = database.get_recent_faults(limit=5)
        recent_checks = database.get_recent_checks(limit=6)
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
    def device_list():
        """Device inventory page with search, status filters, sorting, and pagination."""
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', 'ALL').strip()
        sort_by = request.args.get('sort', 'id').strip()
        sort_dir = request.args.get('dir', 'asc').strip()
        page_raw = request.args.get('page', '1').strip()

        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1

        per_page = 10
        total_devices = database.get_devices_count(search=search, status_filter=status_filter)
        total_pages = max(1, (total_devices + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        devices = database.get_all_devices(
            search=search,
            status_filter=status_filter,
            sort_by=sort_by,
            sort_dir=sort_dir,
            page=page,
            per_page=per_page
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
    def add_device():
        """Form and handler for registering a new network device."""
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
                if database.check_duplicate_device(ip_address, port_val):
                    errors.append(f"A device with IP '{ip_address}' and port '{port_val or 'None'}' is already registered.")

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

            dev_id = database.create_device(
                device_name=device_name,
                ip_address=ip_address,
                port=port_val,
                description=description or None,
                monitoring_enabled=monitoring_enabled
            )

            # Perform initial non-blocking check
            scheduler.check_single_device(dev_id)

            flash(f"Device '{device_name}' successfully added and initial check performed.", 'success')
            return redirect(url_for('device_list'))

        return render_template('add_device.html')

    @app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
    def edit_device(device_id):
        """Form and handler for editing an existing device."""
        device = database.get_device_by_id(device_id)
        if not device:
            flash("Device not found.", 'error')
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
                if database.check_duplicate_device(ip_address, port_val, exclude_id=device_id):
                    errors.append(f"Another device already uses IP '{ip_address}' and port '{port_val or 'None'}'.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                return render_template('edit_device.html', device=device), 400

            database.update_device(
                device_id=device_id,
                device_name=device_name,
                ip_address=ip_address,
                port=port_val,
                description=description or None,
                monitoring_enabled=monitoring_enabled
            )

            scheduler.check_single_device(device_id)

            flash(f"Device '{device_name}' updated successfully.", 'success')
            return redirect(url_for('device_details', device_id=device_id))

        return render_template('edit_device.html', device=device)

    @app.route('/devices/<int:device_id>/delete', methods=['POST'])
    def delete_device(device_id):
        """Deletes a device and cascades deletion to monitoring_history."""
        if not validate_csrf_token():
            flash("Security token validation failed.", 'error')
            return redirect(url_for('device_list'))

        device = database.get_device_by_id(device_id)
        if device:
            database.delete_device(device_id)
            flash(f"Device '{device['device_name']}' and its history have been permanently deleted.", 'success')
        else:
            flash("Device not found.", 'error')
        return redirect(url_for('device_list'))

    @app.route('/devices/<int:device_id>/toggle', methods=['POST'])
    def toggle_device(device_id):
        """Toggles monitoring state for a device."""
        if not validate_csrf_token():
            flash("Security token validation failed.", 'error')
            return redirect(url_for('device_list'))

        new_val = database.toggle_device_monitoring(device_id)
        state_str = "enabled" if new_val == 1 else "disabled"
        flash(f"Monitoring {state_str} for device.", 'success')
        return redirect(request.referrer or url_for('device_list'))

    @app.route('/devices/<int:device_id>')
    def device_details(device_id):
        """Detailed view for an individual network device."""
        device = database.get_device_by_id(device_id)
        if not device:
            flash("Device not found.", 'error')
            return redirect(url_for('device_list'))

        history = database.get_device_history(device_id, limit=25)
        timeseries = database.get_history_timeseries(device_id=device_id, limit=15)
        return render_template('device_details.html', device=device, history=history, timeseries=timeseries)

    @app.route('/history')
    def history_view():
        """Chronological monitoring history table with filters and pagination."""
        device_id_raw = request.args.get('device_id', '').strip()
        status_filter = request.args.get('status', 'ALL').strip().upper()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        page_raw = request.args.get('page', '1').strip()

        device_id = int(device_id_raw) if device_id_raw.isdigit() else None
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1

        per_page = 20
        total_records = database.get_history_count(
            device_id=device_id,
            status=status_filter,
            date_from=date_from or None,
            date_to=date_to or None
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
            per_page=per_page
        )
        all_devices = database.get_all_devices()

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
    def faults_view():
        """Fault reports and investigation view."""
        device_id_raw = request.args.get('device_id', '').strip()
        category = request.args.get('category', 'ALL').strip()
        status = request.args.get('status', 'ALL').strip()

        device_id = int(device_id_raw) if device_id_raw.isdigit() else None
        reports = database.get_fault_reports(device_id=device_id, category=category, status=status)
        devices = database.get_all_devices()

        return render_template(
            'faults.html',
            reports=reports,
            devices=devices,
            selected_device_id=device_id,
            selected_category=category,
            selected_status=status
        )

    @app.route('/faults/export')
    def export_faults():
        """Exports filtered fault reports as CSV."""
        device_id_raw = request.args.get('device_id', '').strip()
        category = request.args.get('category', 'ALL').strip()
        status = request.args.get('status', 'ALL').strip()
        device_id = int(device_id_raw) if device_id_raw.isdigit() else None

        csv_data = services.generate_faults_csv(device_id=device_id, category=category, status=status)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=fault_reports.csv"}
        )

    @app.route('/history/export')
    def export_history():
        """Exports filtered monitoring audit log as CSV."""
        device_id_raw = request.args.get('device_id', '').strip()
        status = request.args.get('status', 'ALL').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        device_id = int(device_id_raw) if device_id_raw.isdigit() else None

        csv_data = services.generate_history_csv(
            device_id=device_id,
            status=status,
            date_from=date_from or None,
            date_to=date_to or None
        )
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=monitoring_history.csv"}
        )

    @app.route('/settings', methods=['GET', 'POST'])
    def settings_view():
        """Configuration page for monitoring parameters."""
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

            except (ValueError, TypeError):
                errors.append("All configuration fields must be valid numbers.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                return render_template('settings.html', settings=database.get_settings()), 400

            database.update_settings(
                monitor_interval=monitor_interval,
                ping_timeout=ping_timeout,
                tcp_timeout=tcp_timeout,
                ping_count=ping_count,
                concurrency_limit=concurrency_limit,
                auto_monitoring=auto_monitoring
            )
            flash("Monitoring settings updated successfully and persisted to SQLite.", 'success')
            return redirect(url_for('settings_view'))

        current_settings = database.get_settings()
        return render_template('settings.html', settings=current_settings)

    @app.route('/system')
    def system_view():
        """System Information and architecture diagnostics page."""
        diagnostics = services.get_system_diagnostics(scheduler)
        return render_template('system.html', diag=diagnostics)

    # ---------------------------------------------------------
    # REST / JSON API Endpoints (Asynchronous Dashboard)
    # ---------------------------------------------------------

    @app.route('/api/summary')
    def api_summary():
        """Returns JSON dashboard counts and average response time."""
        return jsonify(database.get_dashboard_summary())

    @app.route('/api/devices')
    def api_devices():
        """Returns JSON array of devices with latest monitoring states."""
        return jsonify(database.get_all_devices())

    @app.route('/api/devices/<int:device_id>/check', methods=['POST'])
    def api_check_device(device_id):
        """Triggers immediate monitoring check for an individual device."""
        device = database.get_device_by_id(device_id)
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        result = scheduler.check_single_device(device_id)
        updated_device = database.get_device_by_id(device_id)
        return jsonify({
            'success': True,
            'result': result,
            'device': updated_device
        })

    @app.route('/api/check-all', methods=['POST'])
    def api_check_all():
        """Triggers immediate monitoring check for all registered devices."""
        results = scheduler.check_all_devices(only_enabled=False)
        summary = database.get_dashboard_summary()
        devices = database.get_all_devices()
        return jsonify({
            'success': True,
            'checked_count': len(results),
            'summary': summary,
            'devices': devices
        })

    @app.route('/api/scheduler/start', methods=['POST'])
    def api_scheduler_start():
        """Starts background periodic monitoring worker."""
        started = scheduler.start()
        return jsonify({
            'success': True,
            'running': scheduler.is_running(),
            'message': 'Background monitoring started.' if started else 'Scheduler is already running.'
        })

    @app.route('/api/scheduler/stop', methods=['POST'])
    def api_scheduler_stop():
        """Stops background periodic monitoring worker."""
        stopped = scheduler.stop()
        return jsonify({
            'success': True,
            'running': scheduler.is_running(),
            'message': 'Background monitoring stopped.' if stopped else 'Scheduler was not running.'
        })

    @app.route('/api/scheduler/status')
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
    def api_history():
        """Returns JSON array of history records."""
        device_id_raw = request.args.get('device_id')
        status = request.args.get('status')
        limit = min(100, int(request.args.get('limit', 20)))
        device_id = int(device_id_raw) if device_id_raw and device_id_raw.isdigit() else None
        records = database.get_all_history(device_id=device_id, status=status, page=1, per_page=limit)
        return jsonify({'success': True, 'records': records})

    @app.route('/api/faults')
    def api_faults():
        """Returns JSON array of active/recent faults."""
        device_id_raw = request.args.get('device_id')
        device_id = int(device_id_raw) if device_id_raw and device_id_raw.isdigit() else None
        reports = database.get_fault_reports(device_id=device_id)
        return jsonify({'success': True, 'faults': reports})

    @app.route('/api/chart/history')
    def api_chart_history():
        """Returns time-series metrics formatted for Chart.js."""
        device_id_raw = request.args.get('device_id')
        device_id = int(device_id_raw) if device_id_raw and device_id_raw.isdigit() else None
        data = database.get_history_timeseries(device_id=device_id, limit=20)
        return jsonify(data)

    # ---------------------------------------------------------
    # Error Handlers
    # ---------------------------------------------------------

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
    print("=" * 65)
    print(" AUTOMATED FAULT DETECTION SYSTEM")
    print(" Computer Networks Monitoring Server")
    print(f" Local URL: http://127.0.0.1:{port}")
    print("=" * 65)
    app.run(host='127.0.0.1', port=port, debug=False)
