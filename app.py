"""
Automated Fault Detection System - Flask Web Application.
Provides dashboard, device administration, history records, real-time API triggers,
and settings controls.
"""

import os
import sys
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from config import Config
import database
import monitoring
from scheduler import scheduler

# Configure local logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE_PATH, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_app():
    """Application factory for Flask."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize database tables and seed defaults
    with app.app_context():
        database.init_db()

    # ---------------------------------------------------------
    # Frontend Page Routes
    # ---------------------------------------------------------

    @app.route('/')
    def dashboard():
        """Central network monitoring dashboard."""
        summary = database.get_dashboard_summary()
        devices = database.get_all_devices()
        scheduler_running = scheduler.is_running()
        last_cycle = scheduler.get_last_cycle_time()
        return render_template(
            'dashboard.html',
            summary=summary,
            devices=devices,
            scheduler_running=scheduler_running,
            last_cycle=last_cycle
        )

    @app.route('/devices')
    def device_list():
        """Device management inventory list."""
        devices = database.get_all_devices()
        return render_template('devices.html', devices=devices)

    @app.route('/devices/add', methods=['GET', 'POST'])
    def add_device():
        """Form and handler for registering a new network device."""
        if request.method == 'POST':
            device_name = request.form.get('device_name', '').strip()
            ip_address = request.form.get('ip_address', '').strip()
            port_raw = request.form.get('port', '').strip()
            description = request.form.get('description', '').strip()

            errors = []

            # Validate name
            if not device_name:
                errors.append("Device name is required.")

            # Validate IP
            is_valid_ip, ip_err, _ = monitoring.validate_ip_address(ip_address)
            if not is_valid_ip:
                errors.append(ip_err)

            # Validate Port (optional)
            is_valid_port, port_err, port_val = monitoring.validate_port(port_raw if port_raw else None)
            if not is_valid_port:
                errors.append(port_err)

            # Check duplicate registration
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
                    description=description
                ), 400

            # Create device
            dev_id = database.create_device(
                device_name=device_name,
                ip_address=ip_address,
                port=port_val,
                description=description or None
            )

            # Automatically run initial connectivity check
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
            device_name = request.form.get('device_name', '').strip()
            ip_address = request.form.get('ip_address', '').strip()
            port_raw = request.form.get('port', '').strip()
            description = request.form.get('description', '').strip()

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
                description=description or None
            )

            # Run re-check with updated parameters
            scheduler.check_single_device(device_id)

            flash(f"Device '{device_name}' updated successfully.", 'success')
            return redirect(url_for('device_details', device_id=device_id))

        return render_template('edit_device.html', device=device)

    @app.route('/devices/<int:device_id>/delete', methods=['POST'])
    def delete_device(device_id):
        """Deletes a device and related monitoring history."""
        device = database.get_device_by_id(device_id)
        if device:
            database.delete_device(device_id)
            flash(f"Device '{device['device_name']}' and its history have been permanently deleted.", 'success')
        else:
            flash("Device not found.", 'error')
        return redirect(url_for('device_list'))

    @app.route('/devices/<int:device_id>')
    def device_details(device_id):
        """Detailed view for an individual network device."""
        device = database.get_device_by_id(device_id)
        if not device:
            flash("Device not found.", 'error')
            return redirect(url_for('device_list'))

        history = database.get_device_history(device_id, limit=25)
        return render_template('device_details.html', device=device, history=history)

    @app.route('/history')
    def history_view():
        """Chronological monitoring history table with filters and pagination."""
        device_id_raw = request.args.get('device_id', '').strip()
        status_filter = request.args.get('status', 'ALL').strip().upper()
        page_raw = request.args.get('page', '1').strip()

        device_id = int(device_id_raw) if device_id_raw.isdigit() else None
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1

        per_page = 20
        total_records = database.get_history_count(device_id=device_id, status=status_filter)
        total_pages = max(1, (total_records + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        history_records = database.get_all_history(
            device_id=device_id,
            status=status_filter,
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
            page=page,
            total_pages=total_pages,
            total_records=total_records
        )

    @app.route('/settings', methods=['GET', 'POST'])
    def settings_view():
        """Configuration page for monitoring parameters."""
        if request.method == 'POST':
            errors = []
            try:
                monitor_interval = int(request.form.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL))
                ping_timeout = int(request.form.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT))
                tcp_timeout = int(request.form.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT))
                ping_count = int(request.form.get('ping_count', Config.DEFAULT_PING_COUNT))

                if not (Config.MIN_MONITOR_INTERVAL <= monitor_interval <= Config.MAX_MONITOR_INTERVAL):
                    errors.append(f"Monitoring interval must be between {Config.MIN_MONITOR_INTERVAL} and {Config.MAX_MONITOR_INTERVAL} seconds.")

                if not (Config.MIN_PING_TIMEOUT <= ping_timeout <= Config.MAX_PING_TIMEOUT):
                    errors.append(f"Ping timeout must be between {Config.MIN_PING_TIMEOUT} and {Config.MAX_PING_TIMEOUT} seconds.")

                if not (Config.MIN_TCP_TIMEOUT <= tcp_timeout <= Config.MAX_TCP_TIMEOUT):
                    errors.append(f"TCP timeout must be between {Config.MIN_TCP_TIMEOUT} and {Config.MAX_TCP_TIMEOUT} seconds.")

                if not (Config.MIN_PING_COUNT <= ping_count <= Config.MAX_PING_COUNT):
                    errors.append(f"Ping attempts count must be between {Config.MIN_PING_COUNT} and {Config.MAX_PING_COUNT}.")

            except (ValueError, TypeError):
                errors.append("All settings must be valid integer numbers.")

            if errors:
                for err in errors:
                    flash(err, 'error')
                current_settings = database.get_settings()
                return render_template('settings.html', settings=current_settings), 400

            database.update_settings(monitor_interval, ping_timeout, tcp_timeout, ping_count)
            flash("Monitoring settings updated successfully and applied to subsequent cycles.", 'success')
            return redirect(url_for('settings_view'))

        current_settings = database.get_settings()
        return render_template('settings.html', settings=current_settings)

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
        results = scheduler.check_all_devices()
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
            'interval': settings.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL)
        })

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
    # Print clean local application URL
    print("=" * 65)
    print(" AUTOMATED FAULT DETECTION SYSTEM")
    print(" Computer Networks Monitoring Server")
    print(" Local URL: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False)
