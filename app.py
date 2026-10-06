"""
NetFault – Automated Network Fault Detection and Monitoring System
Main Flask Application.
Provides Web Dashboard routes and REST API endpoints.
"""

import re
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from config import Config
import database
from monitor import (
    background_monitor,
    monitor_device_by_id,
    monitor_all_devices
)

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database schema at startup
database.init_db()

# Start background monitoring daemon thread
background_monitor.start()


# ==========================================
# VALIDATION HELPERS
# ==========================================

def validate_device_input(device_name, ip_address, tcp_port_str):
    """
    Validates device fields according to requirements:
    - Device name must not be empty.
    - IP/Hostname must not be empty.
    - TCP Port, if provided, must be between 1 and 65535.
    Returns (is_valid, error_message, parsed_port)
    """
    if not device_name or not device_name.strip():
        return False, "Device name cannot be empty.", None

    if not ip_address or not ip_address.strip():
        return False, "IP address or Hostname cannot be empty.", None

    parsed_port = None
    if tcp_port_str is not None and str(tcp_port_str).strip() != "":
        try:
            parsed_port = int(str(tcp_port_str).strip())
            if parsed_port < 1 or parsed_port > 65535:
                return False, "TCP port must be between 1 and 65535.", None
        except ValueError:
            return False, "TCP port must be a valid number between 1 and 65535.", None

    return True, None, parsed_port


# ==========================================
# WEB PAGE ROUTES (FRONTEND)
# ==========================================

@app.route("/")
def dashboard():
    """
    Main Administrator Dashboard.
    Displays summary cards, active devices table, and real-time statuses.
    """
    stats = database.get_dashboard_stats()
    devices = database.get_all_devices_with_latest_status()
    return render_template(
        "dashboard.html",
        stats=stats,
        devices=devices,
        auto_interval=background_monitor.interval,
        auto_enabled=background_monitor.enabled
    )


@app.route("/devices")
def devices_page():
    """
    Device Management Page.
    Lists all devices with options to add, edit, delete, and manually probe.
    """
    devices = database.get_all_devices_with_latest_status()
    return render_template("devices.html", devices=devices)


@app.route("/devices/add", methods=["GET", "POST"])
def add_device_page():
    """
    Form page for registering a new network device.
    Supports standard POST form submission as well as presets.
    """
    if request.method == "POST":
        device_name = request.form.get("device_name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        tcp_port_str = request.form.get("tcp_port", "").strip()
        description = request.form.get("description", "").strip()

        is_valid, err_msg, port = validate_device_input(device_name, ip_address, tcp_port_str)
        if not is_valid:
            flash(err_msg, "danger")
            return render_template("add_device.html", form=request.form)

        try:
            device_id = database.add_device(device_name, ip_address, port, description)
            # Perform initial probe immediately so device has an initial status
            monitor_device_by_id(device_id)
            flash(f"Device '{device_name}' added and initial health check performed!", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            flash(f"Error saving device: {str(e)}", "danger")
            return render_template("add_device.html", form=request.form)

    return render_template("add_device.html", form={})


@app.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
def edit_device_page(device_id):
    """
    Form page for editing an existing network device.
    """
    device = database.get_device_by_id(device_id)
    if not device:
        flash("Device not found.", "warning")
        return redirect(url_for("devices_page"))

    if request.method == "POST":
        device_name = request.form.get("device_name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        tcp_port_str = request.form.get("tcp_port", "").strip()
        description = request.form.get("description", "").strip()

        is_valid, err_msg, port = validate_device_input(device_name, ip_address, tcp_port_str)
        if not is_valid:
            flash(err_msg, "danger")
            return render_template("add_device.html", form=request.form, is_edit=True, device=device)

        try:
            database.update_device(device_id, device_name, ip_address, port, description)
            # Re-check device with updated settings
            monitor_device_by_id(device_id)
            flash(f"Device '{device_name}' updated successfully!", "success")
            return redirect(url_for("devices_page"))
        except Exception as e:
            flash(f"Error updating device: {str(e)}", "danger")
            return render_template("add_device.html", form=request.form, is_edit=True, device=device)

    return render_template("add_device.html", form=device, is_edit=True, device=device)


@app.route("/history")
def history_page():
    """
    Monitoring History Page.
    Displays timestamped monitoring records with device & status filters.
    """
    device_id = request.args.get("device_id", type=int)
    status_filter = request.args.get("status", type=str)
    
    devices = database.get_all_devices()
    history = database.get_monitoring_history(device_id=device_id, status=status_filter, limit=200)
    
    return render_template(
        "history.html",
        history=history,
        devices=devices,
        selected_device=device_id,
        selected_status=status_filter
    )


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """
    Returns summary stats and all devices with their latest status.
    Consumed by dashboard JavaScript for live auto-updating.
    """
    stats = database.get_dashboard_stats()
    devices = database.get_all_devices_with_latest_status()
    return jsonify({
        "success": True,
        "stats": stats,
        "devices": devices,
        "auto_monitor": {
            "enabled": background_monitor.enabled,
            "interval": background_monitor.interval,
            "last_run": background_monitor.last_run_time
        }
    })


@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    """Returns all registered devices."""
    devices = database.get_all_devices_with_latest_status()
    return jsonify({"success": True, "devices": devices})


@app.route("/api/devices", methods=["POST"])
def api_add_device():
    """Adds a new device via JSON API."""
    data = request.get_json(silent=True) or request.form
    device_name = data.get("device_name", "")
    ip_address = data.get("ip_address", "")
    tcp_port_str = data.get("tcp_port", None)
    description = data.get("description", "")

    is_valid, err_msg, port = validate_device_input(device_name, ip_address, tcp_port_str)
    if not is_valid:
        return jsonify({"success": False, "error": err_msg}), 400

    try:
        device_id = database.add_device(device_name, ip_address, port, description)
        check_res = monitor_device_by_id(device_id)
        return jsonify({
            "success": True,
            "message": "Device added successfully.",
            "device_id": device_id,
            "initial_status": check_res
        }), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/devices/<int:device_id>", methods=["GET"])
def api_get_device(device_id):
    """Returns a single device by ID."""
    device = database.get_device_by_id(device_id)
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
    return jsonify({"success": True, "device": device})


@app.route("/api/devices/<int:device_id>", methods=["PUT", "POST"])
def api_update_device(device_id):
    """Updates device details by ID."""
    device = database.get_device_by_id(device_id)
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    data = request.get_json(silent=True) or request.form
    device_name = data.get("device_name", device["device_name"])
    ip_address = data.get("ip_address", device["ip_address"])
    tcp_port_str = data.get("tcp_port", device["tcp_port"])
    description = data.get("description", device["description"])

    is_valid, err_msg, port = validate_device_input(device_name, ip_address, tcp_port_str)
    if not is_valid:
        return jsonify({"success": False, "error": err_msg}), 400

    try:
        database.update_device(device_id, device_name, ip_address, port, description)
        check_res = monitor_device_by_id(device_id)
        return jsonify({
            "success": True,
            "message": "Device updated successfully.",
            "updated_status": check_res
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
@app.route("/api/devices/<int:device_id>/delete", methods=["POST"])
def api_delete_device(device_id):
    """Deletes a device and its history."""
    device = database.get_device_by_id(device_id)
    if not device:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"success": False, "error": "Device not found"}), 404
        flash("Device not found.", "warning")
        return redirect(url_for("devices_page"))

    database.delete_device(device_id)
    
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.method == "DELETE":
        return jsonify({"success": True, "message": "Device deleted successfully."})
        
    flash(f"Device '{device['device_name']}' deleted successfully.", "info")
    return redirect(url_for("devices_page"))


@app.route("/api/devices/<int:device_id>/check", methods=["POST"])
def api_check_single_device(device_id):
    """
    Manually checks a single device immediately.
    Runs Ping and TCP checks, records result in SQLite, and returns JSON.
    """
    result = monitor_device_by_id(device_id)
    if not result:
        return jsonify({"success": False, "error": "Device not found"}), 404

    return jsonify({
        "success": True,
        "message": f"Device checked: {result['status']}",
        "result": result
    })


@app.route("/api/monitor", methods=["POST"])
def api_monitor_all():
    """
    Manually triggers monitoring check for all registered devices.
    Returns list of evaluated results and fresh summary stats.
    """
    results = monitor_all_devices()
    stats = database.get_dashboard_stats()
    return jsonify({
        "success": True,
        "message": f"Monitored {len(results)} devices successfully.",
        "results": results,
        "stats": stats
    })


@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Returns monitoring history records with optional filters."""
    device_id = request.args.get("device_id", type=int)
    status_filter = request.args.get("status", type=str)
    limit = request.args.get("limit", default=100, type=int)

    history = database.get_monitoring_history(device_id=device_id, status=status_filter, limit=limit)
    return jsonify({"success": True, "count": len(history), "history": history})


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears history logs."""
    device_id = request.args.get("device_id", type=int)
    deleted_count = database.clear_monitoring_history(device_id=device_id)
    return jsonify({
        "success": True,
        "message": f"Cleared {deleted_count} history records."
    })


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """Gets or updates auto-monitoring interval and active state."""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        interval = data.get("interval")
        enabled = data.get("enabled")

        if interval is not None:
            try:
                interval_int = int(interval)
                if interval_int >= 5:
                    background_monitor.set_interval(interval_int)
                else:
                    return jsonify({"success": False, "error": "Interval must be at least 5 seconds"}), 400
            except ValueError:
                return jsonify({"success": False, "error": "Invalid interval value"}), 400

        if enabled is not None:
            if isinstance(enabled, str):
                enabled = enabled.lower() in ["true", "1", "yes", "on"]
            background_monitor.toggle(bool(enabled))

        return jsonify({
            "success": True,
            "message": "Settings updated",
            "interval": background_monitor.interval,
            "enabled": background_monitor.enabled
        })

    return jsonify({
        "success": True,
        "interval": background_monitor.interval,
        "enabled": background_monitor.enabled,
        "last_run": background_monitor.last_run_time
    })


if __name__ == "__main__":
    # Ensure tables are ready
    database.init_db()
    print("=" * 60)
    print("NetFault – Automated Network Fault Detection & Monitoring System")
    print("Starting Flask web server on http://127.0.0.1:5000 ...")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
