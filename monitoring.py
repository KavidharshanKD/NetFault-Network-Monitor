"""
Network Monitoring Module for Automated Fault Detection System.
Provides ICMP/Ping reachability checks, TCP socket port connectivity checks,
strict IP/port validation, response time measurement, and status classification (UP/DOWN/FAULT).
"""

import os
import re
import socket
import platform
import subprocess
import time
import ipaddress
import logging
from config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------

def validate_ip_address(ip_str):
    """
    Validates IPv4 or IPv6 address strings.
    Returns (is_valid: bool, error_message: str or None, ip_obj: IPv4Address/IPv6Address or None)
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP address cannot be empty.", None

    ip_clean = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return True, None, ip_obj
    except ValueError:
        return False, f"'{ip_clean}' is not a valid IPv4 or IPv6 address.", None

def validate_port(port_val):
    """
    Validates TCP port numbers (1 - 65535 or None/empty).
    Returns (is_valid: bool, error_message: str or None, port_int: int or None)
    """
    if port_val is None or port_val == '':
        return True, None, None

    try:
        p = int(port_val)
        if 1 <= p <= 65535:
            return True, None, p
        return False, "Port must be an integer between 1 and 65535.", None
    except (ValueError, TypeError):
        return False, "Port must be an integer between 1 and 65535.", None

# ---------------------------------------------------------
# ICMP / Ping Reachability Check
# ---------------------------------------------------------

def ping_host(ip_address, count=None, timeout_sec=None):
    """
    Executes an OS-native ping command without shell interpolation.
    Supports Windows, Linux, and macOS.
    Returns:
        (is_reachable: bool, rtt_ms: float or None, fault_reason: str or None)
    """
    is_valid, err, ip_obj = validate_ip_address(ip_address)
    if not is_valid:
        return False, None, f"Invalid IP address: {err}"

    target_ip = str(ip_obj)
    count = count or Config.DEFAULT_PING_COUNT
    timeout_sec = timeout_sec or Config.DEFAULT_PING_TIMEOUT

    system = platform.system().lower()

    if system == 'windows':
        # Windows ping: -n count, -w timeout_in_milliseconds
        timeout_ms = int(timeout_sec * 1000)
        cmd = ['ping', '-n', str(count), '-w', str(timeout_ms), target_ip]
    else:
        # Linux/macOS ping: -c count, -W timeout_in_seconds
        cmd = ['ping', '-c', str(count), '-W', str(int(timeout_sec)), target_ip]

    proc_timeout = (count * timeout_sec) + 4

    start_exec = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=proc_timeout
        )
        elapsed_total_ms = round((time.perf_counter() - start_exec) * 1000, 2)
    except subprocess.TimeoutExpired:
        return False, None, f"Ping execution timed out after {proc_timeout}s"
    except FileNotFoundError:
        return False, None, "Ping utility not found on host system"
    except Exception as e:
        logger.error(f"Unexpected error running ping for {target_ip}: {e}")
        return False, None, f"Error executing ping: {str(e)}"

    stdout = result.stdout
    stderr = result.stderr

    # Parse Windows ping output
    if system == 'windows':
        # Check for destination host unreachable
        if "Destination host unreachable" in stdout:
            return False, None, "Destination host unreachable"
        if "Request timed out" in stdout and "Reply from" not in stdout:
            return False, None, "ICMP request timed out (packet loss 100%)"
        if "General failure" in stdout:
            return False, None, "Ping general failure (network interface or route error)"

        # Check for successful replies
        if "Reply from" in stdout:
            # Try to extract Average = XXms
            avg_match = re.search(r"Average\s*=\s*(\d+)ms", stdout, re.IGNORECASE)
            if avg_match:
                avg_val = float(avg_match.group(1))
                if avg_val == 0.0 and ("<1ms" in stdout or "time<1ms" in stdout):
                    avg_val = 0.5  # Sub-millisecond response
                return True, avg_val, None

            # Or single reply time
            time_match = re.search(r"time[=<]([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)
            if time_match:
                rtt = float(time_match.group(1))
                if ("<" in stdout or rtt == 0) and ("<1ms" in stdout or "time<1ms" in stdout):
                    rtt = 0.5  # Sub-millisecond response
                return True, rtt, None

            # Fallback to total elapsed time per count if time is missing
            fallback_rtt = round(elapsed_total_ms / max(1, count), 2)
            return True, fallback_rtt, None

        if result.returncode != 0:
            return False, None, "No ICMP echo reply received"

    # Parse Linux / Unix ping output
    else:
        if "100% packet loss" in stdout or "100.0% packet loss" in stdout:
            return False, None, "ICMP request timed out (100% packet loss)"

        # Search for rtt min/avg/max/mdev = 0.040/0.052/0.065/0.010 ms
        rtt_match = re.search(r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*[\d\.]+/([\d\.]+)/", stdout, re.IGNORECASE)
        if rtt_match:
            return True, float(rtt_match.group(1)), None

        # Search for time=XX.X ms
        time_match = re.search(r"time=([0-9]+(?:\.[0-9]+)?)\s*ms", stdout, re.IGNORECASE)
        if time_match:
            return True, float(time_match.group(1)), None

        if result.returncode == 0:
            fallback_rtt = round(elapsed_total_ms / max(1, count), 2)
            return True, fallback_rtt, None

        return False, None, "No ICMP response received"

    return False, None, "Host did not respond to ICMP ping"

# ---------------------------------------------------------
# TCP Socket Port Monitoring
# ---------------------------------------------------------

def check_tcp_port(ip_address, port, timeout_sec=None):
    """
    Checks TCP port connectivity using real socket programming.
    Returns:
        (is_open: bool, connect_time_ms: float or None, fault_reason: str or None)
    """
    is_valid_ip, ip_err, ip_obj = validate_ip_address(ip_address)
    if not is_valid_ip:
        return False, None, f"Invalid IP address: {ip_err}"

    is_valid_port, port_err, port_int = validate_port(port)
    if not is_valid_port or port_int is None:
        return False, None, f"Invalid TCP port: {port_err or 'Port required'}"

    timeout_sec = timeout_sec or Config.DEFAULT_TCP_TIMEOUT
    family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    target_ip = str(ip_obj)

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)

    start_time = time.perf_counter()
    try:
        sock.connect((target_ip, port_int))
        connect_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return True, connect_time_ms, None
    except socket.timeout:
        return False, None, f"TCP connection timed out on port {port_int} after {timeout_sec}s"
    except ConnectionRefusedError:
        return False, None, f"TCP connection actively refused on port {port_int} (service down or blocked)"
    except OSError as e:
        err_msg = os.strerror(e.errno) if hasattr(e, 'errno') and e.errno else str(e)
        return False, None, f"TCP socket connection failed on port {port_int}: {err_msg}"
    except Exception as e:
        logger.error(f"Unexpected TCP socket error for {target_ip}:{port_int}: {e}")
        return False, None, f"Unexpected TCP connection error on port {port_int}: {str(e)}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

# ---------------------------------------------------------
# Master Device Check & Status Classification
# ---------------------------------------------------------

def check_device_connectivity(device, settings=None):
    """
    Performs full monitoring check on a device dictionary:
    1. Runs ICMP Ping check.
    2. Runs TCP port check if a port is configured.
    3. Classifies overall status as UP, DOWN, or FAULT according to specifications:
       - UP:
         * Device reachable via ICMP and configured TCP port open.
         * Device reachable via ICMP and no TCP port configured.
         * ICMP blocked/filtered by firewall, but TCP port connects successfully.
       - DOWN:
         * Device unreachable via ICMP and TCP port unavailable / not configured.
       - FAULT:
         * Device reachable via ICMP, but configured TCP port connection is refused, closed, or timed out.
    4. Measures accurate response time (documenting Ping RTT or TCP Connect time).
    5. Returns formatted result dictionary.
    """
    settings = settings or {}
    ping_timeout = settings.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT)
    tcp_timeout = settings.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT)
    ping_count = settings.get('ping_count', Config.DEFAULT_PING_COUNT)

    device_id = device['id']
    ip = device['ip_address']
    port = device.get('port')

    # Step 1: Reachability check (ICMP Ping)
    ping_reachable, ping_rtt, ping_fault = ping_host(ip, count=ping_count, timeout_sec=ping_timeout)

    reachability_status = "REACHABLE" if ping_reachable else "UNREACHABLE"

    # Step 2: TCP Port check (if port configured)
    has_port = port is not None and str(port).strip() != ''
    tcp_open = False
    tcp_connect_time = None
    tcp_fault = None
    service_status = "NOT_CHECKED"

    if has_port:
        tcp_open, tcp_connect_time, tcp_fault = check_tcp_port(ip, port, timeout_sec=tcp_timeout)
        if tcp_open:
            service_status = "OPEN"
        else:
            if "timed out" in (tcp_fault or "").lower():
                service_status = "TIMEOUT"
            elif "refused" in (tcp_fault or "").lower():
                service_status = "REFUSED"
            else:
                service_status = "CLOSED"

    # Step 3: Status Classification
    overall_status = "DOWN"
    response_time_ms = None
    fault_details = None

    if not has_port:
        # Reachability only
        if ping_reachable:
            overall_status = "UP"
            response_time_ms = ping_rtt
            fault_details = "Device reachable via ICMP (TCP service not configured)"
        else:
            overall_status = "DOWN"
            response_time_ms = None
            fault_details = ping_fault or "ICMP reachability check failed"
    else:
        # Port configured
        if ping_reachable and tcp_open:
            overall_status = "UP"
            # Connection establishment time for TCP service
            response_time_ms = tcp_connect_time
            fault_details = f"Reachable via ICMP ({ping_rtt}ms RTT); TCP port {port} open ({tcp_connect_time}ms connect)"
        elif ping_reachable and not tcp_open:
            # Device is alive, but service failed -> FAULT!
            overall_status = "FAULT"
            # Document ping RTT because host responded, but service is broken
            response_time_ms = ping_rtt
            fault_details = f"Host reachable via ICMP ({ping_rtt}ms), but TCP port {port} failed: {tcp_fault}"
        elif not ping_reachable and tcp_open:
            # ICMP blocked by host/firewall policy, but TCP port works!
            overall_status = "UP"
            reachability_status = "ICMP_FILTERED"
            response_time_ms = tcp_connect_time
            fault_details = f"ICMP ping filtered/blocked, but TCP port {port} is active ({tcp_connect_time}ms connect)"
        else:
            # Neither responded
            overall_status = "DOWN"
            response_time_ms = None
            fault_details = f"Host unreachable via ICMP ({ping_fault or 'timed out'}) and TCP port {port} unavailable ({tcp_fault or 'timed out'})"

    return {
        'device_id': device_id,
        'reachability_status': reachability_status,
        'service_status': service_status,
        'overall_status': overall_status,
        'response_time_ms': response_time_ms,
        'fault_details': fault_details
    }
