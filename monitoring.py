"""
Network Monitoring Module for Automated Fault Detection System.
Provides ICMP/Ping reachability checks, TCP socket port connectivity checks,
strict IP/port validation, response time measurement, and deterministic status classification.

Classification Taxonomy:
- UP:
    * Ping OK and TCP port Open (if configured).
    * Ping OK and No TCP port configured.
    * Ping Blocked/Filtered by firewall, but configured TCP port Open.
- FAULT:
    * Ping OK (Layer 3 reachable), but configured TCP port Refused or Timed Out (Layer 4/7 issue).
- DOWN:
    * Ping Failed and TCP Failed (or no port configured).
- UNKNOWN:
    * Prior to execution or internal inspection failure.
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
    if port_val is None or str(port_val).strip() == '':
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
        (is_reachable: bool, rtt_ms: float or None, fault_category: str or None, fault_reason: str or None)
    """
    is_valid, err, ip_obj = validate_ip_address(ip_address)
    if not is_valid:
        return False, None, "INVALID_ADDRESS", f"Invalid IP address: {err}"

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
        return False, None, "NETWORK_TIMEOUT", f"Ping execution timed out after {proc_timeout}s"
    except FileNotFoundError:
        return False, None, "SYSTEM_ERROR", "Ping utility not found on host system"
    except Exception as e:
        logger.error(f"Unexpected error running ping for {target_ip}: {e}")
        return False, None, "GENERAL_FAILURE", f"Error executing ping: {str(e)}"

    stdout = result.stdout or ""

    # Parse Windows ping output
    if system == 'windows':
        if "Destination host unreachable" in stdout:
            return False, None, "HOST_UNREACHABLE", "Destination host unreachable"
        if "Request timed out" in stdout and "Reply from" not in stdout:
            return False, None, "NETWORK_TIMEOUT", "ICMP request timed out (packet loss 100%)"
        if "General failure" in stdout:
            return False, None, "GENERAL_FAILURE", "Ping general failure (network interface or routing error)"

        if "Reply from" in stdout:
            # Extract Average = XXms
            avg_match = re.search(r"Average\s*=\s*(\d+)ms", stdout, re.IGNORECASE)
            if avg_match:
                avg_val = float(avg_match.group(1))
                if avg_val == 0.0 and ("<1ms" in stdout or "time<1ms" in stdout):
                    avg_val = 0.5
                return True, avg_val, "NONE", None

            # Extract time=XXms
            time_match = re.search(r"time[=<]([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)
            if time_match:
                rtt = float(time_match.group(1))
                if ("<" in stdout or rtt == 0) and ("<1ms" in stdout or "time<1ms" in stdout):
                    rtt = 0.5
                return True, rtt, "NONE", None

            fallback_rtt = round(elapsed_total_ms / max(1, count), 2)
            return True, fallback_rtt, "NONE", None

        if result.returncode != 0:
            return False, None, "HOST_UNREACHABLE", "No ICMP echo reply received"

    # Parse Linux / macOS ping output
    else:
        if "100% packet loss" in stdout or "100.0% packet loss" in stdout:
            return False, None, "NETWORK_TIMEOUT", "ICMP request timed out (100% packet loss)"

        rtt_match = re.search(r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*[\d\.]+/([\d\.]+)/", stdout, re.IGNORECASE)
        if rtt_match:
            return True, float(rtt_match.group(1)), "NONE", None

        time_match = re.search(r"time=([0-9]+(?:\.[0-9]+)?)\s*ms", stdout, re.IGNORECASE)
        if time_match:
            return True, float(time_match.group(1)), "NONE", None

        if result.returncode == 0:
            fallback_rtt = round(elapsed_total_ms / max(1, count), 2)
            return True, fallback_rtt, "NONE", None

        return False, None, "HOST_UNREACHABLE", "No ICMP response received"

    return False, None, "HOST_UNREACHABLE", "Host did not respond to ICMP ping"

# ---------------------------------------------------------
# TCP Socket Port Monitoring
# ---------------------------------------------------------

def check_tcp_port(ip_address, port, timeout_sec=None):
    """
    Checks TCP port connectivity using real socket programming.
    Returns:
        (is_open: bool, connect_time_ms: float or None, fault_category: str or None, fault_reason: str or None)
    """
    is_valid_ip, ip_err, ip_obj = validate_ip_address(ip_address)
    if not is_valid_ip:
        return False, None, "INVALID_ADDRESS", f"Invalid IP address: {ip_err}"

    is_valid_port, port_err, port_int = validate_port(port)
    if not is_valid_port or port_int is None:
        return False, None, "INVALID_PORT", f"Invalid TCP port: {port_err or 'Port required'}"

    timeout_sec = timeout_sec or Config.DEFAULT_TCP_TIMEOUT
    family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    target_ip = str(ip_obj)

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)

    start_time = time.perf_counter()
    try:
        sock.connect((target_ip, port_int))
        connect_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return True, connect_time_ms, "NONE", None
    except socket.timeout:
        return False, None, "SERVICE_TIMEOUT", f"TCP connection timed out on port {port_int} after {timeout_sec}s"
    except ConnectionRefusedError:
        return False, None, "SERVICE_REFUSED", f"TCP connection actively refused on port {port_int} (service down or blocked)"
    except OSError as e:
        err_msg = os.strerror(e.errno) if hasattr(e, 'errno') and e.errno else str(e)
        return False, None, "SOCKET_ERROR", f"TCP socket error on port {port_int}: {err_msg}"
    except Exception as e:
        logger.error(f"Unexpected TCP socket error for {target_ip}:{port_int}: {e}")
        return False, None, "GENERAL_FAILURE", f"Unexpected TCP error on port {port_int}: {str(e)}"
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
    3. Classifies overall status as UP, DOWN, or FAULT:
       - UP:
         * Ping OK and TCP port Open (if configured).
         * Ping OK and No port configured.
         * Ping Blocked/Filtered, but TCP port Open.
       - FAULT:
         * Host responds to ping, but configured TCP port is refused, closed, or timed out.
       - DOWN:
         * Host fails ping AND configured TCP fails (or no port configured).
    4. Measures accurate response time (excluding failed values).
    5. Returns dictionary with category, details, statuses, and latency.
    """
    settings = settings or {}
    ping_timeout = settings.get('ping_timeout', Config.DEFAULT_PING_TIMEOUT)
    tcp_timeout = settings.get('tcp_timeout', Config.DEFAULT_TCP_TIMEOUT)
    ping_count = settings.get('ping_count', Config.DEFAULT_PING_COUNT)

    device_id = device['id']
    ip = device['ip_address']
    port = device.get('port')

    # Step 1: Reachability check (ICMP Ping)
    ping_reachable, ping_rtt, ping_cat, ping_fault = ping_host(ip, count=ping_count, timeout_sec=ping_timeout)
    reachability_status = "REACHABLE" if ping_reachable else "UNREACHABLE"

    # Step 2: TCP Port check (if port configured)
    has_port = port is not None and str(port).strip() != ''
    tcp_open = False
    tcp_connect_time = None
    tcp_cat = None
    tcp_fault = None
    service_status = "NOT_CONFIGURED" if not has_port else "NOT_CHECKED"

    if has_port:
        tcp_open, tcp_connect_time, tcp_cat, tcp_fault = check_tcp_port(ip, port, timeout_sec=tcp_timeout)
        if tcp_open:
            service_status = "OPEN"
        else:
            if tcp_cat == "SERVICE_TIMEOUT":
                service_status = "TIMEOUT"
            elif tcp_cat == "SERVICE_REFUSED":
                service_status = "REFUSED"
            else:
                service_status = "CLOSED"

    # Step 3: Status Classification
    overall_status = "DOWN"
    response_time_ms = None
    fault_category = "NONE"
    fault_details = None

    if not has_port:
        if ping_reachable:
            overall_status = "UP"
            response_time_ms = ping_rtt
            fault_category = "NONE"
            fault_details = "Device reachable via ICMP (TCP service not configured)"
        else:
            overall_status = "DOWN"
            response_time_ms = None
            fault_category = ping_cat or "HOST_UNREACHABLE"
            fault_details = ping_fault or "ICMP reachability check failed"
    else:
        if ping_reachable and tcp_open:
            overall_status = "UP"
            response_time_ms = tcp_connect_time
            fault_category = "NONE"
            fault_details = f"Reachable via ICMP ({ping_rtt}ms RTT); TCP port {port} open ({tcp_connect_time}ms connect)"
        elif ping_reachable and not tcp_open:
            overall_status = "FAULT"
            response_time_ms = ping_rtt
            fault_category = tcp_cat or "SERVICE_REFUSED"
            fault_details = f"Host reachable via ICMP ({ping_rtt}ms), but TCP port {port} failed: {tcp_fault}"
        elif not ping_reachable and tcp_open:
            overall_status = "UP"
            reachability_status = "ICMP_FILTERED"
            response_time_ms = tcp_connect_time
            fault_category = "FIREWALL_FILTERED"
            fault_details = f"ICMP ping filtered/blocked, but TCP port {port} is active ({tcp_connect_time}ms connect)"
        else:
            overall_status = "DOWN"
            response_time_ms = None
            fault_category = ping_cat or "HOST_UNREACHABLE"
            fault_details = f"Host unreachable via ICMP ({ping_fault or 'timed out'}) and TCP port {port} unavailable ({tcp_fault or 'timed out'})"

    return {
        'device_id': device_id,
        'reachability_status': reachability_status,
        'service_status': service_status,
        'overall_status': overall_status,
        'response_time_ms': response_time_ms,
        'fault_category': fault_category,
        'fault_details': fault_details
    }
