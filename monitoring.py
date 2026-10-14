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
from datetime import datetime, timezone
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
# ICMP / Ping Reachability & Packet Loss Measurement
# ---------------------------------------------------------

def get_packet_loss_band(loss_pct, warning_threshold=5.0, critical_threshold=10.0):
    """
    Returns (band_key, band_label, badge_class) based on configurable display bands:
      - 0%: No observed packet loss.
      - >0% and <5%: Low packet loss.
      - 5% to <10%: Moderate packet loss.
      - 10% or above: High packet loss.
      - Unavailable / error: N/A.
    """
    if loss_pct is None:
        return 'UNAVAILABLE', 'N/A', 'badge-neutral'
    try:
        val = float(loss_pct)
    except (ValueError, TypeError):
        return 'UNAVAILABLE', 'N/A', 'badge-neutral'

    if val <= 0.0:
        return 'NONE', '0.00% No Loss', 'badge-up'
    elif val < float(warning_threshold):
        return 'LOW', f'{val:.2f}% Low Loss', 'badge-low-loss'
    elif val < float(critical_threshold):
        return 'MODERATE', f'{val:.2f}% Moderate Loss', 'badge-fault'
    else:
        return 'HIGH', f'{val:.2f}% High Loss', 'badge-down'

def parse_ping_output(stdout, stderr="", returncode=0, count=1, elapsed_total_ms=None, system=None):
    """
    Parses OS-native ping command output across Windows, Linux, and macOS.
    Extracts sent, received, lost, packet-loss percentage ((lost / sent) * 100),
    minimum, maximum, and average round-trip times.
    Supports English and common localized Windows/Unix output.
    Does NOT infer 100% packet loss on execution failure.
    """
    system = (system or platform.system()).lower()
    stdout = stdout or ""
    stderr = stderr or ""

    sent = None
    rcvd = None
    lost = None
    loss_pct = None
    min_rtt = None
    max_rtt = None
    avg_rtt = None
    fault_category = "NONE"
    fault_reason = None
    is_reachable = False
    parse_error = None

    if system == 'windows':
        # 1. Parse Packets Sent, Received, Lost
        # Standard English: Packets: Sent = 20, Received = 18, Lost = 2 (10% loss)
        pkt_match = re.search(
            r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)",
            stdout,
            re.IGNORECASE
        )
        if pkt_match:
            sent = int(pkt_match.group(1))
            rcvd = int(pkt_match.group(2))
            lost = int(pkt_match.group(3))
        else:
            # Flexible regexes for localized Windows ping (Sent / Received / Lost)
            sent_m = re.search(r"(?:Sent|Envoyés|Gesendet|Enviados)\s*=\s*(\d+)", stdout, re.IGNORECASE)
            rcvd_m = re.search(r"(?:Received|Reçus|Empfangen|Recibidos)\s*=\s*(\d+)", stdout, re.IGNORECASE)
            lost_m = re.search(r"(?:Lost|Perdus|Verloren|Perdidos)\s*=\s*(\d+)", stdout, re.IGNORECASE)
            if sent_m and rcvd_m:
                sent = int(sent_m.group(1))
                rcvd = int(rcvd_m.group(1))
                lost = int(lost_m.group(1)) if lost_m else max(0, sent - rcvd)

        # 2. Calculate actual packet loss percentage: (lost / sent) * 100
        if sent is not None and sent > 0 and lost is not None:
            loss_pct = round((float(lost) / float(sent)) * 100.0, 2)
        elif "100% loss" in stdout or "100% de perte" in stdout or "100% Verlust" in stdout:
            if sent is None:
                sent = count
                rcvd = 0
                lost = count
            loss_pct = 100.0

        # 3. Parse Round-Trip Times (Min, Max, Avg)
        # Minimum = 24ms, Maximum = 28ms, Average = 25ms
        min_m = re.search(r"(?:Minimum|Min)\s*=\s*([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)
        max_m = re.search(r"(?:Maximum|Max)\s*=\s*([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)
        avg_m = re.search(r"(?:Average|Moyenne|Mittelwert|Media)\s*=\s*([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)

        if min_m:
            min_rtt = float(min_m.group(1))
        if max_m:
            max_rtt = float(max_m.group(1))
        if avg_m:
            avg_rtt = float(avg_m.group(1))

        # Check for sub-millisecond notation: time<1ms
        if "<1ms" in stdout or "time<1ms" in stdout:
            if avg_rtt == 0.0 or avg_rtt is None:
                avg_rtt = 0.5
            if min_rtt == 0.0 or min_rtt is None:
                min_rtt = 0.5
            if max_rtt == 0.0 or max_rtt is None:
                max_rtt = 0.5

        # Fallback individual echo reply times if summary block is absent
        if avg_rtt is None:
            time_matches = re.findall(r"time[=<]([0-9]+(?:\.[0-9]+)?)ms", stdout, re.IGNORECASE)
            if time_matches:
                times = [float(t) for t in time_matches]
                min_rtt = round(min(times), 2)
                max_rtt = round(max(times), 2)
                avg_rtt = round(sum(times) / len(times), 2)

        # 4. Status and Reachability Determination
        has_replies = bool(re.search(r"Reply from|Réponse de|Antwort von", stdout, re.IGNORECASE))
        if rcvd is not None:
            is_reachable = rcvd > 0
        else:
            is_reachable = has_replies and returncode == 0

        if is_reachable:
            fault_category = "NONE"
            fault_reason = None
            if avg_rtt is None and elapsed_total_ms is not None:
                avg_rtt = round(elapsed_total_ms / max(1, count), 2)
        else:
            if "Destination host unreachable" in stdout or "Impossible de joindre l'hôte" in stdout:
                fault_category = "HOST_UNREACHABLE"
                fault_reason = "Destination host unreachable"
            elif "Request timed out" in stdout or (loss_pct is not None and loss_pct >= 100.0):
                fault_category = "NETWORK_TIMEOUT"
                fault_reason = "ICMP request timed out (packet loss 100%)"
            elif "General failure" in stdout:
                fault_category = "GENERAL_FAILURE"
                fault_reason = "Ping general failure (network interface or routing error)"
            else:
                fault_category = "HOST_UNREACHABLE"
                fault_reason = "No ICMP echo reply received"

    else:
        # Linux and macOS ping parsing
        linux_pkt = re.search(
            r"(\d+)\s+(?:packets\s+)?transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(?:([0-9\.]+)%\s+packet loss)",
            stdout,
            re.IGNORECASE
        )
        if linux_pkt:
            sent = int(linux_pkt.group(1))
            rcvd = int(linux_pkt.group(2))
            lost = max(0, sent - rcvd)
            loss_pct = round((float(lost) / float(sent)) * 100.0, 2) if sent > 0 else 0.0

        rtt_match = re.search(
            r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([0-9\.]+)/([0-9\.]+)/([0-9\.]+)",
            stdout,
            re.IGNORECASE
        )
        if rtt_match:
            min_rtt = float(rtt_match.group(1))
            avg_rtt = float(rtt_match.group(2))
            max_rtt = float(rtt_match.group(3))

        if rcvd is not None:
            is_reachable = rcvd > 0
        else:
            is_reachable = ("bytes from" in stdout) and returncode == 0

        if is_reachable:
            fault_category = "NONE"
            fault_reason = None
            if avg_rtt is None and elapsed_total_ms is not None:
                avg_rtt = round(elapsed_total_ms / max(1, count), 2)
        else:
            if "100% packet loss" in stdout or (loss_pct is not None and loss_pct >= 100.0):
                fault_category = "NETWORK_TIMEOUT"
                fault_reason = "ICMP request timed out (100% packet loss)"
            else:
                fault_category = "HOST_UNREACHABLE"
                fault_reason = "No ICMP echo response received"

    band_key, band_label, badge_class = get_packet_loss_band(loss_pct)

    return {
        'is_reachable': is_reachable,
        'reachable': is_reachable,
        'rtt_ms': avg_rtt if is_reachable else None,
        'response_time_ms': avg_rtt if is_reachable else None,
        'min_rtt_ms': min_rtt,
        'max_rtt_ms': max_rtt,
        'avg_rtt_ms': avg_rtt,
        'packets_sent': sent,
        'packets_received': rcvd,
        'packets_lost': lost,
        'packet_loss_pct': loss_pct,
        'packet_loss_status': band_key,
        'packet_loss_band_label': band_label,
        'packet_loss_badge': badge_class,
        'fault_category': fault_category,
        'fault_reason': fault_reason,
        'fault_details': fault_reason,
        'error': parse_error,
        'raw_output': stdout
    }

def ping_host(ip_address, count=None, timeout_sec=None, full_result=False):
    """
    Executes an OS-native ping command without shell interpolation.
    Supports Windows (ping -n <count> -w <timeout_ms>), Linux, and macOS.
    Validates IP addresses using ipaddress module.
    
    When full_result=False:
        Returns legacy 4-tuple: (is_reachable, rtt_ms, fault_category, fault_reason)
    When full_result=True:
        Returns structured dictionary containing reachability, latency,
        and packet-loss telemetry (sent, received, lost, loss percentage).
    """
    is_valid, err, ip_obj = validate_ip_address(ip_address)
    if not is_valid:
        error_dict = {
            'is_reachable': False,
            'rtt_ms': None,
            'min_rtt_ms': None,
            'max_rtt_ms': None,
            'avg_rtt_ms': None,
            'packets_sent': None,
            'packets_received': None,
            'packets_lost': None,
            'packet_loss_pct': None,
            'packet_loss_status': 'UNAVAILABLE',
            'packet_loss_band_label': 'N/A',
            'packet_loss_badge': 'badge-neutral',
            'fault_category': 'INVALID_ADDRESS',
            'fault_reason': f"Invalid IP address: {err}",
            'error': f"Invalid IP address: {err}",
            'raw_output': ""
        }
        if full_result:
            return error_dict
        return False, None, "INVALID_ADDRESS", f"Invalid IP address: {err}"

    target_ip = str(ip_obj)
    count = count or getattr(Config, 'DEFAULT_PING_PROBE_COUNT', Config.DEFAULT_PING_COUNT)
    timeout_sec = timeout_sec or Config.DEFAULT_PING_TIMEOUT

    system = platform.system().lower()

    if system == 'windows':
        # Windows ping: -n count, -w timeout_in_milliseconds
        timeout_ms = int(timeout_sec * 1000)
        cmd = ['ping', '-n', str(count), '-w', str(timeout_ms), target_ip]
    else:
        # Linux/macOS ping: -c count, -W timeout_in_seconds
        cmd = ['ping', '-c', str(count), '-W', str(int(timeout_sec)), target_ip]

    proc_timeout = (count * timeout_sec) + 5

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
        parsed = parse_ping_output(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            count=count,
            elapsed_total_ms=elapsed_total_ms,
            system=system
        )
    except subprocess.TimeoutExpired:
        # Bounded subprocess timeout: return measurement error rather than guessing 100% loss
        err_msg = f"Ping execution timed out after {proc_timeout}s"
        parsed = {
            'is_reachable': False,
            'rtt_ms': None,
            'min_rtt_ms': None,
            'max_rtt_ms': None,
            'avg_rtt_ms': None,
            'packets_sent': count,
            'packets_received': None,
            'packets_lost': None,
            'packet_loss_pct': None,
            'packet_loss_status': 'UNAVAILABLE',
            'packet_loss_band_label': 'N/A',
            'packet_loss_badge': 'badge-neutral',
            'fault_category': 'NETWORK_TIMEOUT',
            'fault_reason': err_msg,
            'error': err_msg,
            'raw_output': ""
        }
    except FileNotFoundError:
        err_msg = "Ping utility not found on host system"
        parsed = {
            'is_reachable': False,
            'rtt_ms': None,
            'min_rtt_ms': None,
            'max_rtt_ms': None,
            'avg_rtt_ms': None,
            'packets_sent': None,
            'packets_received': None,
            'packets_lost': None,
            'packet_loss_pct': None,
            'packet_loss_status': 'UNAVAILABLE',
            'packet_loss_band_label': 'N/A',
            'packet_loss_badge': 'badge-neutral',
            'fault_category': 'SYSTEM_ERROR',
            'fault_reason': err_msg,
            'error': err_msg,
            'raw_output': ""
        }
    except Exception as e:
        logger.error(f"Unexpected error running ping for {target_ip}: {e}")
        err_msg = f"Error executing ping: {str(e)}"
        parsed = {
            'is_reachable': False,
            'rtt_ms': None,
            'min_rtt_ms': None,
            'max_rtt_ms': None,
            'avg_rtt_ms': None,
            'packets_sent': None,
            'packets_received': None,
            'packets_lost': None,
            'packet_loss_pct': None,
            'packet_loss_status': 'UNAVAILABLE',
            'packet_loss_band_label': 'N/A',
            'packet_loss_badge': 'badge-neutral',
            'fault_category': 'GENERAL_FAILURE',
            'fault_reason': err_msg,
            'error': err_msg,
            'raw_output': ""
        }

    if full_result:
        return parsed

    return parsed['is_reachable'], parsed['rtt_ms'], parsed['fault_category'], parsed['fault_reason']

def measure_packet_loss(ip_address, count=None, timeout_sec=None):
    """
    Dedicated packet-loss measurement helper.
    Returns structured packet-loss statistics dictionary without modifying system state.
    """
    return ping_host(ip_address, count=count, timeout_sec=timeout_sec, full_result=True)

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
    ping_count = settings.get('ping_count', getattr(Config, 'DEFAULT_PING_PROBE_COUNT', Config.DEFAULT_PING_COUNT))
    warning_thresh = settings.get('packet_loss_warning_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_WARNING_PCT', 5))
    critical_thresh = settings.get('packet_loss_critical_pct', getattr(Config, 'DEFAULT_PACKET_LOSS_CRITICAL_PCT', 10))

    device_id = device['id']
    ip = device['ip_address']
    port = device.get('port')

    # Step 1: Reachability and Packet Loss check (Single OS ICMP Ping Execution)
    # Reuses the exact same command output for reachability, RTT, and packet loss statistics
    raw_ping_res = ping_host(ip, count=ping_count, timeout_sec=ping_timeout, full_result=True)
    if isinstance(raw_ping_res, (tuple, list)):
        # Normalize when ping_host returns or is mocked to return the legacy 4-tuple
        p_reach = bool(raw_ping_res[0]) if len(raw_ping_res) > 0 else False
        p_rtt = raw_ping_res[1] if len(raw_ping_res) > 1 else None
        p_cat = raw_ping_res[2] if len(raw_ping_res) > 2 else "NONE"
        p_reason = raw_ping_res[3] if len(raw_ping_res) > 3 else None
        p_sent = ping_count if ping_count else 20
        p_rcvd = p_sent if p_reach else 0
        p_lost = 0 if p_reach else p_sent
        p_loss_pct = 0.0 if p_reach else 100.0
        b_key, b_lbl, b_cls = get_packet_loss_band(p_loss_pct, warning_thresh, critical_thresh)
        ping_res = {
            'is_reachable': p_reach,
            'rtt_ms': p_rtt,
            'min_rtt_ms': p_rtt,
            'max_rtt_ms': p_rtt,
            'avg_rtt_ms': p_rtt,
            'packets_sent': p_sent,
            'packets_received': p_rcvd,
            'packets_lost': p_lost,
            'packet_loss_pct': p_loss_pct,
            'packet_loss_status': b_key,
            'packet_loss_band_label': b_lbl,
            'packet_loss_badge': b_cls,
            'fault_category': p_cat,
            'fault_reason': p_reason,
            'error': None
        }
    else:
        ping_res = raw_ping_res

    ping_reachable = bool(ping_res.get('is_reachable', ping_res.get('reachable', False)))
    ping_rtt = ping_res.get('rtt_ms', ping_res.get('response_time_ms'))
    ping_cat = ping_res.get('fault_category', 'NONE')
    ping_fault = ping_res.get('fault_reason', ping_res.get('fault_details'))
    reachability_status = "REACHABLE" if ping_reachable else "UNREACHABLE"

    loss_pct = ping_res.get('packet_loss_pct')
    if loss_pct is not None and loss_pct > 0:
        loss_text = f", {loss_pct:.2f}% packet loss ({ping_res.get('packets_lost')}/{ping_res.get('packets_sent')} lost)"
    elif loss_pct == 0.0:
        loss_text = ", 0% loss"
    else:
        loss_text = ""

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
    # Packet loss is an independent metric and does NOT automatically mark a host DOWN
    # if it remains reachable (at least 1 packet received)
    overall_status = "DOWN"
    response_time_ms = None
    fault_category = "NONE"
    fault_details = None

    if not has_port:
        if ping_reachable:
            overall_status = "UP"
            response_time_ms = ping_rtt
            fault_category = "NONE"
            fault_details = f"Device reachable via ICMP ({ping_rtt}ms RTT{loss_text}; TCP service not configured)"
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
            fault_details = f"Reachable via ICMP ({ping_rtt}ms RTT{loss_text}); TCP port {port} open ({tcp_connect_time}ms connect)"
        elif ping_reachable and not tcp_open:
            overall_status = "FAULT"
            response_time_ms = ping_rtt
            fault_category = tcp_cat or "SERVICE_REFUSED"
            fault_details = f"Host reachable via ICMP ({ping_rtt}ms RTT{loss_text}), but TCP port {port} failed: {tcp_fault}"
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

    band_key, band_label, badge_class = get_packet_loss_band(
        loss_pct,
        warning_threshold=warning_thresh,
        critical_threshold=critical_thresh
    )

    return {
        'device_id': device_id,
        'reachability_status': reachability_status,
        'service_status': service_status,
        'overall_status': overall_status,
        'response_time_ms': response_time_ms,
        'fault_category': fault_category,
        'fault_details': fault_details,
        'packets_sent': ping_res.get('packets_sent'),
        'packets_received': ping_res.get('packets_received'),
        'packets_lost': ping_res.get('packets_lost'),
        'packet_loss_pct': ping_res.get('packet_loss_pct'),
        'min_rtt_ms': ping_res.get('min_rtt_ms'),
        'max_rtt_ms': ping_res.get('max_rtt_ms'),
        'avg_rtt_ms': ping_res.get('avg_rtt_ms'),
        'packet_loss_status': band_key,
        'packet_loss_band_label': band_label,
        'packet_loss_badge': badge_class,
        'measurement_time': datetime.now(timezone.utc).isoformat(),
        'packet_loss_error': ping_res.get('error')
    }


# ---------------------------------------------------------
# Hop-by-Hop Fault Localization & Traceroute Diagnostics
# ---------------------------------------------------------

def parse_tracert_output(output, target_ip, execution_incomplete=False):
    """
    Parses native Windows tracert and Linux traceroute output into structured hop telemetry.
    Correctly accounts for router ICMP deprioritization, intermediate timeouts,
    trace completion vs destination reachability, and partial execution.
    """
    hops = []
    lines = (output or "").strip().splitlines()
    destination_reached = False
    destination_hop = None
    trace_completed = any("Trace complete" in l or "trace complete" in l.lower() for l in lines)
    hop_regex = re.compile(r'^\s*(\d+)\s+(.+)$')

    for line in lines:
        match = hop_regex.match(line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2).strip()

        is_timeout = (
            "Request timed out" in rest
            or re.search(r'^\*\s+\*\s+\*(\s+Request timed out\.?)?$', rest)
            or rest == "* * *"
        )

        bracket_ip = re.search(r'\[([0-9a-fA-F\:\.]{7,45})\]', rest)
        if bracket_ip:
            hop_ip = bracket_ip.group(1)
        else:
            ip_candidates = re.findall(r'([0-9a-fA-F\:\.]{7,45})', rest)
            valid_ips = [
                cand for cand in ip_candidates
                if ('.' in cand or ':' in cand) and not cand.endswith('ms')
            ]
            if valid_ips:
                hop_ip = valid_ips[-1]
            elif is_timeout:
                hop_ip = '*'
            else:
                hop_ip = '*'

        rtt_area = rest
        if hop_ip != '*' and hop_ip in rtt_area:
            rtt_area = rtt_area.replace(hop_ip, ' ')
        if "Request timed out" in rtt_area:
            rtt_area = rtt_area.replace("Request timed out.", " ").replace("Request timed out", " ")

        rtt_tokens = re.findall(r'(?:<\s*1|\d+(?:\.\d+)?|\*)\s*(?:ms)?', rtt_area)
        cleaned_rtts = []
        numeric_rtts = []
        for tok in rtt_tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok == '*':
                cleaned_rtts.append('*')
            elif '<' in tok:
                cleaned_rtts.append('<1 ms')
                numeric_rtts.append(0.5)
            else:
                num = re.search(r'(\d+(?:\.\d+)?)', tok)
                if num:
                    cleaned_rtts.append(f"{num.group(1)} ms")
                    numeric_rtts.append(float(num.group(1)))
            if len(cleaned_rtts) == 3:
                break

        while len(cleaned_rtts) < 3:
            cleaned_rtts.append('*')

        avg_rtt = round(sum(numeric_rtts) / len(numeric_rtts), 1) if numeric_rtts else None
        if not numeric_rtts or hop_ip == '*':
            status = 'TIMED_OUT'
        elif '*' in cleaned_rtts:
            status = 'PARTIAL_LOSS'
        elif avg_rtt and avg_rtt > 100:
            status = 'HIGH_LATENCY'
        else:
            status = 'SUCCESS'

        is_target = (
            (hop_ip == target_ip)
            or (target_ip in ('127.0.0.1', 'localhost') and hop_ip in ('127.0.0.1', 'localhost', '::1'))
        )
        if is_target:
            destination_reached = True
            destination_hop = hop_num

        hops.append({
            'hop': hop_num,
            'ip': hop_ip,
            'rtt1': cleaned_rtts[0],
            'rtt2': cleaned_rtts[1],
            'rtt3': cleaned_rtts[2],
            'avg_rtt_ms': avg_rtt,
            'status': status
        })

        if destination_reached:
            trace_completed = True
            break

    total_hops = len(hops)
    responding_hops = sum(1 for h in hops if h.get('status') != 'TIMED_OUT' and h.get('ip') != '*')
    non_responsive_hops = sum(1 for h in hops if h.get('status') == 'TIMED_OUT' or h.get('ip') == '*')

    fault_hop = None
    fault_localized = False

    if destination_reached:
        dest_str = f" at hop {destination_hop}" if destination_hop else ""
        fault_summary = (
            f"Destination {target_ip} reached{dest_str}. "
            f"{responding_hops} responding hop(s), {non_responsive_hops} non-responsive hop(s) "
            f"(intermediate ICMP deprioritization/filtering)."
        )
    elif execution_incomplete:
        fault_summary = (
            f"Traceroute deadline reached after {total_hops} hop(s) "
            f"({responding_hops} responding, {non_responsive_hops} non-responsive). "
            f"Destination reachability unconfirmed by trace."
        )
    else:
        # Trace completed to max_hops or ended, but destination was not reached
        if responding_hops == 0 and total_hops > 0:
            fault_hop = 1
            fault_localized = True
            fault_summary = (
                f"No response received from any of the {total_hops} probed hops. "
                f"Default gateway or local network interface failed to route traffic to {target_ip}."
            )
        else:
            responding_list = [h for h in hops if h.get('status') != 'TIMED_OUT' and h.get('ip') != '*']
            if responding_list:
                last_responding = responding_list[-1]
                last_hop_num = last_responding['hop']
                last_ip = last_responding['ip']
                trailing_timeouts = [h for h in hops if h['hop'] > last_hop_num]
                if len(trailing_timeouts) >= 2:
                    fault_hop = last_hop_num + 1
                    fault_localized = True
                    fault_summary = (
                        f"Packet drop localized after Hop {last_hop_num} ({last_ip}). "
                        f"Traffic dropped entering upstream network at Hop {fault_hop}."
                    )
                else:
                    fault_summary = (
                        f"Destination {target_ip} did not respond within {total_hops} hop(s) "
                        f"({responding_hops} responding, {non_responsive_hops} non-responsive). "
                        f"Trace complete."
                    )
            else:
                fault_summary = (
                    f"Destination {target_ip} did not respond within {total_hops} hop(s) "
                    f"({responding_hops} responding, {non_responsive_hops} non-responsive)."
                )

    return {
        'target_ip': target_ip,
        'total_hops': total_hops,
        'responding_hops': responding_hops,
        'non_responsive_hops': non_responsive_hops,
        'destination_reached': destination_reached,
        'destination_hop': destination_hop,
        'trace_completed': trace_completed,
        'execution_incomplete': execution_incomplete,
        'fault_hop': fault_hop,
        'fault_localized': fault_localized,
        'fault_summary': fault_summary,
        'hops': hops,
        'raw_output': output
    }

def run_traceroute(target_ip, max_hops=15, timeout_ms=1000):
    """
    Executes a hop-by-hop traceroute to target_ip using the native OS utility.
    Under Windows: tracert -d -h <max_hops> -w <timeout_ms> <target_ip>
    Under Linux/macOS: traceroute -n -m <max_hops> -w <timeout_sec> <target_ip>
    Captures stdout and stderr, preserves partial results upon deadline expiration,
    and returns structured hop telemetry and diagnostics.
    """
    is_valid, err_msg, _ = validate_ip_address(target_ip)
    if not is_valid and target_ip not in ('localhost', '127.0.0.1'):
        return {
            'target_ip': target_ip,
            'total_hops': 0,
            'responding_hops': 0,
            'non_responsive_hops': 0,
            'destination_reached': False,
            'destination_hop': None,
            'trace_completed': False,
            'execution_incomplete': False,
            'fault_hop': None,
            'fault_localized': True,
            'fault_summary': f"Invalid target IP address: {err_msg}",
            'hops': [],
            'raw_output': ""
        }

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), target_ip]
    else:
        timeout_sec = max(1, int(timeout_ms / 1000))
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_sec), target_ip]

    # Calculate appropriate execution deadline:
    # 3 probes per hop. If hops time out, wait_time = 3 * timeout_ms per hop.
    wait_sec_per_probe = max(0.5, float(timeout_ms) / 1000.0)
    max_duration = int((max_hops * 3 * wait_sec_per_probe) + 15)
    max_duration = max(30, min(180, max_duration))

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max_duration,
            check=False
        )
        stdout_txt = result.stdout or ""
        stderr_txt = result.stderr or ""
        combined_output = stdout_txt
        if stderr_txt.strip():
            combined_output = f"{stdout_txt}\n{stderr_txt}".strip()
        return parse_tracert_output(combined_output, target_ip, execution_incomplete=False)
    except subprocess.TimeoutExpired as exc:
        raw_out = ""
        if exc.stdout:
            raw_out = exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode('utf-8', errors='ignore')
        if exc.stderr:
            err_str = exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode('utf-8', errors='ignore')
            if err_str.strip():
                raw_out = f"{raw_out}\n{err_str}".strip()
        if not raw_out:
            raw_out = "Traceroute execution deadline expired."
        logger.warning(f"Traceroute to {target_ip} reached deadline of {max_duration}s. Preserving partial results.")
        return parse_tracert_output(raw_out, target_ip, execution_incomplete=True)
    except Exception as e:
        logger.error(f"Error executing traceroute to {target_ip}: {e}")
        return {
            'target_ip': target_ip,
            'total_hops': 0,
            'responding_hops': 0,
            'non_responsive_hops': 0,
            'destination_reached': False,
            'destination_hop': None,
            'trace_completed': False,
            'execution_incomplete': True,
            'fault_hop': None,
            'fault_localized': True,
            'fault_summary': f"Subprocess invocation failure: {str(e)}",
            'hops': [],
            'raw_output': str(e)
        }
