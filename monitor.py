"""
Networking and Monitoring module for NetFault.
Implements:
1. ICMP/Ping reachability and latency measurement.
2. TCP socket port availability checking.
3. Three-tier fault classification logic (UP, DOWN, FAULT).
4. Automated background monitoring worker thread.
"""

import time
import socket
import subprocess
import platform
import re
import threading
from config import Config
import database

def check_ping(host, timeout_seconds=Config.PING_TIMEOUT_SECONDS):
    """
    Performs an ICMP ping check to determine host reachability and roundtrip time.
    Cross-platform support for Windows, Linux, and macOS.
    Does not require root or administrator privileges.
    
    Returns:
        dict: {
            "reachable": bool,
            "response_time": float or None (in milliseconds)
        }
    """
    system_os = platform.system().lower()
    start_time = time.perf_counter()
    
    try:
        if system_os == "windows":
            # -n 1: 1 echo request, -w <ms>: timeout in milliseconds
            timeout_ms = int(timeout_seconds * 1000)
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(host)]
        else:
            # -c 1: 1 count, -W <seconds>: timeout in seconds
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_seconds)), str(host)]
            
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds + 1.5
        )
        
        output = process.stdout + process.stderr
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        # Check if ping succeeded
        if process.returncode == 0:
            # Search for response time in ping output
            # Windows format: time=12ms or time<1ms
            # Linux format: time=12.4 ms
            match_time = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
            
            if match_time:
                rt_val = float(match_time.group(1))
                # For Windows 'time<1ms', group(1) might be 1; provide high-resolution fallback if 0
                if rt_val == 0.0 and "time<1ms" in output.lower():
                    rt_val = 0.8
                return {"reachable": True, "response_time": rt_val}
            
            # If time pattern not parsed but 0% loss confirmed, use wall-clock elapsed time
            if "0% loss" in output or "0% packet loss" in output:
                return {"reachable": True, "response_time": elapsed_ms}
                
        # Ping failed or timed out
        return {"reachable": False, "response_time": None}
        
    except (subprocess.TimeoutExpired, Exception):
        return {"reachable": False, "response_time": None}


def check_tcp_port(host, port, timeout_seconds=Config.TCP_TIMEOUT_SECONDS):
    """
    Checks if a specific TCP port is open and accepting connections on host.
    Measures TCP handshake latency.
    
    Returns:
        dict: {
            "available": bool,
            "response_time": float or None (in milliseconds)
        }
    """
    if not port:
        return {"available": False, "response_time": None}
        
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return {"available": False, "response_time": None}
    except (ValueError, TypeError):
        return {"available": False, "response_time": None}
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    start_time = time.perf_counter()
    
    try:
        # Attempt TCP connection
        sock.connect((str(host), port_num))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {"available": True, "response_time": elapsed_ms}
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        return {"available": False, "response_time": None}
    finally:
        sock.close()


def evaluate_device(device):
    """
    Evaluates the status of a single device following the exact system flow:
    
    1. Ping check:
       - If Ping fails -> Status: DOWN, Fault: "Device unreachable"
    2. If Ping succeeds:
       - If TCP port is configured:
         - TCP check:
           - If Port open -> Status: UP, Fault: "-"
           - If Port closed -> Status: FAULT, Fault: "Device reachable but service/port unavailable"
       - If NO TCP port configured:
         - Status: UP, Fault: "-"
         
    Stores the evaluation result into SQLite and returns the result dictionary.
    """
    device_id = device["id"]
    device_name = device["device_name"]
    ip_address = device["ip_address"]
    tcp_port = device.get("tcp_port")
    
    # 1. ICMP / Ping Check
    ping_res = check_ping(ip_address)
    
    if not ping_res["reachable"]:
        # Case 1: Device unreachable
        status = "DOWN"
        fault_info = "Device unreachable"
        response_time = None
    else:
        # Ping succeeded
        ping_latency = ping_res["response_time"]
        
        # Check if TCP port is configured
        if tcp_port is not None and str(tcp_port).strip() != "":
            # 2. TCP Port Check
            tcp_res = check_tcp_port(ip_address, tcp_port)
            if tcp_res["available"]:
                # Case 3: Device reachable and port reachable
                status = "UP"
                fault_info = "-"
                response_time = ping_latency
            else:
                # Case 2: Device reachable but port closed/refused
                status = "FAULT"
                fault_info = "Device reachable but service/port unavailable"
                response_time = ping_latency
        else:
            # Case 4: No TCP port configured and ping succeeded
            status = "UP"
            fault_info = "-"
            response_time = ping_latency
            
    # Persist monitoring result in SQLite
    result_id = database.save_monitoring_result(
        device_id=device_id,
        status=status,
        response_time=response_time,
        fault_info=fault_info
    )
    
    return {
        "result_id": result_id,
        "device_id": device_id,
        "device_name": device_name,
        "ip_address": ip_address,
        "tcp_port": tcp_port,
        "status": status,
        "response_time": response_time,
        "fault_info": fault_info
    }


def monitor_device_by_id(device_id):
    """
    Fetches a specific device and runs evaluation.
    """
    device = database.get_device_by_id(device_id)
    if not device:
        return None
    return evaluate_device(device)


def monitor_all_devices():
    """
    Runs evaluation sequentially on all registered devices.
    Returns list of evaluated results.
    """
    devices = database.get_all_devices()
    results = []
    for dev in devices:
        res = evaluate_device(dev)
        results.append(res)
    return results


class BackgroundMonitor:
    """
    Background worker thread that periodically polls all registered devices.
    Runs as a daemon thread so it automatically shuts down with the Flask app.
    Interval and active state can be modified at runtime.
    """
    def __init__(self, interval_seconds=Config.DEFAULT_MONITOR_INTERVAL):
        self.interval = interval_seconds
        self.enabled = True
        self._stop_event = threading.Event()
        self._thread = None
        self.last_run_time = None
        
    def _worker(self):
        while not self._stop_event.is_set():
            if self.enabled:
                try:
                    monitor_all_devices()
                    self.last_run_time = time.strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    # Log error without crashing thread
                    print(f"[NetFault Auto-Monitor] Error during check cycle: {e}")
            
            # Sleep in 1-second chunks to allow rapid shutdown response
            for _ in range(int(self.interval)):
                if self._stop_event.is_set():
                    break
                time.sleep(1)
                
    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._worker, daemon=True, name="NetFaultMonitorThread")
            self._thread.start()
            print(f"[NetFault] Background monitor started. Interval: {self.interval}s")
            
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
            print("[NetFault] Background monitor stopped.")
            
    def set_interval(self, seconds):
        if seconds > 0:
            self.interval = int(seconds)
            
    def toggle(self, state=None):
        if state is None:
            self.enabled = not self.enabled
        else:
            self.enabled = bool(state)
        return self.enabled


# Global monitor instance
background_monitor = BackgroundMonitor()
