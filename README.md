# Automated Fault Detection System

An enterprise-grade, laboratory-oriented network monitoring and automated fault detection web application built with Python Flask, ICMP/Ping subprocess integration, TCP socket programming, and SQLite.

Designed specifically as a **Computer Networks Laboratory Project**, this application enables network engineers and laboratory instructors to register endpoints (IPv4/IPv6), verify end-to-end ICMP reachability, inspect specific TCP service socket availability, track historical fault occurrences, and configure monitoring thresholds through a clean, high-contrast monochrome dashboard.

---

## 1. Abstract

Modern enterprise and campus networks require continuous monitoring to ensure high availability of critical services. Traditional network troubleshooting often relies on manual command-line utilities such as `ping` and `telnet`, which are inefficient for multi-host infrastructures. The **Automated Fault Detection System (AFDS)** solves this problem by centralizing real-time connectivity testing and transport-layer verification into an automated, periodic web platform. By combining Internet Control Message Protocol (ICMP) echo requests with raw TCP three-way handshake socket probes, AFDS categorizes the health of each registered device into deterministic operational states (`UP`, `DOWN`, or `FAULT`), measuring precise latencies and archiving historical diagnostics in an ACID-compliant SQLite database.

---

## 2. Problem Statement

Network administrators frequently face challenges when diagnosing system outages:
- **Ambiguous Failure Modes**: An administrator may receive reports that a web service is down without knowing whether the host physical machine is unreachable (Layer 3 issue) or whether the host is reachable but the application service has crashed or closed its listening port (Layer 4/7 issue).
- **Manual Overhead**: Running ad-hoc terminal ping and port-scanning tools across multiple subnets is time-consuming and fails to maintain historical logs.
- **Resource Heavy Monitoring Tools**: Commercial monitoring suites (e.g., Zabbix, Nagios, SolarWinds) often require heavy daemon agents, complex third-party databases, and excessive server overhead unsuited for academic demonstrations or lightweight network labs.

---

## 3. Proposed Solution

The **Automated Fault Detection System** provides a lightweight, agentless architecture:
1. **Network-Layer Reachability (ICMP)**: Native OS-level echo probes determine whether the host IP route is operational and calculate round-trip time (RTT).
2. **Transport-Layer Verification (TCP Sockets)**: Standard Python BSD socket connections verify whether configured application ports (HTTP `80`, HTTPS `443`, SSH `22`, Flask `5000`, etc.) actively complete the TCP 3-way handshake.
3. **Deterministic Fault Triangulation**: The system distinguishes between general connectivity loss (`DOWN`) and service-specific failure (`FAULT`), recording granular error descriptions (e.g., connection refused, timeout, network unreachable).
4. **Autonomous Background Worker**: A dedicated Python background thread executes scheduled monitoring cycles at configurable intervals without blocking the Flask web server.
5. **Zero-Configuration Persistence**: Automatic runtime initialization of SQLite database schemas with strict foreign-key cascade policies.

---

## 4. Key Objectives

- Develop a modular Flask application with server-rendered HTML5 templates and responsive JavaScript updates.
- Implement secure, shell-injection-safe ICMP ping execution on Windows, Linux, and macOS.
- Perform real TCP socket connection tests measuring true connection latency in milliseconds.
- Classify device states strictly according to network observations without synthetic data.
- Provide full CRUD capabilities for network endpoints with duplicate collision prevention.
- Deliver an academic, high-contrast monochrome user interface free of decorative bloat.
- Provide comprehensive automated test coverage with mocked network calls.

---

## 5. Technology Stack

- **Backend**: Python 3.10+
- **Web Framework**: Flask 3.0+
- **Network Layer Protocol**: ICMP Echo (via OS ping subprocess)
- **Transport Layer Protocol**: TCP Socket Programming (`socket.SOCK_STREAM`)
- **Database**: SQLite 3 (using standard library `sqlite3` with foreign-key enforcement)
- **Frontend**: Semantic HTML5, Vanilla CSS3 (custom monochrome design system), Modern JavaScript (Fetch API)
- **Testing**: Python `unittest` framework with `unittest.mock`

> **Note**: No third-party enterprise databases, React, Node.js, Redis, or Docker containers are required. The application runs natively with minimal dependencies.

---

## 6. Project Directory Structure

```text
automated-fault-detection/
|
|-- app.py                  # Flask application entry point, routes, and JSON API
|-- config.py               # System configuration, paths, defaults, and validation ranges
|-- database.py             # SQLite initialization, parameterized CRUD, and history queries
|-- monitoring.py           # Core network logic: IP validation, ICMP ping, and TCP socket probes
|-- scheduler.py            # Thread-safe background monitoring worker and cycle coordinator
|-- requirements.txt        # Python dependency manifest
|-- README.md               # Complete project documentation
|-- .gitignore              # Git ignore rules for databases, logs, and environments
|
|-- templates/              # Server-rendered Jinja2 HTML templates
|   |-- base.html           # Master layout with sidebar navigation and toast container
|   |-- dashboard.html      # Central monitoring dashboard with summary metrics & live table
|   |-- devices.html        # Registered device inventory with management options
|   |-- add_device.html     # Registration form for new network targets
|   |-- edit_device.html    # Configuration editing form
|   |-- device_details.html # Comprehensive device diagnostic status & recent history
|   |-- history.html        # Filterable, paginated audit log of all monitoring checks
|   |-- settings.html       # Dynamic runtime parameter configuration
|   |-- 404.html            # Not Found error page
|   |-- 500.html            # Internal Server Error page
|
|-- static/                 # Static frontend assets
|   |-- css/
|   |   |-- style.css       # Laboratory-grade monochrome stylesheet
|   |
|   |-- js/
|       |-- dashboard.js    # Asynchronous polling, live check triggers, and UI controls
|
|-- instance/               # Runtime database directory (auto-created)
|   |-- .gitkeep
|
|-- logs/                   # System runtime log files
|   |-- .gitkeep
|
|-- tests/                  # Automated unit and integration test suite
    |-- test_database.py    # Database schema, CRUD, cascade, and settings tests
    |-- test_monitoring.py  # Network validation, mocked ping, sockets, & status tests
    |-- test_routes.py      # Flask views, form validation, error pages, & API tests
```

---

## 7. Status Classification System

Every target device monitored by AFDS is classified into one of three distinct operational states:

| Status Badge | State Name | Technical Definition | Condition |
| :---: | :---: | :--- | :--- |
| `● UP` | **Operational** | The host responds to ICMP ping AND its configured TCP service is accepting connections (or ICMP succeeds when no port is configured). Also applies if ICMP is blocked by firewall policy but the TCP service socket completes handshake. | `Ping: OK` + `TCP: Open`<br>or `Ping: OK` + `Port: None`<br>or `Ping: Blocked` + `TCP: Open` |
| `▲ FAULT` | **Service Fault** | The device responds to network reachability (ICMP ping), but the configured TCP port actively refuses the connection, times out, or fails. | `Ping: OK` + `TCP: Refused / Timeout` |
| `✕ DOWN` | **Offline / Unreachable** | The host does not respond to ICMP ping AND its configured TCP service fails to connect or times out. | `Ping: Fail` + `TCP: Fail / None` |
| `○ UNCHECKED` | **Pending** | Device newly registered; awaiting its first monitoring cycle. | Prior to execution |

---

## 8. Network Monitoring Mechanics

### A. ICMP / Ping Monitoring
1. **Validation**: The target string is strictly parsed using Python's standard `ipaddress` library, verifying whether it conforms to IPv4 or IPv6 standards.
2. **Safe Subprocess Invocation**: Ping requests are launched using `subprocess.run(shell=False)` with explicit argument lists. This eliminates shell command injection vulnerabilities.
   - **Windows**: `ping -n <count> -w <timeout_ms> <ip>`
   - **Linux / macOS**: `ping -c <count> -W <timeout_sec> <ip>`
3. **Latency Extraction**: Regular expressions extract average round-trip times (`Average = XXms` or `time=XXms`). For localhost loopback (`127.0.0.1`), sub-millisecond latencies (`<1ms`) are normalized to `0.5 ms`.
4. **Fault Handling**: Differentiates between `"Destination host unreachable"`, `"Request timed out"`, and general network adapter failures.

### B. TCP Port Monitoring
1. **Socket Allocation**: A native BSD stream socket (`socket.SOCK_STREAM`) is instantiated with the target address family (`AF_INET` or `AF_INET6`).
2. **Handshake Probing**: The socket invokes `.connect((ip, port))` bounded by a configurable timeout.
3. **Response Time Calculation**: High-resolution performance counters (`time.perf_counter()`) record connection establishment time in milliseconds.
4. **Exception Handling**:
   - `ConnectionRefusedError`: Identifies that the host operating system is active but the target service daemon is stopped or actively rejecting SYN packets on that port.
   - `socket.timeout`: Indicates packet drop, routing blackhole, or firewall stealth dropping SYN packets.
   - Socket handles are always cleanly closed in a `finally` block to prevent descriptor leaks.

---

## 9. SQLite Database Design

The database file is automatically created at `instance/network_monitor.db` upon initial application launch.

### Table: `devices`
Stores registered network devices and configurations.
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `device_name` (TEXT NOT NULL)
- `ip_address` (TEXT NOT NULL)
- `port` (INTEGER, NULLABLE)
- `description` (TEXT, NULLABLE)
- `created_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)

### Table: `monitoring_history`
Maintains immutable, chronological audit records for all monitoring checks.
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `device_id` (INTEGER NOT NULL, FOREIGN KEY REFERENCES `devices(id)` ON DELETE CASCADE)
- `checked_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)
- `reachability_status` (TEXT NOT NULL: `REACHABLE`, `UNREACHABLE`, `TIMEOUT`, `ICMP_FILTERED`)
- `service_status` (TEXT NOT NULL: `OPEN`, `REFUSED`, `TIMEOUT`, `CLOSED`, `NOT_CHECKED`)
- `overall_status` (TEXT NOT NULL: `UP`, `DOWN`, `FAULT`)
- `response_time_ms` (REAL, NULLABLE)
- `fault_details` (TEXT, NULLABLE)

### Table: `settings`
Stores dynamic monitoring thresholds:
- `monitor_interval`: Background cycle frequency in seconds (default: 30)
- `ping_timeout`: Timeout per ping packet in seconds (default: 2)
- `tcp_timeout`: Socket connection timeout in seconds (default: 3)
- `ping_count`: Packets per check (default: 2)

---

## 10. Installation & Setup Instructions (Windows & VS Code)

### Prerequisites
- Windows 10 or Windows 11
- Python 3.10+ installed and added to `PATH`
- Visual Studio Code

### Step-by-Step Setup

1. **Open Project in Visual Studio Code**
   Open Visual Studio Code, click **File > Open Folder...**, and select the project directory:
   ```text
   Computer network Project
   ```

2. **Open Terminal in VS Code**
   Press ``Ctrl + ` `` or click **Terminal > New Terminal** (PowerShell or Command Prompt).

3. **Create and Activate Virtual Environment** (Optional but recommended):
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   *(If script execution is restricted in PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

4. **Install Dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

5. **Run the Automated Test Suite**:
   ```powershell
   python -m unittest discover tests
   ```
   All 26 tests will run and report `OK`.

6. **Launch the Application**:
   ```powershell
   python app.py
   ```

7. **Access the Application**:
   Open Google Chrome, Microsoft Edge, or Mozilla Firefox and navigate to:
   ```text
   http://127.0.0.1:5000
   ```

---

## 11. User Guide & Demonstration Scenarios

### Scenario 1: Monitoring Localhost Web Service (UP)
1. Navigate to **+ Add Device**.
2. Enter:
   - **Device Name**: `Local Flask Server`
   - **IP Address**: `127.0.0.1`
   - **TCP Port**: `5000`
   - **Description**: `Local development server`
3. Click **Save and Run Initial Check**.
4. The dashboard displays `● UP` with sub-millisecond response latency.

### Scenario 2: Detecting a Service Fault (FAULT)
1. Navigate to **+ Add Device**.
2. Enter:
   - **Device Name**: `Localhost Closed Port`
   - **IP Address**: `127.0.0.1`
   - **TCP Port**: `65432` (an unused port)
   - **Description**: `Host reachable but port closed`
3. Click **Save and Run Initial Check**.
4. **Result**: The dashboard flags `▲ FAULT`. The diagnosis confirms:
   `"Host reachable via ICMP (0.5ms), but TCP port 65432 failed: TCP connection actively refused on port 65432"`.

### Scenario 3: Detecting an Offline / Unreachable Host (DOWN)
1. Navigate to **+ Add Device**.
2. Enter:
   - **Device Name**: `Unreachable Gateway`
   - **IP Address**: `192.0.2.1` (TEST-NET non-routable IP)
   - **TCP Port**: `80`
3. Click **Save and Run Initial Check**.
4. **Result**: The dashboard flags `✕ DOWN`. Diagnosis records:
   `"Host unreachable via ICMP (ICMP request timed out) and TCP port 80 unavailable"`.

### Scenario 4: Monitoring Reachability Only (No Port)
1. Navigate to **+ Add Device**.
2. Enter:
   - **Device Name**: `Public DNS Gateway`
   - **IP Address**: `8.8.8.8`
   - **TCP Port**: *(Leave blank)*
3. Click **Save and Run Initial Check**.
4. **Result**: Status is `● UP` with measured ICMP latency and fault detail noting:
   `"Device reachable via ICMP (TCP service not configured)"`.

---

## 12. Common Errors and Solutions

1. **`ping: command not found` or subprocess error**
   - **Cause**: The system `PATH` environment variable does not include the system directory.
   - **Solution**: On Windows, ensure `C:\Windows\System32` is present in system environment variables.

2. **ICMP Ping Blocked / 100% Loss for Reachable Servers**
   - **Cause**: Many corporate firewalls and public web hosts intentionally block ICMP Echo packets to prevent denial-of-service scans.
   - **Solution**: When a TCP port is specified (e.g., port 443 for web hosts), AFDS automatically identifies when ICMP is blocked while TCP is open, correctly marking the service as `UP` with note `"ICMP ping filtered/blocked, but TCP port is active"`.

3. **Port 5000 Already in Use**
   - **Cause**: Another process or previous Flask instance is running on port 5000.
   - **Solution**: Terminate the existing process via PowerShell:
     ```powershell
     Stop-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess -Force
     ```
     Or adjust the port in `app.py` to `5001`.

---

## 13. Limitations

- **Privileged ICMP**: Raw socket ICMP creation without administrative permissions is restricted on modern operating systems; hence, this system uses safe OS ping subprocess calls.
- **Firewall Policies**: Hosts configured to drop both ICMP and closed-port TCP SYN packets without returning RST cannot be distinguished from powered-off machines without deeper probe tools.
- **Subnet Sweeping**: In adherence to safety guidelines, the tool does not perform unprompted subnet range scans. Only explicitly registered targets are monitored.

---

## 14. Academic Integrity & Project Report Attribution

This project was built from scratch adhering strictly to the Computer Networks laboratory specifications for automated fault detection systems. All network operations use native Python socket APIs and system subprocess calls with parameterized SQLite persistence.
