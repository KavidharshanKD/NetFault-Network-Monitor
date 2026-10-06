# NetFault – Automated Network Fault Detection and Monitoring System

**NetFault** is a web-based network fault detection and monitoring system designed for Computer Networks and Software Engineering academic projects. It continuously monitors registered network devices, measures roundtrip latency, checks TCP port services, and classifies device health into **UP**, **DOWN**, or **FAULT** states according to a rigorous 2-step decision flow.

---

## 1. Project Problem Statement

In modern network infrastructures, monitoring multiple network devices (servers, routers, switches, workstations) manually is tedious, error-prone, and unsustainable:
- **Delayed Outage Detection:** Failures often go unnoticed until end-users file complaints.
- **Ambiguous Root Causes:** Difficult to diagnose whether the fault lies in the physical/data link layer (unreachable host) or in the application layer (closed/crashed service port).
- **Lack of Centralization:** Administrators must log into each machine or terminal individually.
- **Absence of Audit Logs:** Historical metrics and fault timestamps are lost without systematic database storage.

---

## 2. Proposed Solution

**NetFault** provides a centralized, browser-accessible monitoring console powered by Python and Flask:
- Periodically pings hosts using real OS ICMP Echo requests (cross-platform, zero root privileges needed).
- Probes specified TCP service ports using real Python socket connections.
- Classifies each node using a strict 3-tier state model: **UP**, **DOWN**, or **FAULT**.
- Logs every probe result to an **SQLite** database with millisecond latency metrics and fault explanations.
- Updates an interactive administrator dashboard with live visual status badges and summary counters.

---

## 3. System Architecture & Flowchart

```
                 +-----------------------------------------+
                 |       Administrator Web Dashboard       |
                 +-----------------------------------------+
                                      |
                     [Auto 30s Poll / Manual Check]
                                      v
                 +-----------------------------------------+
                 |         Flask Backend Controller        |
                 +-----------------------------------------+
                                      |
                           Step 1: ICMP / Ping Check
                                      v
                             Is Host Reachable?
                                    /    \
                           NO      /      \      YES
                          --------         --------
                         |                         |
                         v                         v
                   [Status: DOWN]        Is TCP Port Configured?
               "Device unreachable"               /    \
                         |               NO      /      \      YES
                         |              --------         --------
                         |             |                         |
                         |             v                         v
                         |       [Status: UP]        Step 2: TCP Socket Check
                         |        "Normal"                       |
                         |             |                Is TCP Port Open?
                         |             |                     /    \
                         |             |            NO      /      \      YES
                         |             |           --------         --------
                         |             |          |                         |
                         |             |          v                         v
                         |             |   [Status: FAULT]            [Status: UP]
                         |             |  "Port unavailable"           "Normal"
                         |             |          |                         |
                         +-------------+----------+-------------------------+
                                                  |
                                                  v
                                     Save Probe Result into SQLite
                                   (device_id, status, rtt, fault)
                                                  v
                                   Update UI Metrics & Audit Log
```

---

## 4. Status Classification Logic

| Status | Condition | Ping Result | TCP Port Result | Fault Message |
| :--- | :--- | :--- | :--- | :--- |
| **`UP`** | Host reachable & service healthy | Reply received (0% loss) | Connected successfully (or no port set) | `"-"` / Normal |
| **`DOWN`** | Host completely unreachable | Request timed out / Host unreachable | Skipped | `"Device unreachable"` |
| **`FAULT`** | Host online, but service crashed / blocked | Reply received (0% loss) | Connection refused / timed out | `"Device reachable but service/port unavailable"` |

---

## 5. Technology Stack

- **Backend:** Python 3.10+ & Flask 3.x
- **Database:** SQLite 3 (embedded, zero-configuration)
- **Networking:**
  - ICMP Ping via subprocess (cross-platform for Windows, Linux, and macOS)
  - TCP handshake probe via standard library `socket`
- **Frontend:**
  - HTML5 & Vanilla CSS3 (Custom Cyber-Clean Dark Theme)
  - JavaScript (Fetch API, live polling, and DOM updates)
  - Bootstrap 5 (Responsive grid & components)
  - FontAwesome 6 (Network & status iconography)

---

## 6. Directory Structure

```
Computer network Project/
│
├── app.py              # Main Flask application and REST API endpoints
├── config.py           # Application settings, timeouts, and database paths
├── database.py         # SQLite schema initialization, queries, and migrations
├── monitor.py          # Real ICMP & TCP socket probes, background worker
├── seed.py             # Demo seeder to pre-populate devices for viva/presentations
├── requirements.txt    # Python dependencies (Flask)
├── README.md           # Documentation and user manual
│
├── templates/          # Jinja2 HTML templates
│   ├── base.html       # Base layout with navbar, alerts, and footer
│   ├── dashboard.html  # Main dashboard with live cards and status table
│   ├── devices.html    # Registered device management view
│   ├── add_device.html # Device registration and editing form with demo presets
│   └── history.html    # Historical audit trail with filters and log cleanup
│
├── static/
│   ├── css/
│   │   └── style.css   # Dark glassmorphic aesthetic & status badge styles
│   └── js/
│       └── dashboard.js# AJAX check handlers, live polling, and modals
│
└── data/
    └── netfault.db     # SQLite database storage (auto-created)
```

---

## 7. Installation & Setup

### Prerequisites
- Python 3.10 or higher installed (`python --version`)
- Standard terminal (PowerShell, Command Prompt, or Bash)

### Step 1: Open the Project Directory
```powershell
cd "c:\Users\Kavidhrashan S\OneDrive\Desktop\Projects\Computer network Project"
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 8. Running the Application

### Option A: Quick Demo Seeding (Recommended for Evaluation)
To populate the database with sample nodes covering **UP**, **DOWN**, and **FAULT** conditions:
```powershell
python seed.py
```

### Option B: Start the Web Server
```powershell
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 9. How to Test UP, DOWN, and FAULT States

For your college demo or lab evaluation, register the following devices:

### Test 1: Testing `UP` Condition (Ping only)
- **Device Name:** `Google DNS`
- **IP Address:** `8.8.8.8`
- **TCP Port:** *(Leave empty)*
- **Expected Result:** Status displays **UP** in green badge, response time ~10-40 ms, Fault info `"-"`.

### Test 2: Testing `UP` Condition (Ping + Open Port)
- **Device Name:** `NetFault Web Server`
- **IP Address:** `127.0.0.1`
- **TCP Port:** `5000`
- **Expected Result:** Status displays **UP**, since local host replies to ping and Flask is listening on port 5000.

### Test 3: Testing `FAULT` Condition (Ping UP + Closed Port)
- **Device Name:** `Closed Service Node`
- **IP Address:** `127.0.0.1`
- **TCP Port:** `9999`
- **Expected Result:** Status displays **FAULT** in amber badge. Ping succeeds (`127.0.0.1`), but port `9999` refuses the connection. Fault info shows:
  `"Device reachable but service/port unavailable"`.

### Test 4: Testing `DOWN` Condition (Ping Unreachable)
- **Device Name:** `Dead Gateway`
- **IP Address:** `192.0.2.1` (or non-routable dummy IP)
- **TCP Port:** *(Leave empty)*
- **Expected Result:** Status displays **DOWN** in red badge, response time `N/A`, Fault info shows:
  `"Device unreachable"`.

*(Tip: In the "Add Device" page, click the **Quick Demo Test Presets** buttons to auto-populate any of these test cases with one click!)*

---

## 10. Database Schema (SQLite)

### Table: `devices`
Stores registered network devices configured by the administrator:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `device_name` (TEXT NOT NULL)
- `ip_address` (TEXT NOT NULL)
- `tcp_port` (INTEGER NULLABLE)
- `description` (TEXT)
- `created_at` (TIMESTAMP)

### Table: `monitoring_results`
Stores every periodic probe and manual check:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `device_id` (INTEGER FOREIGN KEY -> devices.id ON DELETE CASCADE)
- `status` (TEXT: 'UP', 'DOWN', 'FAULT')
- `response_time` (REAL: Latency in ms, or NULL)
- `fault_info` (TEXT: Error details or '-')
- `checked_at` (TIMESTAMP)

---

## 11. REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web Dashboard view |
| `GET` | `/api/dashboard` | JSON summary statistics & latest device statuses |
| `GET` | `/api/devices` | JSON list of all registered devices |
| `POST` | `/api/devices` | Register a new device |
| `GET` | `/api/devices/<id>` | Fetch specific device details |
| `POST` | `/api/devices/<id>/update` | Update device name, IP, port, description |
| `POST` | `/api/devices/<id>/delete` | Delete a device and cascade delete its logs |
| `POST` | `/api/devices/<id>/check` | Immediately trigger manual probe for one device |
| `POST` | `/api/monitor` | Trigger manual probe across all devices |
| `GET` | `/api/history` | Query historical logs with `device_id` & `status` filters |
| `POST` | `/api/history/clear` | Purge audit history logs |
| `GET/POST`| `/api/settings` | Query or update auto-monitor interval and toggle |

---

## 12. Future Enhancements

- **Email / Discord Alerts:** Send automated notifications when a node transitions from UP to DOWN.
- **SNMP Monitoring:** Query CPU, memory, and interface bandwidth statistics.
- **Traceroute Integration:** Visual network path hop-by-hop latency graph.
- **Subnet Auto-Discovery:** Scan an authorized subnet to discover online nodes automatically.
