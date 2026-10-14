# Automated Fault Detection System (AFDS)
## Enterprise Network Monitoring with Supabase PostgreSQL

An enterprise-grade, laboratory-oriented network monitoring and automated fault detection web application built with Python Flask, ICMP/Ping subprocess integration, raw TCP socket programming, **Supabase PostgreSQL** cloud persistence, and a modern, high-contrast light beige dashboard.

Designed specifically as a **Computer Networks Laboratory Project**, this application enables network administrators and laboratory instructors to register endpoints (IPv4/IPv6), verify end-to-end ICMP reachability, inspect specific TCP service socket availability, track historical fault occurrences, and configure monitoring thresholds through a secure, professional web console.

---

## 1. Abstract

Modern enterprise and campus networks require continuous monitoring to ensure high availability of critical services. Traditional network troubleshooting often relies on manual command-line utilities such as `ping` and `telnet`, which are inefficient for multi-host infrastructures. The **Automated Fault Detection System (AFDS)** solves this problem by centralizing real-time connectivity testing and transport-layer verification into an automated, periodic web platform.

By combining Internet Control Message Protocol (ICMP) echo requests with raw TCP three-way handshake socket probes, AFDS categorizes the health of each registered device into deterministic operational states (`UP`, `DOWN`, `FAULT`, or `UNKNOWN`), measuring precise latencies and archiving historical diagnostics in a persistent, cloud-hosted **Supabase PostgreSQL** database.

---

## 2. Key Architecture & Features

1. **Network-Layer Reachability (ICMP)**: Native OS-level echo probes determine whether the host IP route is operational and calculate true round-trip time (RTT).
2. **Transport-Layer Verification (TCP Sockets)**: Standard Python BSD socket connections verify whether configured application ports (HTTP `80`, HTTPS `443`, SSH `22`, Flask `5000`, etc.) actively complete the TCP 3-way handshake.
3. **Deterministic Fault Triangulation**: The system distinguishes between general connectivity loss (`DOWN`) and service-specific failure (`FAULT`), recording granular error descriptions (e.g., connection refused, timeout, network unreachable).
4. **Supabase PostgreSQL Persistence**: All network targets, monitoring audits, persistent settings, hop-by-hop traceroute diagnostics, and administrator credentials reside in Supabase PostgreSQL with UUID primary keys and cascading foreign keys.
5. **Local Session Authentication**: Built-in credential verification (`admin@supabase.local` / `admin123`) storing salted password hashes directly in the Supabase `users` table without requiring Supabase GoTrue Auth.
6. **Autonomous Background Worker**: A dedicated Python background thread executes scheduled monitoring cycles at configurable intervals without blocking the Flask web server.
7. **Modern Light Beige UI**: Sophisticated warm linen/beige palette (`#f6f3ed`, `#fdfbf7`, `#e6dfd3`, `#1c1917`) replacing harsh, stark white with refined high-contrast readability.

---

## 3. Technology Stack

- **Backend Framework**: Python 3.10+ / Flask 3.0+
- **Database Engine**: Supabase PostgreSQL (via official `supabase` SDK)
- **Network Layer Protocol**: ICMP Echo (via OS ping subprocess without shell interpolation)
- **Transport Layer Protocol**: TCP Socket Programming (`socket.SOCK_STREAM`)
- **Frontend Architecture**: Semantic HTML5, Vanilla CSS3 (Modern Light Beige Design System), Vanilla JavaScript (Fetch API), Chart.js (offline local bundle)
- **Testing**: `pytest` and `unittest` with in-memory `MockSupabaseClient` for 100% offline test coverage

---

## 4. Supabase Database Schema

The complete PostgreSQL schema is defined in [`supabase/migrations/001_initial_schema.sql`](supabase/migrations/001_initial_schema.sql):

### Tables

1. **`devices`**:
   - `id`: UUID Primary Key (`gen_random_uuid()`)
   - `device_name`: TEXT, required
   - `ip_address`: TEXT, validated IPv4 or IPv6
   - `port`: INTEGER, nullable (1–65535)
   - `description`: TEXT, nullable
   - `monitoring_enabled`: BOOLEAN, default `TRUE`
   - `created_at` / `updated_at`: TIMESTAMPTZ
   - Unique Index: `idx_devices_ip_port_unique` on `(ip_address, COALESCE(port, -1))`

2. **`monitoring_history`**:
   - `id`: UUID Primary Key
   - `device_id`: UUID Foreign Key referencing `devices(id)` ON DELETE CASCADE
   - `checked_at`: TIMESTAMPTZ
   - `reachability_status`: TEXT (`REACHABLE`, `UNREACHABLE`, `FILTERED`)
   - `service_status`: TEXT (`OPEN`, `REFUSED`, `TIMEOUT`, `CLOSED`, `NOT_CONFIGURED`)
   - `overall_status`: TEXT (`UP`, `DOWN`, `FAULT`, `UNKNOWN`)
   - `response_time_ms`: DOUBLE PRECISION
   - `fault_category` / `fault_details`: Diagnostic context

3. **`application_settings`**:
   - `id`: UUID Primary Key
   - `setting_key`: TEXT UNIQUE
   - `setting_value`: JSONB (interval, timeouts, ping count, worker concurrency limit)
   - `updated_at`: TIMESTAMPTZ

4. **`traceroute_history`**:
   - `id`: UUID Primary Key
   - `device_id`: UUID Foreign Key referencing `devices(id)` ON DELETE CASCADE
   - `target_ip`: TEXT
   - `total_hops`: INTEGER
   - `destination_reached`: BOOLEAN
   - `fault_hop`: INTEGER
   - `fault_summary`: TEXT
   - `hops_json`: JSONB array of hop details
   - `raw_output`: TEXT
   - `executed_at`: TIMESTAMPTZ

5. **`users`**:
   - `id`: UUID Primary Key
   - `email`: TEXT UNIQUE
   - `password_hash`: TEXT (werkzeug scrypt hash)
   - `full_name`: TEXT
   - `role`: TEXT default `'admin'`
   - `created_at` / `updated_at`: TIMESTAMPTZ

### Views

- **`devices_with_status`**: Combines device attributes with their single most recent check from `monitoring_history`.
- **`monitoring_history_with_devices`**: Enriches history records with device name, IP address, and port.

---

## 5. Step-by-Step Supabase Setup Guide

Follow these steps to link your Supabase PostgreSQL project:

### Step 1: Create a Supabase Project
1. Go to [https://supabase.com](https://supabase.com) and log in.
2. Click **New Project**.
3. Choose an organization, enter a name (e.g. `netfault-monitor`), set a database password, and select your preferred region.
4. Click **Create new project** and wait ~1 minute for provisioning.

### Step 2: Run the Database Schema Migration
1. In your Supabase Project Dashboard, click on **SQL Editor** in the left sidebar.
2. Click **New Query**.
3. Open [`supabase/migrations/001_initial_schema.sql`](supabase/migrations/001_initial_schema.sql) from this repository, copy its entire contents, and paste it into the Supabase SQL Editor.
4. Click **Run** (or press `Ctrl+Enter`).
5. Confirm that all tables (`devices`, `monitoring_history`, `application_settings`, `traceroute_history`, `users`) and views (`devices_with_status`, `monitoring_history_with_devices`) are created.

### Step 3: Retrieve Project API Credentials
1. In the Supabase dashboard, click the **Settings (gear icon)** at the bottom of the left sidebar.
2. Select **API** (under Project Settings).
3. Under **Project URL**, copy the URL (e.g. `https://xyzprojectid.supabase.co`).
4. Under **Project API keys**, find the **`service_role` (secret)** key. Click **Reveal** and copy it.
   > **Security Notice**: Keep the `service_role` key private. It is used strictly server-side by Flask and is never exposed in frontend templates or browser requests.

### Step 4: Configure Local `.env`
1. In the root directory of this repository, open `.env` (or copy `.env.example` to `.env`):
   ```env
   SUPABASE_URL=https://your-project-id.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=your-actual-service-role-key-here
   SECRET_KEY=afds-supabase-network-monitor-key-2026-secure
   ADMIN_EMAIL=admin@supabase.local
   ADMIN_PASSWORD=admin123
   PORT=5000
   HOST=127.0.0.1
   ```
2. Replace `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` with your real Supabase credentials.

---

## 6. Optional: One-Time Data Import from Existing SQLite

If you have an existing SQLite database (e.g., `instance/network_monitor.db`) containing prior records, migrate them to Supabase in one command:

```powershell
python scripts/import_sqlite_to_supabase.py
```

This utility:
- Reads existing devices, history, settings, and traceroutes from SQLite.
- Generates new Supabase UUIDs and maps foreign keys properly.
- Skips duplicate devices based on IP and Port.
- Never modifies or deletes your original SQLite database file.

---

## 7. Windows Installation & Running the Application

### 1. Install Dependencies
Ensure Python 3.10+ is installed on your Windows machine:
```powershell
pip install -r requirements.txt
```

### 2. Start the Flask Application
```powershell
python app.py
```

Console Output:
```text
=================================================================
 AUTOMATED FAULT DETECTION SYSTEM (AFDS)
 Powered by Supabase PostgreSQL Database
 Web Interface: http://127.0.0.1:5000
 Default Admin: admin@supabase.local / admin123
=================================================================
```

### 3. Open the Web Console
Visit the local link in your browser:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 4. Log In
- **Email**: `admin@supabase.local`
- **Password**: `admin123`

---

## 8. Status Classification Rules

Every target device monitored by AFDS is classified into one of four deterministic operational states:

| Status Badge | State Name | Technical Definition | Condition |
| :---: | :---: | :--- | :--- |
| `● UP` | **Operational** | Host responds to ICMP ping AND its configured TCP service is accepting connections (or ICMP succeeds when no port is configured). Also applies if ICMP is blocked by firewall policy but the TCP service socket completes handshake. | `Ping: OK` + `TCP: Open`<br>or `Ping: OK` + `Port: None`<br>or `Ping: Blocked` + `TCP: Open` |
| `▲ FAULT` | **Service Fault** | Device responds to ICMP ping (Layer 3 reachable), but the configured TCP port actively refuses the connection, times out, or fails (Layer 4/7 issue). | `Ping: OK` + `TCP: Refused / Timeout` |
| `✕ DOWN` | **Offline / Unreachable** | Host does not respond to ICMP ping AND its configured TCP service fails to connect or times out. | `Ping: Fail` + `TCP: Fail / None` |
| `○ UNCHECKED` | **Pending / Unknown** | Device newly registered; awaiting its first monitoring cycle. | Prior to execution |

---

## 9. Running Automated Tests

AFDS features an extensive unit test suite with mocked Supabase responses:

```powershell
python -m pytest
```

Output:
```text
tests\test_database.py .......                                           [ 16%]
tests\test_devices.py ......                                             [ 30%]
tests\test_monitoring.py ..............                                  [ 64%]
tests\test_routes.py ...............                                     [100%]

============================= 42 passed in 11.91s =============================
```

Tests cover:
- Supabase client initialization & error handling
- Device CRUD with UUIDs
- Duplicate device detection
- History audit insertion & cascade deletions
- Fault reporting analytics & time-series generation
- System settings persistence
- Hop-by-hop traceroute persistence
- Session authentication & route protection
- ICMP ping and raw TCP socket classification
- CSV exports & JSON API endpoints

---

## 10. License & Academic Attribution

Developed as a **Computer Networks Laboratory Project**. Demonstrates socket programming, ICMP subprocess handling, concurrent thread management, and modern cloud database architecture with Supabase PostgreSQL.
