"""
NetFault – Seed Script for College Project Demonstrations & Testing
Pre-populates the database with 4 representative network devices:
1. Google Public DNS (8.8.8.8) -> Ping only -> UP
2. Local Web Service (127.0.0.1:5000) -> Ping & Open Port -> UP
3. Simulated Service Fault (127.0.0.1:9999) -> Ping UP, Closed Port -> FAULT
4. Unreachable Host (192.0.2.1) -> Ping Timed Out -> DOWN
"""

import database
import monitor

def seed():
    print("=" * 60)
    print("NetFault – Seeding Sample Network Devices for Demo")
    print("=" * 60)
    
    database.init_db()
    
    # Clear previous sample data
    conn = database.get_db_connection()
    conn.execute("DELETE FROM monitoring_results")
    conn.execute("DELETE FROM devices")
    conn.commit()
    conn.close()
    
    # Add Sample Devices
    devices_data = [
        ("Google Public DNS", "8.8.8.8", None, "High availability public DNS resolver (ICMP only)"),
        ("NetFault App Server", "127.0.0.1", 5000, "Local Flask application web service"),
        ("Simulated Fault Server", "127.0.0.1", 9999, "Reachable local host with closed port 9999"),
        ("Offline Host", "192.0.2.1", None, "Unreachable documentation/test subnet address")
    ]
    
    print("\nRegistering sample devices...")
    device_ids = []
    for name, ip, port, desc in devices_data:
        d_id = database.add_device(name, ip, port, desc)
        device_ids.append(d_id)
        print(f" [+] Added: {name} ({ip}:{port or 'None'}) [ID: {d_id}]")
        
    print("\nRunning initial network health probes (ICMP + TCP)...")
    for d_id in device_ids:
        dev = database.get_device_by_id(d_id)
        res = monitor.evaluate_device(dev)
        print(f" [*] Probed {dev['device_name']} -> Status: {res['status']} | Latency: {res['response_time']} ms | Fault: {res['fault_info']}")
        
    stats = database.get_dashboard_stats()
    print("\nSeeding complete! Current Dashboard Summary:")
    print(f" - Total Devices : {stats['total_devices']}")
    print(f" - UP Devices    : {stats['up_devices']}")
    print(f" - DOWN Devices  : {stats['down_devices']}")
    print(f" - FAULT Devices : {stats['fault_devices']}")
    print("=" * 60)

if __name__ == "__main__":
    seed()
