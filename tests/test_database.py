"""
Unit tests for database module:
Schema creation, device CRUD, duplicate checks, monitoring history, fault reporting,
concurrency settings, and CASCADE deletions.
"""

import os
import json
import unittest
import tempfile
import database

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        database.init_db(self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_database_initialization(self):
        """Verify tables and default settings are initialized."""
        conn = database.get_db_connection(self.temp_db_path)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = [t['name'] for t in tables]
        conn.close()

        self.assertIn('devices', table_names)
        self.assertIn('monitoring_history', table_names)
        self.assertIn('settings', table_names)

        settings = database.get_settings(self.temp_db_path)
        self.assertIn('monitor_interval', settings)
        self.assertIn('ping_timeout', settings)
        self.assertIn('concurrency_limit', settings)
        self.assertIn('auto_monitoring', settings)

    def test_device_crud_operations(self):
        """Test device insertion, retrieval, update, and deletion."""
        dev_id = database.create_device(
            device_name="Test Gateway",
            ip_address="192.168.1.1",
            port=80,
            description="Local router",
            monitoring_enabled=1,
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(dev_id)

        dev = database.get_device_by_id(dev_id, db_path=self.temp_db_path)
        self.assertEqual(dev['device_name'], "Test Gateway")
        self.assertEqual(dev['ip_address'], "192.168.1.1")
        self.assertEqual(dev['port'], 80)
        self.assertEqual(dev['monitoring_enabled'], 1)

        updated = database.update_device(
            device_id=dev_id,
            device_name="Updated Gateway",
            ip_address="192.168.1.254",
            port=443,
            description="Upgraded router",
            monitoring_enabled=0,
            db_path=self.temp_db_path
        )
        self.assertTrue(updated)
        dev_updated = database.get_device_by_id(dev_id, db_path=self.temp_db_path)
        self.assertEqual(dev_updated['device_name'], "Updated Gateway")
        self.assertEqual(dev_updated['ip_address'], "192.168.1.254")
        self.assertEqual(dev_updated['port'], 443)
        self.assertEqual(dev_updated['monitoring_enabled'], 0)

        deleted = database.delete_device(dev_id, db_path=self.temp_db_path)
        self.assertTrue(deleted)
        self.assertIsNone(database.get_device_by_id(dev_id, db_path=self.temp_db_path))

    def test_duplicate_device_detection(self):
        """Ensure duplicate IP and port combinations are properly detected."""
        database.create_device("Host A", "10.0.0.1", 80, db_path=self.temp_db_path)
        database.create_device("Host B", "10.0.0.2", None, db_path=self.temp_db_path)

        self.assertTrue(database.check_duplicate_device("10.0.0.1", 80, db_path=self.temp_db_path))
        self.assertFalse(database.check_duplicate_device("10.0.0.1", 443, db_path=self.temp_db_path))
        self.assertTrue(database.check_duplicate_device("10.0.0.2", None, db_path=self.temp_db_path))

    def test_monitoring_history_and_fault_reports(self):
        """Test recording results, fault categorization, and fault queries."""
        dev_id = database.create_device("Test Node", "127.0.0.1", 8080, db_path=self.temp_db_path)
        
        hist_id = database.record_monitoring_result(
            device_id=dev_id,
            reachability_status="REACHABLE",
            service_status="REFUSED",
            overall_status="FAULT",
            response_time_ms=1.45,
            fault_category="SERVICE_REFUSED",
            fault_details="Port 8080 connection refused",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(hist_id)

        history = database.get_device_history(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['overall_status'], 'FAULT')
        self.assertEqual(history[0]['fault_category'], 'SERVICE_REFUSED')

        faults = database.get_fault_reports(db_path=self.temp_db_path)
        self.assertEqual(len(faults), 1)
        self.assertEqual(faults[0]['fault_category'], 'SERVICE_REFUSED')
        self.assertEqual(faults[0]['consecutive_failures'], 1)

        # Timeseries test
        timeseries = database.get_history_timeseries(device_id=dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(timeseries['response_times']), 1)

        # Cascade delete verification
        database.delete_device(dev_id, db_path=self.temp_db_path)
        history_after = database.get_device_history(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(history_after), 0)

    def test_settings_update(self):
        """Test reading and writing settings including concurrency and auto_monitoring."""
        database.update_settings(
            monitor_interval=45,
            ping_timeout=4,
            tcp_timeout=5,
            ping_count=3,
            concurrency_limit=8,
            auto_monitoring=0,
            db_path=self.temp_db_path
        )
        settings = database.get_settings(self.temp_db_path)
        self.assertEqual(settings['monitor_interval'], 45)
        self.assertEqual(settings['ping_timeout'], 4)
        self.assertEqual(settings['tcp_timeout'], 5)
        self.assertEqual(settings['ping_count'], 3)
        self.assertEqual(settings['concurrency_limit'], 8)
        self.assertEqual(settings['auto_monitoring'], 0)

    def test_traceroute_persistence(self):
        """Test saving, retrieving, and cascade deleting traceroute records."""
        dev_id = database.create_device(
            device_name="Traceroute Target",
            ip_address="8.8.8.8",
            db_path=self.temp_db_path
        )
        hops_sample = json.dumps([
            {"hop": 1, "ip": "192.168.1.1", "status": "SUCCESS"},
            {"hop": 2, "ip": "8.8.8.8", "status": "SUCCESS"}
        ])
        trace_id = database.save_traceroute(
            device_id=dev_id,
            target_ip="8.8.8.8",
            total_hops=2,
            destination_reached=True,
            fault_hop=None,
            fault_summary="Route complete in 2 hops",
            hops_json=hops_sample,
            raw_output="Hop 1\nHop 2\n",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(trace_id)

        traces = database.get_device_traceroutes(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]['destination_reached'], 1)
        self.assertEqual(traces[0]['total_hops'], 2)

        single_trace = database.get_traceroute_by_id(trace_id, db_path=self.temp_db_path)
        self.assertIsNotNone(single_trace)
        self.assertEqual(single_trace['target_ip'], "8.8.8.8")

        # Verify cascading delete
        database.delete_device(dev_id, db_path=self.temp_db_path)
        traces_after = database.get_device_traceroutes(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(traces_after), 0)

if __name__ == '__main__':
    unittest.main()
