"""
Unit tests for Supabase database module:
Client configuration, initialization, device CRUD with UUIDs, duplicate checks,
monitoring history, fault reporting, concurrency settings, and CASCADE deletions.
"""

import unittest
import json
import uuid
import database
from tests.mock_supabase import MockSupabaseClient

class TestSupabaseDatabase(unittest.TestCase):
    def setUp(self):
        self.mock_client = MockSupabaseClient()
        database.set_supabase_client(self.mock_client)
        database.init_db(client=self.mock_client)

    def tearDown(self):
        database.set_supabase_client(None)

    def test_database_initialization(self):
        """Verify default settings and admin user are initialized."""
        settings = database.get_settings(client=self.mock_client)
        self.assertIn('monitor_interval', settings)
        self.assertIn('ping_timeout', settings)
        self.assertIn('concurrency_limit', settings)
        self.assertIn('auto_monitoring', settings)

        user = database.get_user_by_email('admin@supabase.local', client=self.mock_client)
        self.assertIsNotNone(user)
        self.assertEqual(user['email'], 'admin@supabase.local')

    def test_device_crud_operations_with_uuid(self):
        """Test device insertion returns UUID, retrieval, update, and deletion."""
        dev_id = database.create_device(
            device_name="Test Gateway",
            ip_address="192.168.1.1",
            port=80,
            description="Local router",
            monitoring_enabled=1,
            client=self.mock_client
        )
        self.assertIsNotNone(dev_id)
        # Verify valid UUID string returned
        val_uuid = uuid.UUID(str(dev_id))
        self.assertEqual(str(val_uuid), str(dev_id))

        dev = database.get_device_by_id(dev_id, client=self.mock_client)
        self.assertIsNotNone(dev)
        self.assertEqual(dev['device_name'], "Test Gateway")
        self.assertEqual(dev['ip_address'], "192.168.1.1")
        self.assertEqual(dev['port'], 80)
        self.assertTrue(dev['monitoring_enabled'])

        updated = database.update_device(
            device_id=dev_id,
            device_name="Updated Gateway",
            ip_address="192.168.1.254",
            port=443,
            description="Upgraded router",
            monitoring_enabled=0,
            client=self.mock_client
        )
        self.assertTrue(updated)

        dev_updated = database.get_device_by_id(dev_id, client=self.mock_client)
        self.assertEqual(dev_updated['device_name'], "Updated Gateway")
        self.assertEqual(dev_updated['ip_address'], "192.168.1.254")
        self.assertEqual(dev_updated['port'], 443)
        self.assertFalse(dev_updated['monitoring_enabled'])

        deleted = database.delete_device(dev_id, client=self.mock_client)
        self.assertTrue(deleted)
        self.assertIsNone(database.get_device_by_id(dev_id, client=self.mock_client))

    def test_duplicate_device_detection(self):
        """Ensure duplicate IP and port combinations are detected in Supabase."""
        database.create_device("Host A", "10.0.0.1", 80, client=self.mock_client)
        database.create_device("Host B", "10.0.0.2", None, client=self.mock_client)

        self.assertTrue(database.check_duplicate_device("10.0.0.1", 80, client=self.mock_client))
        self.assertFalse(database.check_duplicate_device("10.0.0.1", 443, client=self.mock_client))
        self.assertTrue(database.check_duplicate_device("10.0.0.2", None, client=self.mock_client))

    def test_monitoring_history_and_fault_reports(self):
        """Test recording results, fault categorization, timeseries, and CASCADE deletion."""
        dev_id = database.create_device("Test Node", "127.0.0.1", 8080, client=self.mock_client)

        hist_id = database.record_monitoring_result(
            device_id=dev_id,
            reachability_status="REACHABLE",
            service_status="REFUSED",
            overall_status="FAULT",
            response_time_ms=1.45,
            fault_category="SERVICE_REFUSED",
            fault_details="Port 8080 connection refused",
            client=self.mock_client
        )
        self.assertIsNotNone(hist_id)

        history = database.get_device_history(dev_id, client=self.mock_client)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['overall_status'], 'FAULT')
        self.assertEqual(history[0]['fault_category'], 'SERVICE_REFUSED')

        faults = database.get_fault_reports(client=self.mock_client)
        self.assertEqual(len(faults), 1)
        self.assertEqual(faults[0]['fault_category'], 'SERVICE_REFUSED')
        self.assertEqual(faults[0]['consecutive_failures'], 1)

        # Timeseries test
        timeseries = database.get_history_timeseries(device_id=dev_id, client=self.mock_client)
        self.assertEqual(len(timeseries['response_times']), 1)

        # Cascade delete verification
        database.delete_device(dev_id, client=self.mock_client)
        history_after = database.get_device_history(dev_id, client=self.mock_client)
        self.assertEqual(len(history_after), 0)

    def test_settings_update(self):
        """Test reading and writing settings to Supabase application_settings."""
        database.update_settings(
            monitor_interval=45,
            ping_timeout=4,
            tcp_timeout=5,
            ping_count=3,
            concurrency_limit=8,
            auto_monitoring=0,
            client=self.mock_client
        )
        settings = database.get_settings(client=self.mock_client)
        self.assertEqual(settings['monitor_interval'], 45)
        self.assertEqual(settings['ping_timeout'], 4)
        self.assertEqual(settings['tcp_timeout'], 5)
        self.assertEqual(settings['ping_count'], 3)
        self.assertEqual(settings['concurrency_limit'], 8)
        self.assertEqual(settings['auto_monitoring'], 0)

    def test_traceroute_persistence(self):
        """Test saving, retrieving, and cascade deleting traceroute records in Supabase."""
        dev_id = database.create_device(
            device_name="Traceroute Target",
            ip_address="8.8.8.8",
            client=self.mock_client
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
            client=self.mock_client
        )
        self.assertIsNotNone(trace_id)

        traces = database.get_device_traceroutes(dev_id, client=self.mock_client)
        self.assertEqual(len(traces), 1)
        self.assertTrue(traces[0]['destination_reached'])
        self.assertEqual(traces[0]['total_hops'], 2)

        single_trace = database.get_traceroute_by_id(trace_id, client=self.mock_client)
        self.assertIsNotNone(single_trace)
        self.assertEqual(single_trace['target_ip'], "8.8.8.8")

        # Cascade delete verification
        database.delete_device(dev_id, client=self.mock_client)
        traces_after = database.get_device_traceroutes(dev_id, client=self.mock_client)
        self.assertEqual(len(traces_after), 0)

    def test_user_authentication(self):
        """Test user verification with hashed password."""
        verified = database.verify_user_credentials('admin@supabase.local', 'admin123', client=self.mock_client)
        self.assertIsNotNone(verified)
        self.assertEqual(verified['email'], 'admin@supabase.local')

        wrong_pw = database.verify_user_credentials('admin@supabase.local', 'wrong_pass', client=self.mock_client)
        self.assertIsNone(wrong_pw)

if __name__ == '__main__':
    unittest.main()
