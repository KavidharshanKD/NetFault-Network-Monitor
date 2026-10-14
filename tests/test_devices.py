"""
Unit tests for device operations, search, filters, sorting, and scheduler concurrency with Supabase.
"""

import unittest
from unittest.mock import patch, MagicMock
import database
from scheduler import MonitoringScheduler
from tests.mock_supabase import MockSupabaseClient

class TestDevices(unittest.TestCase):
    def setUp(self):
        self.mock_client = MockSupabaseClient()
        database.set_supabase_client(self.mock_client)
        database.init_db(client=self.mock_client)

        # Create multiple test devices for search/filter tests
        self.dev1 = database.create_device("Core Switch", "10.0.0.1", None, "Main backbone switch", 1, client=self.mock_client)
        self.dev2 = database.create_device("Web Application", "10.0.0.2", 80, "HTTP server", 1, client=self.mock_client)
        self.dev3 = database.create_device("Database Master", "10.0.0.3", 5432, "PostgreSQL node", 0, client=self.mock_client)

    def tearDown(self):
        database.set_supabase_client(None)

    def test_search_devices_by_name_and_ip(self):
        """Test searching devices by substring in name or IP."""
        results = database.get_all_devices(search="Switch", client=self.mock_client)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['device_name'], "Core Switch")

        results_ip = database.get_all_devices(search="10.0.0.2", client=self.mock_client)
        self.assertEqual(len(results_ip), 1)
        self.assertEqual(results_ip[0]['device_name'], "Web Application")

    def test_sort_devices(self):
        """Test sorting devices by name ascending and descending."""
        asc = database.get_all_devices(sort_by="name", sort_dir="asc", client=self.mock_client)
        self.assertEqual(asc[0]['device_name'], "Core Switch")

        desc = database.get_all_devices(sort_by="name", sort_dir="desc", client=self.mock_client)
        self.assertEqual(desc[0]['device_name'], "Web Application")

    def test_pagination_devices(self):
        """Test pagination limit and offset."""
        page1 = database.get_all_devices(page=1, per_page=2, client=self.mock_client)
        self.assertEqual(len(page1), 2)

        page2 = database.get_all_devices(page=2, per_page=2, client=self.mock_client)
        self.assertEqual(len(page2), 1)

    def test_toggle_device_monitoring(self):
        """Test toggling monitoring between enabled and disabled."""
        new_status = database.toggle_device_monitoring(self.dev1, client=self.mock_client)
        self.assertEqual(new_status, 0)
        dev = database.get_device_by_id(self.dev1, client=self.mock_client)
        self.assertFalse(dev['monitoring_enabled'])

        # Toggle back
        new_status = database.toggle_device_monitoring(self.dev1, client=self.mock_client)
        self.assertEqual(new_status, 1)

    def test_duplicate_port_collision_rule(self):
        """Test collision rules: same IP with same port collides, distinct port allowed."""
        self.assertTrue(database.check_duplicate_device("10.0.0.2", 80, client=self.mock_client))
        self.assertFalse(database.check_duplicate_device("10.0.0.2", 443, client=self.mock_client))
        # Excluding self ID during update allows keeping same port
        self.assertFalse(database.check_duplicate_device("10.0.0.2", 80, exclude_id=self.dev2, client=self.mock_client))

    @patch('monitoring.check_device_connectivity')
    def test_scheduler_check_all_enabled_filtering(self, mock_check):
        """Scheduler checks only enabled devices when only_enabled=True."""
        mock_check.return_value = {
            'device_id': self.dev1,
            'reachability_status': 'REACHABLE',
            'service_status': 'OPEN',
            'overall_status': 'UP',
            'response_time_ms': 5.0,
            'fault_category': 'NONE',
            'fault_details': 'Nominal'
        }

        scheduler_inst = MonitoringScheduler()
        with patch.object(scheduler_inst, 'check_single_device', return_value={'ok': True}) as mock_single:
            scheduler_inst.check_all_devices(only_enabled=True)
            # Should only check the 2 enabled devices (dev1 and dev2)
            self.assertEqual(mock_single.call_count, 2)

if __name__ == '__main__':
    unittest.main()
