"""
Unit tests for device operations, search, filters, sorting, and scheduler concurrency.
"""

import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import database
from scheduler import MonitoringScheduler

class TestDevices(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        database.init_db(self.temp_db_path)

        # Create multiple test devices for search/filter tests
        self.dev1 = database.create_device("Core Switch", "10.0.0.1", None, "Main backbone switch", 1, self.temp_db_path)
        self.dev2 = database.create_device("Web Application", "10.0.0.2", 80, "HTTP server", 1, self.temp_db_path)
        self.dev3 = database.create_device("Database Master", "10.0.0.3", 5432, "PostgreSQL node", 0, self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_search_devices_by_name_and_ip(self):
        """Test searching devices by substring in name or IP."""
        results = database.get_all_devices(search="Switch", db_path=self.temp_db_path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['device_name'], "Core Switch")

        results_ip = database.get_all_devices(search="10.0.0.2", db_path=self.temp_db_path)
        self.assertEqual(len(results_ip), 1)
        self.assertEqual(results_ip[0]['device_name'], "Web Application")

    def test_sort_devices(self):
        """Test sorting devices by name ascending and descending."""
        asc = database.get_all_devices(sort_by="name", sort_dir="asc", db_path=self.temp_db_path)
        self.assertEqual(asc[0]['device_name'], "Core Switch")

        desc = database.get_all_devices(sort_by="name", sort_dir="desc", db_path=self.temp_db_path)
        self.assertEqual(desc[0]['device_name'], "Web Application")

    def test_pagination_devices(self):
        """Test pagination limit and offset."""
        page1 = database.get_all_devices(page=1, per_page=2, db_path=self.temp_db_path)
        self.assertEqual(len(page1), 2)

        page2 = database.get_all_devices(page=2, per_page=2, db_path=self.temp_db_path)
        self.assertEqual(len(page2), 1)

    def test_toggle_device_monitoring(self):
        """Test toggling monitoring between enabled and disabled."""
        new_status = database.toggle_device_monitoring(self.dev1, db_path=self.temp_db_path)
        self.assertEqual(new_status, 0)
        dev = database.get_device_by_id(self.dev1, db_path=self.temp_db_path)
        self.assertEqual(dev['monitoring_enabled'], 0)

        # Toggle back
        new_status = database.toggle_device_monitoring(self.dev1, db_path=self.temp_db_path)
        self.assertEqual(new_status, 1)

    def test_duplicate_port_collision_rule(self):
        """Test collision rules: same IP with same port collides, distinct port allowed."""
        self.assertTrue(database.check_duplicate_device("10.0.0.2", 80, db_path=self.temp_db_path))
        self.assertFalse(database.check_duplicate_device("10.0.0.2", 443, db_path=self.temp_db_path))
        # Excluding self ID during update allows keeping same port
        self.assertFalse(database.check_duplicate_device("10.0.0.2", 80, exclude_id=self.dev2, db_path=self.temp_db_path))

    @patch('monitoring.check_device_connectivity')
    def test_scheduler_check_all_enabled_filtering(self, mock_check):
        """Scheduler checks only enabled devices when only_enabled=True."""
        mock_check.return_value = {
            'device_id': 1,
            'reachability_status': 'REACHABLE',
            'service_status': 'OPEN',
            'overall_status': 'UP',
            'response_time_ms': 5.0,
            'fault_category': 'NONE',
            'fault_details': 'Nominal'
        }

        scheduler_inst = MonitoringScheduler()
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            with patch('database.get_all_devices') as mock_get_all:
                mock_get_all.return_value = [
                    {'id': self.dev1, 'monitoring_enabled': 1},
                    {'id': self.dev2, 'monitoring_enabled': 1},
                    {'id': self.dev3, 'monitoring_enabled': 0}
                ]
                with patch.object(scheduler_inst, 'check_single_device', return_value={'ok': True}) as mock_single:
                    scheduler_inst.check_all_devices(only_enabled=True)
                    # Should only check 2 enabled devices
                    self.assertEqual(mock_single.call_count, 2)

if __name__ == '__main__':
    unittest.main()
