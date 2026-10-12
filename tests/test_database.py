"""
Unit tests for database module:
Schema creation, device CRUD, duplicate checks, monitoring history, and settings persistence.
"""

import os
import unittest
import tempfile
import database

class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Create a temporary SQLite database file for isolation
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        database.init_db(self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_database_initialization(self):
        """Verify tables and settings were created."""
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

    def test_device_crud_operations(self):
        """Test device insertion, retrieval, update, and deletion."""
        # Create
        dev_id = database.create_device(
            device_name="Test Gateway",
            ip_address="192.168.1.1",
            port=80,
            description="Local router",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(dev_id)

        # Read
        dev = database.get_device_by_id(dev_id, db_path=self.temp_db_path)
        self.assertEqual(dev['device_name'], "Test Gateway")
        self.assertEqual(dev['ip_address'], "192.168.1.1")
        self.assertEqual(dev['port'], 80)

        # Update
        updated = database.update_device(
            device_id=dev_id,
            device_name="Updated Gateway",
            ip_address="192.168.1.254",
            port=443,
            description="Upgraded router",
            db_path=self.temp_db_path
        )
        self.assertTrue(updated)
        dev_updated = database.get_device_by_id(dev_id, db_path=self.temp_db_path)
        self.assertEqual(dev_updated['device_name'], "Updated Gateway")
        self.assertEqual(dev_updated['ip_address'], "192.168.1.254")
        self.assertEqual(dev_updated['port'], 443)

        # Delete
        deleted = database.delete_device(dev_id, db_path=self.temp_db_path)
        self.assertTrue(deleted)
        self.assertIsNone(database.get_device_by_id(dev_id, db_path=self.temp_db_path))

    def test_duplicate_device_detection(self):
        """Ensure duplicate IP and port combinations are properly detected."""
        database.create_device("Host A", "10.0.0.1", 80, db_path=self.temp_db_path)
        database.create_device("Host B", "10.0.0.2", None, db_path=self.temp_db_path)

        # Duplicate with port
        self.assertTrue(database.check_duplicate_device("10.0.0.1", 80, db_path=self.temp_db_path))
        # Different port on same IP is allowed
        self.assertFalse(database.check_duplicate_device("10.0.0.1", 443, db_path=self.temp_db_path))
        # Duplicate without port
        self.assertTrue(database.check_duplicate_device("10.0.0.2", None, db_path=self.temp_db_path))

    def test_monitoring_history_cascade(self):
        """Ensure monitoring history is saved and deleted via CASCADE when device is removed."""
        dev_id = database.create_device("Test Node", "127.0.0.1", 8080, db_path=self.temp_db_path)
        
        hist_id = database.record_monitoring_result(
            device_id=dev_id,
            reachability_status="REACHABLE",
            service_status="OPEN",
            overall_status="UP",
            response_time_ms=1.45,
            fault_details="All checks nominal",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(hist_id)

        history = database.get_device_history(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['overall_status'], 'UP')
        self.assertEqual(history[0]['response_time_ms'], 1.45)

        # Cascade delete verification
        database.delete_device(dev_id, db_path=self.temp_db_path)
        history_after = database.get_device_history(dev_id, db_path=self.temp_db_path)
        self.assertEqual(len(history_after), 0)

    def test_settings_update(self):
        """Test reading and writing settings."""
        database.update_settings(
            monitor_interval=45,
            ping_timeout=4,
            tcp_timeout=5,
            ping_count=3,
            db_path=self.temp_db_path
        )
        settings = database.get_settings(self.temp_db_path)
        self.assertEqual(settings['monitor_interval'], 45)
        self.assertEqual(settings['ping_timeout'], 4)
        self.assertEqual(settings['tcp_timeout'], 5)
        self.assertEqual(settings['ping_count'], 3)

if __name__ == '__main__':
    unittest.main()
