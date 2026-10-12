"""
Unit tests for Flask routes and JSON API endpoints:
Views, forms, client/server validations, error handling, and API endpoints.
"""

import os
import unittest
import tempfile
from unittest.mock import patch
from app import create_app
import database

class TestRoutes(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        
        # Patch DATABASE_PATH in Config
        self.app = create_app()
        self.app.config['DATABASE_PATH'] = self.temp_db_path
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        # Initialize tables in temp database
        database.init_db(self.temp_db_path)

        # Seed test device
        with patch('scheduler.scheduler.check_single_device'):
            self.test_dev_id = database.create_device(
                device_name="Test Web Host",
                ip_address="127.0.0.1",
                port=5000,
                description="Local web node",
                db_path=self.temp_db_path
            )

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_dashboard_route(self):
        """Dashboard renders with 200 OK."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            response = self.client.get('/')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Network Monitoring Dashboard", response.data)

    def test_device_inventory_route(self):
        """Device inventory page lists registered device."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            response = self.client.get('/devices')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Test Web Host", response.data)

    def test_add_device_valid(self):
        """Submitting valid device form creates record and redirects."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            with patch('scheduler.scheduler.check_single_device'):
                response = self.client.post('/devices/add', data={
                    'device_name': 'Router Alpha',
                    'ip_address': '192.168.10.1',
                    'port': '80',
                    'description': 'Main router'
                }, follow_redirects=True)
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"Router Alpha", response.data)

    def test_add_device_invalid_ip(self):
        """Submitting invalid IP returns 400 Bad Request."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            response = self.client.post('/devices/add', data={
                'device_name': 'Invalid Host',
                'ip_address': 'not.an.ip.address',
                'port': '80',
                'description': ''
            })
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"is not a valid IPv4 or IPv6 address", response.data)

    def test_device_details_and_not_found(self):
        """Device details loads with 200, missing device redirects."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get(f'/devices/{self.test_dev_id}')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Current Diagnostic Status", resp.data)

            # Missing device
            resp_missing = self.client.get('/devices/99999', follow_redirects=True)
            self.assertEqual(resp_missing.status_code, 200)
            self.assertIn(b"Device not found", resp_missing.data)

    def test_edit_device(self):
        """Editing device updates fields."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            with patch('scheduler.scheduler.check_single_device'):
                resp = self.client.post(f'/devices/{self.test_dev_id}/edit', data={
                    'device_name': 'Renamed Web Host',
                    'ip_address': '127.0.0.1',
                    'port': '8080',
                    'description': 'Modified'
                }, follow_redirects=True)
                self.assertEqual(resp.status_code, 200)
                self.assertIn(b"Renamed Web Host", resp.data)

    def test_delete_device(self):
        """Deleting device removes it from database."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.post(f'/devices/{self.test_dev_id}/delete', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            dev = database.get_device_by_id(self.test_dev_id, db_path=self.temp_db_path)
            self.assertIsNone(dev)

    def test_history_view_filtering(self):
        """History view filters by status."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/history?status=UP')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Monitoring History", resp.data)

    def test_settings_view_and_post(self):
        """Settings page reads and saves configuration."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/settings')
            self.assertEqual(resp.status_code, 200)

            resp_post = self.client.post('/settings', data={
                'monitor_interval': '45',
                'ping_timeout': '3',
                'tcp_timeout': '4',
                'ping_count': '3'
            }, follow_redirects=True)
            self.assertEqual(resp_post.status_code, 200)
            self.assertIn(b"Monitoring settings updated successfully", resp_post.data)

    def test_api_endpoints(self):
        """Test JSON API endpoints."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            # Summary
            resp = self.client.get('/api/summary')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn('total_devices', data)

            # Devices JSON
            resp = self.client.get('/api/devices')
            self.assertEqual(resp.status_code, 200)
            devices = resp.get_json()
            self.assertEqual(len(devices), 1)

            # Scheduler status
            resp = self.client.get('/api/scheduler/status')
            self.assertEqual(resp.status_code, 200)
            self.assertIn('running', resp.get_json())

    def test_404_error_page(self):
        """Accessing undefined route yields 404 template."""
        resp = self.client.get('/this-path-does-not-exist')
        self.assertEqual(resp.status_code, 404)
        self.assertIn(b"404 Resource Not Found", resp.data)

if __name__ == '__main__':
    unittest.main()
