"""
Unit tests for Flask routes and JSON API endpoints:
Views, forms, client/server validations, fault reports, exports, diagnostics, and error handling.
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
        
        self.app = create_app()
        self.app.config['DATABASE_PATH'] = self.temp_db_path
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        database.init_db(self.temp_db_path)

        with patch('scheduler.scheduler.check_single_device'):
            self.test_dev_id = database.create_device(
                device_name="Test Web Host",
                ip_address="127.0.0.1",
                port=5000,
                description="Local web node",
                monitoring_enabled=1,
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
            self.assertIn(b"AUTOMATED FAULT DETECTION SYSTEM", response.data)

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
                    'description': 'Main router',
                    'monitoring_enabled': '1'
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
            self.assertIn(b"Test Web Host", resp.data)

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
                    'description': 'Modified',
                    'monitoring_enabled': '1'
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

    def test_toggle_device_monitoring(self):
        """Toggling device switches enabled status."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.post(f'/devices/{self.test_dev_id}/toggle', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            dev = database.get_device_by_id(self.test_dev_id, db_path=self.temp_db_path)
            self.assertEqual(dev['monitoring_enabled'], 0)

    def test_history_view_and_export(self):
        """History view filters and exports CSV."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/history?status=UP')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Monitoring History Audit Log", resp.data)

            # CSV Export
            resp_csv = self.client.get('/history/export')
            self.assertEqual(resp_csv.status_code, 200)
            self.assertEqual(resp_csv.mimetype, 'text/csv')
            self.assertIn(b"Record ID,Timestamp", resp_csv.data)

    def test_faults_view_and_export(self):
        """Faults view renders and exports CSV."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/faults')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Fault Diagnostics", resp.data)

            resp_csv = self.client.get('/faults/export')
            self.assertEqual(resp_csv.status_code, 200)
            self.assertEqual(resp_csv.mimetype, 'text/csv')
            self.assertIn(b"Device ID,Device Name", resp_csv.data)

    def test_system_view(self):
        """System information view renders real runtime diagnostics."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/system')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"System Architecture", resp.data)

    def test_settings_view_and_post(self):
        """Settings page reads and saves configuration."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/settings')
            self.assertEqual(resp.status_code, 200)

            resp_post = self.client.post('/settings', data={
                'monitor_interval': '45',
                'ping_timeout': '3',
                'tcp_timeout': '4',
                'ping_count': '3',
                'concurrency_limit': '6',
                'auto_monitoring': '1'
            }, follow_redirects=True)
            self.assertEqual(resp_post.status_code, 200)
            self.assertIn(b"Monitoring settings updated successfully", resp_post.data)

    def test_api_endpoints(self):
        """Test JSON API endpoints."""
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.get('/api/summary')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn('total_devices', data)

            resp = self.client.get('/api/devices')
            self.assertEqual(resp.status_code, 200)
            devices = resp.get_json()
            self.assertEqual(len(devices), 1)

            resp = self.client.get('/api/scheduler/status')
            self.assertEqual(resp.status_code, 200)
            self.assertIn('running', resp.get_json())

            resp = self.client.get('/api/chart/history')
            self.assertEqual(resp.status_code, 200)
            chart_data = resp.get_json()
            self.assertIn('response_times', chart_data)

    @patch('monitoring.run_traceroute')
    def test_traceroute_endpoints(self, mock_trace):
        """Test traceroute trigger API and historical fetch API."""
        mock_trace.return_value = {
            'target_ip': '127.0.0.1',
            'total_hops': 1,
            'destination_reached': True,
            'fault_hop': None,
            'fault_summary': 'Direct loopback reach',
            'hops': [{'hop': 1, 'ip': '127.0.0.1', 'status': 'SUCCESS'}],
            'raw_output': 'Trace complete'
        }
        with patch('database.Config.DATABASE_PATH', self.temp_db_path):
            resp = self.client.post(f'/api/devices/{self.test_dev_id}/traceroute')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data['success'])
            self.assertEqual(data['result']['total_hops'], 1)

            resp_hist = self.client.get(f'/api/devices/{self.test_dev_id}/traceroutes')
            self.assertEqual(resp_hist.status_code, 200)
            hist_data = resp_hist.get_json()
            self.assertTrue(hist_data['success'])
            self.assertEqual(len(hist_data['traceroutes']), 1)

    def test_404_error_page(self):
        """Accessing undefined route yields 404 template."""
        resp = self.client.get('/this-path-does-not-exist')
        self.assertEqual(resp.status_code, 404)
        self.assertIn(b"404 Resource Not Found", resp.data)

if __name__ == '__main__':
    unittest.main()
