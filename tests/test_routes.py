"""
Unit tests for Flask routes, session authentication, and JSON API endpoints:
Views, forms, client/server validations, fault reports, exports, diagnostics, and error handling.
"""

import unittest
from unittest.mock import patch
from app import create_app
import database
from tests.mock_supabase import MockSupabaseClient

class TestRoutes(unittest.TestCase):
    def setUp(self):
        self.mock_client = MockSupabaseClient()
        database.set_supabase_client(self.mock_client)
        database.init_db(client=self.mock_client)

        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        # Set default authenticated session for self.client
        with self.client.session_transaction() as sess:
            sess['user_id'] = '00000000-0000-0000-0000-000000000001'
            sess['user_email'] = 'admin@supabase.local'
            sess['user_name'] = 'Administrator'

        with patch('scheduler.scheduler.check_single_device'):
            self.test_dev_id = database.create_device(
                device_name="Test Web Host",
                ip_address="127.0.0.1",
                port=5000,
                description="Local web node",
                monitoring_enabled=1,
                user_id='00000000-0000-0000-0000-000000000001',
                client=self.mock_client
            )

    def tearDown(self):
        database.set_supabase_client(None)

    def test_login_and_logout_flow(self):
        """Test Supabase Auth sign-in, account creation, and logout."""
        unauth_client = self.app.test_client()

        # 1. Unauthenticated access to dashboard redirects to login
        resp = unauth_client.get('/', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.headers['Location'])

        # 2. Invalid credentials return 401
        resp_bad = unauth_client.post('/login', data={
            'email': 'admin@supabase.local',
            'password': 'wrong_password'
        })
        self.assertEqual(resp_bad.status_code, 401)

        # 3. Account registration with new user
        resp_reg = unauth_client.post('/register', json={
            'full_name': 'New Engineer',
            'email': 'engineer@network.io',
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertEqual(resp_reg.status_code, 200)
        self.assertTrue(resp_reg.get_json()['success'])

        # 4. Duplicate account registration returns 400
        another_client = self.app.test_client()
        resp_dup = another_client.post('/register', json={
            'full_name': 'Duplicate Engineer',
            'email': 'engineer@network.io',
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertEqual(resp_dup.status_code, 400)

        # 5. Password reset flow returns neutral confirmation
        resp_reset = unauth_client.post('/forgot-password', json={
            'email': 'engineer@network.io'
        })
        self.assertEqual(resp_reset.status_code, 200)
        self.assertTrue(resp_reset.get_json()['success'])

        # 6. Valid credentials authenticate and redirect to dashboard
        resp_ok = unauth_client.post('/login', data={
            'email': 'admin@supabase.local',
            'password': 'admin123'
        }, follow_redirects=True)
        self.assertEqual(resp_ok.status_code, 200)

        # 7. Logout clears session and redirects
        resp_logout = unauth_client.get('/logout', follow_redirects=True)
        self.assertEqual(resp_logout.status_code, 200)

    def test_dashboard_route(self):
        """Dashboard renders with 200 OK."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Network Monitor", response.data)

    def test_device_inventory_route(self):
        """Device inventory page lists registered device."""
        response = self.client.get('/devices')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test Web Host", response.data)

    def test_add_device_valid(self):
        """Submitting valid device form creates record in Supabase and redirects."""
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
        resp = self.client.get(f'/devices/{self.test_dev_id}')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Test Web Host", resp.data)

        resp_missing = self.client.get('/devices/non-existent-uuid', follow_redirects=True)
        self.assertEqual(resp_missing.status_code, 200)
        self.assertIn(b"Device not found", resp_missing.data)

    def test_edit_device(self):
        """Editing device updates fields in Supabase."""
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

    def test_toggle_device_monitoring(self):
        """Toggling device monitoring updates state."""
        resp = self.client.post(f'/devices/{self.test_dev_id}/toggle', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        dev = database.get_device_by_id(self.test_dev_id, client=self.mock_client)
        self.assertFalse(dev['monitoring_enabled'])

    def test_delete_device(self):
        """Deleting device removes record from Supabase."""
        resp = self.client.post(f'/devices/{self.test_dev_id}/delete', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        dev = database.get_device_by_id(self.test_dev_id, client=self.mock_client)
        self.assertIsNone(dev)

    def test_history_and_faults_routes(self):
        """History and Fault reports render 200 OK."""
        resp_hist = self.client.get('/history')
        self.assertEqual(resp_hist.status_code, 200)

        resp_faults = self.client.get('/faults')
        self.assertEqual(resp_faults.status_code, 200)

    def test_settings_get_and_post(self):
        """Settings route returns form and updates settings."""
        resp_get = self.client.get('/settings')
        self.assertEqual(resp_get.status_code, 200)

        resp_post = self.client.post('/settings', data={
            'monitor_interval': '45',
            'ping_timeout': '3',
            'tcp_timeout': '3',
            'ping_count': '2',
            'concurrency_limit': '8',
            'auto_monitoring': '1'
        }, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)
        settings = database.get_settings(client=self.mock_client)
        self.assertEqual(settings['monitor_interval'], 45)

    def test_api_summary_and_devices(self):
        """REST API endpoints return valid JSON responses."""
        resp_summary = self.client.get('/api/summary')
        self.assertEqual(resp_summary.status_code, 200)
        self.assertIn('total_devices', resp_summary.get_json())

        resp_devices = self.client.get('/api/devices')
        self.assertEqual(resp_devices.status_code, 200)
        self.assertIsInstance(resp_devices.get_json(), list)

    def test_api_scheduler_controls(self):
        """Scheduler API endpoints control worker status."""
        resp_status = self.client.get('/api/scheduler/status')
        self.assertEqual(resp_status.status_code, 200)
        self.assertIn('running', resp_status.get_json())

        resp_stop = self.client.post('/api/scheduler/stop')
        self.assertEqual(resp_stop.status_code, 200)

        resp_start = self.client.post('/api/scheduler/start')
        self.assertEqual(resp_start.status_code, 200)

    def test_exports_csv(self):
        """CSV export endpoints return 200 with text/csv mimetype."""
        resp_h = self.client.get('/history/export')
        self.assertEqual(resp_h.status_code, 200)
        self.assertIn('text/csv', resp_h.content_type)

        resp_f = self.client.get('/faults/export')
        self.assertEqual(resp_f.status_code, 200)
        self.assertIn('text/csv', resp_f.content_type)

    def test_404_error_handler(self):
        """Invalid route returns custom 404 page."""
        resp = self.client.get('/this-path-does-not-exist')
        self.assertEqual(resp.status_code, 404)
        self.assertIn(b"404", resp.data)
        self.assertIn(b"Not Found", resp.data)

if __name__ == '__main__':
    unittest.main()
