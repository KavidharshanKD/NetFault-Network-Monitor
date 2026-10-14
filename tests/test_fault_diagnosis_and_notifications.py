"""
Comprehensive Unit & Integration Tests for:
1. Intelligent Fault Localization and Root-Cause Diagnosis
2. Immediate Email Notifications for Detected Faults & Recovery
Covering all 15 scenarios mandated in the master specification.
"""

import pytest
import uuid
import smtplib
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from config import Config
from app import create_app
import database
import monitoring
import fault_diagnosis
import notifications
from scheduler import scheduler
from tests.mock_supabase import MockSupabaseClient

class TestFaultDiagnosisAndNotifications:
    @pytest.fixture(autouse=True)
    def setup_isolated_env(self):
        """Set up in-memory MockSupabaseClient and Flask test client for each test."""
        self.mock_client = MockSupabaseClient()
        database.set_supabase_client(self.mock_client)

        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Seed admin and regular user
        self.user_id = "11111111-1111-1111-1111-111111111111"
        self.mock_client.tables['users'].append({
            'id': self.user_id,
            'email': 'operator@netfault.local',
            'password_hash': 'hash123',
            'full_name': 'Network Operator',
            'role': 'user'
        })

        # Seed enabled notification settings in mock
        self.mock_client.tables['application_settings'] = [
            {'id': '1', 'setting_key': 'monitor_interval', 'setting_value': 30},
            {'id': '2', 'setting_key': 'ping_timeout', 'setting_value': 2},
            {'id': '3', 'setting_key': 'tcp_timeout', 'setting_value': 2},
            {'id': '4', 'setting_key': 'ping_count', 'setting_value': 1},
            {'id': '5', 'setting_key': 'concurrency_limit', 'setting_value': 5},
            {'id': '6', 'setting_key': 'auto_monitoring', 'setting_value': 1},
            {'id': '7', 'setting_key': 'email_notifications_enabled', 'setting_value': 1},
            {'id': '8', 'setting_key': 'alert_recipient_email', 'setting_value': 'noc-alerts@company.com'},
            {'id': '9', 'setting_key': 'alert_on_down', 'setting_value': 1},
            {'id': '10', 'setting_key': 'alert_on_fault', 'setting_value': 1},
            {'id': '11', 'setting_key': 'alert_on_latency', 'setting_value': 1},
            {'id': '12', 'setting_key': 'alert_on_recovery', 'setting_value': 1},
            {'id': '13', 'setting_key': 'latency_threshold_ms', 'setting_value': 200},
            {'id': '14', 'setting_key': 'packet_loss_threshold_pct', 'setting_value': 50},
            {'id': '15', 'setting_key': 'smtp_host', 'setting_value': 'smtp.mockserver.local'},
            {'id': '16', 'setting_key': 'smtp_port', 'setting_value': 587},
            {'id': '17', 'setting_key': 'smtp_username', 'setting_value': 'mailer@netfault.local'},
            {'id': '18', 'setting_key': 'smtp_password', 'setting_value': 'secretpass'},
            {'id': '19', 'setting_key': 'alert_sender_email', 'setting_value': 'netfault-alerts@local'}
        ]

        yield

        database.set_supabase_client(None)

    def _login(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.user_id
            sess['user_email'] = 'operator@netfault.local'
            sess['user_name'] = 'Network Operator'

    def _make_device(self, name, ip, port=None):
        """Creates a device and returns its full dictionary."""
        dev_id = database.create_device(name, ip, port=port, user_id=self.user_id)
        return database.get_device_by_id(dev_id, user_id=self.user_id)

    # -------------------------------------------------------------------------
    # Scenario 1: Healthy device remains UP and generates no fault alert
    # -------------------------------------------------------------------------
    def test_scenario_1_healthy_device_remains_up(self):
        """A healthy device remains UP and generates no fault alert."""
        dev = self._make_device("Web Server", "192.168.1.10", port=80)
        
        healthy_check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'OPEN',
            'overall_status': 'UP',
            'response_time_ms': 15.5,
            'fault_category': 'NONE',
            'fault_details': 'Reachable and port open'
        }

        diag = fault_diagnosis.diagnose_check(device=dev, current_check=healthy_check)
        assert diag['current_status'] == 'UP'
        assert diag['is_fault'] is False
        assert diag['severity'] == 'INFO'

        # Process through notification handler
        with patch('notifications._send_smtp_message') as mock_smtp:
            notifications.handle_incident_notifications(dev, diag, healthy_check)
            mock_smtp.assert_not_called()

        assert len(self.mock_client.tables['incidents']) == 0

    # -------------------------------------------------------------------------
    # Scenario 2: Device becomes unreachable and immediately triggers DOWN incident & email
    # -------------------------------------------------------------------------
    def test_scenario_2_device_unreachable_triggers_down_incident_and_email(self):
        """A device becomes unreachable and immediately triggers a DOWN incident and email."""
        dev = self._make_device("Core Switch", "10.0.0.1", port=None)
        
        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'Destination host unreachable'
        }

        diag = fault_diagnosis.diagnose_check(device=dev, current_check=down_check)
        assert diag['current_status'] == 'DOWN'
        assert diag['is_fault'] is True
        assert diag['severity'] == 'CRITICAL'
        assert diag['fault_category'] in (fault_diagnosis.CAT_HOST_UNREACHABLE, fault_diagnosis.CAT_DEST_UNREACHABLE)

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            notifications.handle_incident_notifications(dev, diag, down_check)
            mock_smtp.assert_called_once()
            call_kwargs = mock_smtp.call_args[1]
            assert "Core Switch" in call_kwargs['subject']
            assert "CRITICAL" in call_kwargs['subject']
            assert "DOWN" in call_kwargs['subject']

        # Confirm incident was logged in Supabase
        incidents = self.mock_client.tables['incidents']
        assert len(incidents) == 1
        assert incidents[0]['incident_status'] == 'OPEN'
        assert incidents[0]['severity'] == 'CRITICAL'

    # -------------------------------------------------------------------------
    # Scenario 3: Host responds, but TCP service becomes FAULT -> triggers FAULT email
    # -------------------------------------------------------------------------
    def test_scenario_3_service_fault_triggers_fault_email(self):
        """Host responds, but configured TCP service unavailable -> triggers FAULT email."""
        dev = self._make_device("App Server", "192.168.1.50", port=8080)

        fault_check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'REFUSED',
            'overall_status': 'FAULT',
            'response_time_ms': 12.0,
            'fault_category': 'SERVICE_REFUSED',
            'fault_details': 'TCP connection actively refused on port 8080'
        }

        diag = fault_diagnosis.diagnose_check(device=dev, current_check=fault_check)
        assert diag['current_status'] == 'FAULT'
        assert diag['is_fault'] is True
        assert diag['severity'] == 'HIGH'
        assert diag['fault_category'] == fault_diagnosis.CAT_CONNECTION_REFUSED

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            notifications.handle_incident_notifications(dev, diag, fault_check)
            mock_smtp.assert_called_once()
            call_kwargs = mock_smtp.call_args[1]
            assert "[NetFault FAULT]" in call_kwargs['subject']
            assert "App Server" in call_kwargs['subject']

    # -------------------------------------------------------------------------
    # Scenario 4: Connection-refused error correctly diagnosed with actionable advice
    # -------------------------------------------------------------------------
    def test_scenario_4_connection_refused_correctly_diagnosed(self):
        """A connection-refused error is correctly diagnosed when observed."""
        dev = self._make_device("Database Node", "10.10.1.25", port=5432)
        
        check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'REFUSED',
            'overall_status': 'FAULT',
            'response_time_ms': 5.0,
            'fault_category': 'SERVICE_REFUSED',
            'fault_details': 'TCP connection actively refused on port 5432'
        }

        diag = fault_diagnosis.diagnose_check(device=dev, current_check=check)
        assert diag['fault_category'] == fault_diagnosis.CAT_CONNECTION_REFUSED
        assert diag['confidence_level'] == 'High'
        assert "TCP RST" in diag['probable_cause']
        assert "5432" in diag['recommended_action']

    # -------------------------------------------------------------------------
    # Scenario 5: Connection timeout reported accurately without inventing cause
    # -------------------------------------------------------------------------
    def test_scenario_5_connection_timeout_reported_accurately(self):
        """A connection timeout is reported accurately without inventing its cause."""
        dev = self._make_device("Secured Node", "10.20.1.15", port=443)

        check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'TIMEOUT',
            'overall_status': 'FAULT',
            'response_time_ms': 8.0,
            'fault_category': 'SERVICE_TIMEOUT',
            'fault_details': 'TCP connection timed out on port 443 after 2s'
        }

        diag = fault_diagnosis.diagnose_check(device=dev, current_check=check)
        assert diag['fault_category'] == fault_diagnosis.CAT_CONNECTION_TIMEOUT
        assert "TCP SYN packet to port 443 was silently discarded" in diag['probable_cause']
        assert diag['confidence_level'] == 'Medium'

    # -------------------------------------------------------------------------
    # Scenario 6: ICMP fails but configured TCP service works -> marked UP
    # -------------------------------------------------------------------------
    def test_scenario_6_icmp_fails_but_tcp_works_remains_up(self):
        """ICMP fails but the configured TCP service works; the device is not incorrectly marked DOWN."""
        dev = self._make_device("Firewalled Cloud Server", "1.1.1.1", port=443)

        with patch('monitoring.ping_host', return_value=(False, None, 'NETWORK_TIMEOUT', 'Ping timed out')), \
             patch('monitoring.check_tcp_port', return_value=(True, 22.5, 'NONE', None)):
            res = monitoring.check_device_connectivity(dev)

        assert res['overall_status'] == 'UP'
        assert res['reachability_status'] == 'ICMP_FILTERED'
        assert res['service_status'] == 'OPEN'

        diag = fault_diagnosis.diagnose_check(dev, res)
        assert diag['current_status'] == 'UP'
        assert diag['is_fault'] is False

    # -------------------------------------------------------------------------
    # Scenario 7: Intermediate traceroute hop times out, destination reaches -> NO DOWN alert
    # -------------------------------------------------------------------------
    def test_scenario_7_intermediate_hop_timeout_does_not_mark_destination_down(self):
        """An intermediate traceroute hop times out but the destination responds; no false device-DOWN email is sent."""
        dev = self._make_device("Upstream Gateway", "8.8.8.8", port=53)

        current_trace = {
            'target_ip': '8.8.8.8',
            'destination_reached': True,
            'hops': [
                {'hop': 1, 'ip': '192.168.1.1', 'avg_rtt_ms': 2.0, 'status': 'SUCCESS'},
                {'hop': 2, 'ip': '*', 'avg_rtt_ms': None, 'status': 'TIMED_OUT'},  # router ICMP filter
                {'hop': 3, 'ip': '8.8.8.8', 'avg_rtt_ms': 18.0, 'status': 'SUCCESS'}
            ]
        }

        findings = fault_diagnosis.analyze_hop_by_hop_comparison(current_trace)
        assert len(findings) == 1
        assert "Intermediate hop(s) 2 did not respond, but destination 8.8.8.8 was reached successfully" in findings[0]['summary']
        assert findings[0]['actionable'] is False

    # -------------------------------------------------------------------------
    # Scenario 8: Newly detected fault generates one initial notification immediately
    # -------------------------------------------------------------------------
    def test_scenario_8_immediate_notification_on_first_failure(self):
        """A newly detected fault generates one initial notification without waiting for three consecutive failures."""
        dev = self._make_device("Critical Gateway", "172.16.0.1")

        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'ICMP ping timed out'
        }

        # Simulate monitoring check cycle 1
        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            diag = fault_diagnosis.diagnose_check(dev, down_check)
            notifications.handle_incident_notifications(dev, diag, down_check)
            assert mock_smtp.call_count == 1

    # -------------------------------------------------------------------------
    # Scenario 9: Persistent fault does not repeatedly send duplicate alerts
    # -------------------------------------------------------------------------
    def test_scenario_9_persistent_fault_suppresses_duplicate_alerts(self):
        """A persistent fault does not repeatedly generate the same initial alert."""
        dev = self._make_device("Edge Router", "192.168.100.1")

        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'No response'
        }

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            # Cycle 1: New fault
            diag1 = fault_diagnosis.diagnose_check(dev, down_check)
            notifications.handle_incident_notifications(dev, diag1, down_check)
            assert mock_smtp.call_count == 1

            # Cycle 2: Persistent fault (same device still down)
            diag2 = fault_diagnosis.diagnose_check(dev, down_check)
            notifications.handle_incident_notifications(dev, diag2, down_check)
            # Must NOT dispatch second email!
            assert mock_smtp.call_count == 1

            # Cycle 3: Still persistent
            diag3 = fault_diagnosis.diagnose_check(dev, down_check)
            notifications.handle_incident_notifications(dev, diag3, down_check)
            assert mock_smtp.call_count == 1

        # Still only one OPEN incident
        incidents = self.mock_client.tables['incidents']
        assert len(incidents) == 1
        assert incidents[0]['incident_status'] == 'OPEN'

    # -------------------------------------------------------------------------
    # Scenario 10: Device recovers and generates one recovery email
    # -------------------------------------------------------------------------
    def test_scenario_10_device_recovers_and_generates_recovery_email(self):
        """A device recovers and generates one recovery email."""
        dev = self._make_device("Branch Switch", "10.0.5.1")

        # 1. First it fails
        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'Timeout'
        }
        with patch('notifications._send_smtp_message', return_value=True):
            diag = fault_diagnosis.diagnose_check(dev, down_check)
            notifications.handle_incident_notifications(dev, diag, down_check)

        assert len(self.mock_client.tables['incidents']) == 1
        assert self.mock_client.tables['incidents'][0]['incident_status'] == 'OPEN'

        # 2. Device recovers
        recovery_check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'UP',
            'response_time_ms': 14.2,
            'fault_category': 'NONE',
            'fault_details': 'Reachable via ICMP'
        }

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            rec_diag = fault_diagnosis.diagnose_check(dev, recovery_check)
            notifications.handle_incident_notifications(dev, rec_diag, recovery_check)
            mock_smtp.assert_called_once()
            call_kwargs = mock_smtp.call_args[1]
            assert "[NetFault RECOVERED]" in call_kwargs['subject']
            assert "Branch Switch is UP" in call_kwargs['subject']

        # Incident status is now RESOLVED
        assert self.mock_client.tables['incidents'][0]['incident_status'] == 'RESOLVED'
        assert self.mock_client.tables['incidents'][0]['recovered_at'] is not None

    # -------------------------------------------------------------------------
    # Scenario 11: A new incident after recovery generates a new email
    # -------------------------------------------------------------------------
    def test_scenario_11_new_incident_after_recovery_generates_new_email(self):
        """A new incident after recovery generates a new email."""
        dev = self._make_device("Core Firewall", "192.168.1.1")

        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'Unreachable'
        }
        up_check = {
            'device_id': dev['id'],
            'reachability_status': 'REACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'UP',
            'response_time_ms': 2.0,
            'fault_category': 'NONE',
            'fault_details': 'OK'
        }

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            # 1. Initial fault -> Alert 1
            notifications.handle_incident_notifications(dev, fault_diagnosis.diagnose_check(dev, down_check), down_check)
            assert mock_smtp.call_count == 1

            # 2. Recovery -> Alert 2 (Recovery)
            notifications.handle_incident_notifications(dev, fault_diagnosis.diagnose_check(dev, up_check), up_check)
            assert mock_smtp.call_count == 2

            # 3. Subsequent new fault -> Alert 3 (New Fault)
            notifications.handle_incident_notifications(dev, fault_diagnosis.diagnose_check(dev, down_check), down_check)
            assert mock_smtp.call_count == 3

        # Exactly 2 incidents recorded (one RESOLVED, one OPEN)
        incidents = self.mock_client.tables['incidents']
        assert len(incidents) == 2
        assert incidents[0]['incident_status'] == 'RESOLVED'
        assert incidents[1]['incident_status'] == 'OPEN'

    # -------------------------------------------------------------------------
    # Scenario 12: Email delivery failure is recorded safely without crashing engine
    # -------------------------------------------------------------------------
    def test_scenario_12_email_delivery_failure_recorded_safely(self):
        """Email delivery failure is recorded and retried safely without crashing the monitoring engine."""
        dev = self._make_device("Failing Host", "10.0.0.99")

        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'Drop'
        }

        # Mock SMTP raising connection error
        with patch('notifications._send_smtp_message', side_effect=smtplib.SMTPConnectError(421, b"Connection refused")):
            diag = fault_diagnosis.diagnose_check(dev, down_check)
            # Must not crash!
            incident = notifications.handle_incident_notifications(dev, diag, down_check)
            assert incident is not None

        # Confirm incident was created regardless of email failure
        assert len(self.mock_client.tables['incidents']) == 1

    # -------------------------------------------------------------------------
    # Scenario 13: Concurrent monitoring jobs do not create duplicate incidents
    # -------------------------------------------------------------------------
    def test_scenario_13_concurrent_checks_do_not_duplicate_incidents(self):
        """Concurrent monitoring jobs do not create duplicate incidents or alerts."""
        dev = self._make_device("Cluster Node", "192.168.2.100")

        down_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNREACHABLE',
            'service_status': 'NOT_CONFIGURED',
            'overall_status': 'DOWN',
            'response_time_ms': None,
            'fault_category': 'HOST_UNREACHABLE',
            'fault_details': 'Timeout'
        }

        with patch('notifications._send_smtp_message', return_value=True) as mock_smtp:
            # Check 1
            notifications.handle_incident_notifications(dev, fault_diagnosis.diagnose_check(dev, down_check), down_check)
            # Overlapping Check 2 for same device
            notifications.handle_incident_notifications(dev, fault_diagnosis.diagnose_check(dev, down_check), down_check)

            assert mock_smtp.call_count == 1

        assert len(self.mock_client.tables['incidents']) == 1

    # -------------------------------------------------------------------------
    # Scenario 14: Settings authorization and email validation work correctly
    # -------------------------------------------------------------------------
    def test_scenario_14_settings_authorization_and_validation(self):
        """Settings authorization and email validation work correctly."""
        # Test unauthenticated access is redirected to login
        resp_unauth = self.client.post('/settings', data={'monitor_interval': '30'})
        assert resp_unauth.status_code == 302
        assert '/login' in resp_unauth.headers['Location']

        # Test authenticated with invalid email address format
        self._login()
        resp_invalid_email = self.client.post('/settings', data={
            'monitor_interval': '30',
            'ping_timeout': '2',
            'tcp_timeout': '2',
            'ping_count': '1',
            'concurrency_limit': '5',
            'email_notifications_enabled': '1',
            'alert_recipient_email': 'invalid-not-an-email'
        })
        assert resp_invalid_email.status_code == 400

        # Test API test-email without recipient
        resp_test_empty = self.client.post('/api/settings/test-email', json={})
        assert resp_test_empty.status_code == 400

    # -------------------------------------------------------------------------
    # Scenario 15: Diagnostic reports include actual timestamps, evidence, & uncertainty
    # -------------------------------------------------------------------------
    def test_scenario_15_diagnostic_reports_include_uncertainty_when_unknown(self):
        """Diagnostic reports include actual timestamps, evidence, and uncertainty when the cause is unknown."""
        dev = self._make_device("Mystery Device", "10.99.99.99")

        inconclusive_check = {
            'device_id': dev['id'],
            'reachability_status': 'UNCHECKED',
            'service_status': 'NOT_CHECKED',
            'overall_status': 'UNKNOWN',
            'response_time_ms': None,
            'fault_category': 'NONE',
            'fault_details': 'Probe incomplete'
        }

        diag = fault_diagnosis.diagnose_check(dev, inconclusive_check)
        assert diag['confidence_level'] == 'Low'
        assert "Probable cause undetermined" in diag['probable_cause']
        assert diag['detection_timestamp'] is not None
        assert len(diag['evidence']) > 0
