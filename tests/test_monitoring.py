"""
Unit tests for monitoring module:
IP validation, port validation, mocked ICMP ping parsing, mocked TCP socket connections,
and comprehensive UP / DOWN / FAULT status classifications.
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import subprocess
import monitoring

class TestMonitoring(unittest.TestCase):
    def test_ip_validation(self):
        """Test IPv4, IPv6, and invalid IP addresses."""
        valid, err, obj = monitoring.validate_ip_address("127.0.0.1")
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(obj.version, 4)

        valid, err, obj = monitoring.validate_ip_address("::1")
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(obj.version, 6)

        valid, err, _ = monitoring.validate_ip_address("8.8.8.8")
        self.assertTrue(valid)

        self.assertFalse(monitoring.validate_ip_address("999.999.999.999")[0])
        self.assertFalse(monitoring.validate_ip_address("not_an_ip")[0])
        self.assertFalse(monitoring.validate_ip_address("")[0])

    def test_port_validation(self):
        """Test TCP port boundary checks."""
        self.assertTrue(monitoring.validate_port(80)[0])
        self.assertTrue(monitoring.validate_port("443")[0])
        self.assertTrue(monitoring.validate_port(None)[0])
        self.assertTrue(monitoring.validate_port("")[0])

        self.assertFalse(monitoring.validate_port(0)[0])
        self.assertFalse(monitoring.validate_port(65536)[0])
        self.assertFalse(monitoring.validate_port(-5)[0])
        self.assertFalse(monitoring.validate_port("invalid")[0])

    @patch('subprocess.run')
    @patch('platform.system', return_value='Windows')
    def test_ping_windows_success(self, mock_sys, mock_run):
        """Mock successful Windows ping output with round trip time."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Reply from 127.0.0.1: bytes=32 time=4ms TTL=128\nMinimum = 4ms, Maximum = 4ms, Average = 4ms",
            stderr=""
        )
        reachable, rtt, cat, fault = monitoring.ping_host("127.0.0.1", count=1, timeout_sec=1)
        self.assertTrue(reachable)
        self.assertEqual(rtt, 4.0)
        self.assertEqual(cat, "NONE")
        self.assertIsNone(fault)

    @patch('subprocess.run')
    @patch('platform.system', return_value='Windows')
    def test_ping_windows_timeout(self, mock_sys, mock_run):
        """Mock Windows ping timeout output."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="Request timed out.\nRequest timed out.\nPackets: Sent = 2, Received = 0, Lost = 2 (100% loss)",
            stderr=""
        )
        reachable, rtt, cat, fault = monitoring.ping_host("192.0.2.1", count=2, timeout_sec=1)
        self.assertFalse(reachable)
        self.assertIsNone(rtt)
        self.assertEqual(cat, "NETWORK_TIMEOUT")
        self.assertIn("timed out", fault.lower())

    @patch('socket.socket')
    def test_tcp_port_success(self, mock_socket_cls):
        """Mock successful TCP socket connection."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.return_value = None

        is_open, conn_time, cat, fault = monitoring.check_tcp_port("127.0.0.1", 80, timeout_sec=2)
        self.assertTrue(is_open)
        self.assertIsNotNone(conn_time)
        self.assertEqual(cat, "NONE")
        self.assertIsNone(fault)
        mock_sock.close.assert_called_once()

    @patch('socket.socket')
    def test_tcp_port_refused(self, mock_socket_cls):
        """Mock ConnectionRefusedError on closed port."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        is_open, conn_time, cat, fault = monitoring.check_tcp_port("127.0.0.1", 9999, timeout_sec=2)
        self.assertFalse(is_open)
        self.assertIsNone(conn_time)
        self.assertEqual(cat, "SERVICE_REFUSED")
        self.assertIn("refused", fault.lower())
        mock_sock.close.assert_called_once()

    @patch('monitoring.ping_host')
    @patch('monitoring.check_tcp_port')
    def test_status_classification_up_with_port(self, mock_tcp, mock_ping):
        """Device responds to ping AND TCP port open -> UP."""
        mock_ping.return_value = (True, 5.2, "NONE", None)
        mock_tcp.return_value = (True, 12.0, "NONE", None)

        device = {'id': 1, 'ip_address': '192.168.1.1', 'port': 80}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['overall_status'], 'UP')
        self.assertEqual(res['reachability_status'], 'REACHABLE')
        self.assertEqual(res['service_status'], 'OPEN')
        self.assertEqual(res['response_time_ms'], 12.0)

    @patch('monitoring.ping_host')
    def test_status_classification_up_without_port(self, mock_ping):
        """Device responds to ping with no port configured -> UP (NOT_CONFIGURED)."""
        mock_ping.return_value = (True, 3.4, "NONE", None)

        device = {'id': 2, 'ip_address': '192.168.1.254', 'port': None}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['overall_status'], 'UP')
        self.assertEqual(res['reachability_status'], 'REACHABLE')
        self.assertEqual(res['service_status'], 'NOT_CONFIGURED')
        self.assertEqual(res['response_time_ms'], 3.4)

    @patch('monitoring.ping_host')
    @patch('monitoring.check_tcp_port')
    def test_status_classification_fault_port_refused(self, mock_tcp, mock_ping):
        """Device responds to ping, but TCP connection is refused -> FAULT."""
        mock_ping.return_value = (True, 4.0, "NONE", None)
        mock_tcp.return_value = (False, None, "SERVICE_REFUSED", "TCP connection actively refused on port 8080")

        device = {'id': 3, 'ip_address': '192.168.1.50', 'port': 8080}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['overall_status'], 'FAULT')
        self.assertEqual(res['reachability_status'], 'REACHABLE')
        self.assertEqual(res['service_status'], 'REFUSED')
        self.assertEqual(res['fault_category'], 'SERVICE_REFUSED')
        self.assertIn("failed", res['fault_details'].lower())

    @patch('monitoring.ping_host')
    @patch('monitoring.check_tcp_port')
    def test_status_classification_down(self, mock_tcp, mock_ping):
        """Device fails ping and fails TCP connection -> DOWN."""
        mock_ping.return_value = (False, None, "NETWORK_TIMEOUT", "ICMP request timed out")
        mock_tcp.return_value = (False, None, "SERVICE_TIMEOUT", "TCP connection timed out on port 443")

        device = {'id': 4, 'ip_address': '10.255.255.1', 'port': 443}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['overall_status'], 'DOWN')
        self.assertIsNone(res['response_time_ms'])

    @patch('monitoring.ping_host')
    @patch('monitoring.check_tcp_port')
    def test_status_classification_icmp_blocked_tcp_open(self, mock_tcp, mock_ping):
        """Ping fails (firewall blocked) but TCP connects -> UP (ICMP_FILTERED)."""
        mock_ping.return_value = (False, None, "NETWORK_TIMEOUT", "ICMP request timed out")
        mock_tcp.return_value = (True, 15.5, "NONE", None)

        device = {'id': 5, 'ip_address': '1.1.1.1', 'port': 443}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['overall_status'], 'UP')
        self.assertEqual(res['reachability_status'], 'ICMP_FILTERED')
        self.assertEqual(res['service_status'], 'OPEN')
        self.assertEqual(res['response_time_ms'], 15.5)

    def test_traceroute_parser_success(self):
        """Test parsing successful multi-hop traceroute to destination."""
        mock_output = (
            "Tracing route to 8.8.8.8 over a maximum of 15 hops\n\n"
            "  1     1 ms     1 ms    <1 ms  192.168.1.1\n"
            "  2    12 ms    15 ms    10 ms  10.20.0.1\n"
            "  3    22 ms    21 ms    24 ms  8.8.8.8\n\n"
            "Trace complete.\n"
        )
        res = monitoring.parse_tracert_output(mock_output, "8.8.8.8")
        self.assertTrue(res['destination_reached'])
        self.assertFalse(res['fault_localized'])
        self.assertEqual(res['total_hops'], 3)
        self.assertEqual(res['hops'][0]['ip'], '192.168.1.1')
        self.assertEqual(res['hops'][2]['ip'], '8.8.8.8')
        self.assertEqual(res['hops'][2]['status'], 'SUCCESS')

    def test_traceroute_parser_fault_localization(self):
        """Test traceroute fault localization when packets drop at intermediate hop."""
        mock_output = (
            "Tracing route to 198.51.100.1 over a maximum of 15 hops\n\n"
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     *        *        *     Request timed out.\n"
            "  3     *        *        *     Request timed out.\n\n"
            "Trace complete.\n"
        )
        res = monitoring.parse_tracert_output(mock_output, "198.51.100.1")
        self.assertFalse(res['destination_reached'])
        self.assertTrue(res['fault_localized'])
        self.assertEqual(res['fault_hop'], 2)
        self.assertIn("Hop 1 (192.168.1.1)", res['fault_summary'])
        self.assertIn("Hop 2", res['fault_summary'])
        self.assertEqual(res['hops'][1]['status'], 'TIMED_OUT')

    def test_traceroute_invalid_ip(self):
        """Test traceroute with invalid IP returns localized error."""
        res = monitoring.run_traceroute("invalid.ip.format")
        self.assertFalse(res['destination_reached'])
        self.assertTrue(res['fault_localized'])
        self.assertIn("Invalid target IP", res['fault_summary'])

if __name__ == '__main__':
    unittest.main()
