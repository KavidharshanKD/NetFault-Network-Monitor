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

    def test_windows_traceroute_supplied_sample_output(self):
        """
        Verify exact Windows tracert output supplied by user:
        Destination 8.8.8.8 reached at hop 14 after intermediate timeouts (hops 2-6 and 9-10).
        Verifies correct hop counts, responding IPs, non-responsive hops, and absence of false fault.
        """
        mock_output = (
            "Tracing route to 8.8.8.8 over a maximum of 15 hops\n\n"
            "  1     4 ms     1 ms     1 ms  10.178.60.116\n"
            "  2     *        *        *     Request timed out.\n"
            "  3     *        *        *     Request timed out.\n"
            "  4     *        *        *     Request timed out.\n"
            "  5     *        *        *     Request timed out.\n"
            "  6     *        *        *     Request timed out.\n"
            "  7    25 ms    24 ms    24 ms  172.26.75.89\n"
            "  8    26 ms    26 ms    26 ms  192.168.68.134\n"
            "  9     *        *        *     Request timed out.\n"
            " 10     *        *        *     Request timed out.\n"
            " 11    27 ms    27 ms    26 ms  72.14.195.122\n"
            " 12    28 ms    28 ms    28 ms  142.251.66.185\n"
            " 13    29 ms    28 ms    28 ms  142.251.55.121\n"
            " 14    27 ms    28 ms    28 ms  8.8.8.8\n\n"
            "Trace complete.\n"
        )
        res = monitoring.parse_tracert_output(mock_output, "8.8.8.8")

        # 1. Destination reachability
        self.assertTrue(res['destination_reached'], "Destination 8.8.8.8 must be marked reached")
        self.assertEqual(res['destination_hop'], 14, "Destination must be reached at hop 14")
        self.assertTrue(res['trace_completed'])
        self.assertFalse(res['execution_incomplete'])

        # 2. No false fault claim
        self.assertIsNone(res['fault_hop'], "fault_hop must be None when destination is reached")
        self.assertFalse(res['fault_localized'])

        # 3. Dynamic hop counts
        self.assertEqual(res['total_hops'], 14, "Total numbered hops must be exactly 14")
        self.assertEqual(res['responding_hops'], 7, "Responding hops must be exactly 7")
        self.assertEqual(res['non_responsive_hops'], 7, "Non-responsive hops must be exactly 7")

        # 4. Responding hop IPs
        expected_responding_ips = [
            '10.178.60.116', '172.26.75.89', '192.168.68.134',
            '72.14.195.122', '142.251.66.185', '142.251.55.121', '8.8.8.8'
        ]
        actual_responding_ips = [h['ip'] for h in res['hops'] if h['status'] != 'TIMED_OUT']
        self.assertEqual(actual_responding_ips, expected_responding_ips)

        # 5. Timed-out intermediate hops (2-6 and 9-10)
        timed_out_hop_nums = [h['hop'] for h in res['hops'] if h['status'] == 'TIMED_OUT']
        self.assertEqual(timed_out_hop_nums, [2, 3, 4, 5, 6, 9, 10])

        # 6. Fault summary text
        self.assertIn("Destination 8.8.8.8 reached at hop 14", res['fault_summary'])
        self.assertIn("7 responding hop(s)", res['fault_summary'])
        self.assertIn("7 non-responsive hop(s)", res['fault_summary'])

    def test_traceroute_all_hops_respond(self):
        """Test case where all hops respond with nominal latencies to destination."""
        mock_output = (
            "Tracing route to 1.1.1.1 over a maximum of 15 hops\n\n"
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     8 ms     7 ms     8 ms  10.0.0.1\n"
            "  3    12 ms    11 ms    12 ms  172.16.0.1\n"
            "  4    15 ms    14 ms    15 ms  1.1.1.1\n\n"
            "Trace complete.\n"
        )
        res = monitoring.parse_tracert_output(mock_output, "1.1.1.1")
        self.assertTrue(res['destination_reached'])
        self.assertEqual(res['destination_hop'], 4)
        self.assertEqual(res['total_hops'], 4)
        self.assertEqual(res['responding_hops'], 4)
        self.assertEqual(res['non_responsive_hops'], 0)
        self.assertIsNone(res['fault_hop'])
        self.assertFalse(res['fault_localized'])
        self.assertIn("4 responding hop(s)", res['fault_summary'])
        self.assertIn("0 non-responsive hop(s)", res['fault_summary'])

    def test_traceroute_destination_responds_after_timeouts(self):
        """Test case where intermediate router hops time out but destination responds."""
        mock_output = (
            "Tracing route to 9.9.9.9 over a maximum of 15 hops\n\n"
            "  1     2 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     *        *        *     Request timed out.\n"
            "  3     *        *        *     Request timed out.\n"
            "  4    18 ms    17 ms    18 ms  9.9.9.9\n\n"
            "Trace complete.\n"
        )
        res = monitoring.parse_tracert_output(mock_output, "9.9.9.9")
        self.assertTrue(res['destination_reached'])
        self.assertEqual(res['destination_hop'], 4)
        self.assertEqual(res['total_hops'], 4)
        self.assertEqual(res['responding_hops'], 2)
        self.assertEqual(res['non_responsive_hops'], 2)
        self.assertIsNone(res['fault_hop'])
        self.assertFalse(res['fault_localized'])

    def test_traceroute_execution_incomplete_deadline_expired(self):
        """
        Test case where traceroute deadline expired before reaching destination.
        Verifies partial results are preserved and no false fault (such as Hop 1) is claimed.
        """
        partial_output = (
            "Tracing route to 8.8.8.8 over a maximum of 15 hops\n\n"
            "  1     4 ms     1 ms     1 ms  10.178.60.116\n"
            "  2     *        *        *     Request timed out.\n"
            "  3     *        *        *     Request timed out.\n"
        )
        res = monitoring.parse_tracert_output(partial_output, "8.8.8.8", execution_incomplete=True)

        self.assertFalse(res['destination_reached'])
        self.assertTrue(res['execution_incomplete'])
        self.assertEqual(res['total_hops'], 3, "Partial hop rows must be preserved")
        self.assertEqual(res['responding_hops'], 1)
        self.assertEqual(res['non_responsive_hops'], 2)
        self.assertIsNone(res['fault_hop'], "Must not claim a fault at Hop 1 when execution is incomplete")
        self.assertFalse(res['fault_localized'])
        self.assertIn("Traceroute deadline reached", res['fault_summary'])
        self.assertIn("Destination reachability unconfirmed", res['fault_summary'])

    def test_packet_loss_band_classification(self):
        """Test packet loss percentage bands and badge classes."""
        # 0% loss -> None
        status, label, badge = monitoring.get_packet_loss_band(0.0)
        self.assertEqual(status, 'NONE')
        self.assertIn('0.00%', label)
        self.assertEqual(badge, 'badge-up')

        # >0% to <5% -> Low
        status, label, badge = monitoring.get_packet_loss_band(3.5)
        self.assertEqual(status, 'LOW')
        self.assertIn('3.50%', label)
        self.assertEqual(badge, 'badge-low-loss')

        # 5% to <10% -> Moderate
        status, label, badge = monitoring.get_packet_loss_band(5.0)
        self.assertEqual(status, 'MODERATE')
        self.assertIn('5.00%', label)
        self.assertEqual(badge, 'badge-fault')

        # >=10% -> High
        status, label, badge = monitoring.get_packet_loss_band(15.0)
        self.assertEqual(status, 'HIGH')
        self.assertIn('15.00%', label)
        self.assertEqual(badge, 'badge-down')

        # None -> Unavailable
        status, label, badge = monitoring.get_packet_loss_band(None)
        self.assertEqual(status, 'UNAVAILABLE')
        self.assertEqual(label, 'N/A')
        self.assertEqual(badge, 'badge-neutral')

    def test_parse_ping_output_windows_0_loss(self):
        """Test parsing Windows ping output with 0% packet loss."""
        stdout = (
            "Pinging 8.8.8.8 with 32 bytes of data:\n"
            "Reply from 8.8.8.8: bytes=32 time=14ms TTL=117\n"
            "Reply from 8.8.8.8: bytes=32 time=15ms TTL=117\n\n"
            "Ping statistics for 8.8.8.8:\n"
            "    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 14ms, Maximum = 15ms, Average = 14ms\n"
        )
        res = monitoring.parse_ping_output(stdout, "", returncode=0, count=2, system="Windows")
        self.assertTrue(res['reachable'])
        self.assertEqual(res['packets_sent'], 2)
        self.assertEqual(res['packets_received'], 2)
        self.assertEqual(res['packets_lost'], 0)
        self.assertEqual(res['packet_loss_pct'], 0.0)
        self.assertEqual(res['min_rtt_ms'], 14.0)
        self.assertEqual(res['max_rtt_ms'], 15.0)
        self.assertEqual(res['avg_rtt_ms'], 14.0)
        self.assertEqual(res['packet_loss_status'], 'NONE')

    def test_parse_ping_output_windows_partial_loss(self):
        """Test parsing Windows ping output with partial loss (e.g., 20 packets, 2 lost = 10% loss)."""
        stdout = (
            "Ping statistics for 192.168.1.1:\n"
            "    Packets: Sent = 20, Received = 18, Lost = 2 (10% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 2ms, Maximum = 45ms, Average = 12ms\n"
        )
        res = monitoring.parse_ping_output(stdout, "", returncode=0, count=20, system="Windows")
        self.assertTrue(res['reachable'])
        self.assertEqual(res['packets_sent'], 20)
        self.assertEqual(res['packets_received'], 18)
        self.assertEqual(res['packets_lost'], 2)
        self.assertEqual(res['packet_loss_pct'], 10.0)
        self.assertEqual(res['min_rtt_ms'], 2.0)
        self.assertEqual(res['max_rtt_ms'], 45.0)
        self.assertEqual(res['avg_rtt_ms'], 12.0)
        self.assertEqual(res['packet_loss_status'], 'HIGH')

    def test_parse_ping_output_windows_100_loss(self):
        """Test parsing Windows ping output with 100% loss (destination unreachable/timeout)."""
        stdout = (
            "Request timed out.\n"
            "Request timed out.\n\n"
            "Ping statistics for 10.255.255.1:\n"
            "    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),\n"
        )
        res = monitoring.parse_ping_output(stdout, "", returncode=1, count=2, system="Windows")
        self.assertFalse(res['reachable'])
        self.assertEqual(res['packets_sent'], 2)
        self.assertEqual(res['packets_received'], 0)
        self.assertEqual(res['packets_lost'], 2)
        self.assertEqual(res['packet_loss_pct'], 100.0)
        self.assertIsNone(res['avg_rtt_ms'])
        self.assertEqual(res['packet_loss_status'], 'HIGH')

    @patch('subprocess.run')
    @patch('platform.system', return_value='Windows')
    def test_measure_packet_loss(self, mock_sys, mock_run):
        """Test measure_packet_loss helper invoking subprocess and parsing metrics."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Packets: Sent = 20, Received = 20, Lost = 0 (0% loss)\nMinimum = 5ms, Maximum = 10ms, Average = 7ms",
            stderr=""
        )
        res = monitoring.measure_packet_loss("192.168.1.1", count=20)
        self.assertTrue(res['reachable'])
        self.assertEqual(res['packet_loss_pct'], 0.0)
        self.assertEqual(res['avg_rtt_ms'], 7.0)

    @patch('monitoring.ping_host')
    def test_check_device_connectivity_includes_packet_loss(self, mock_ping):
        """Verify check_device_connectivity populates packet loss telemetry fields."""
        mock_ping.return_value = {
            'reachable': True,
            'response_time_ms': 8.5,
            'fault_category': 'NONE',
            'fault_details': None,
            'packets_sent': 20,
            'packets_received': 19,
            'packets_lost': 1,
            'packet_loss_percentage': 5.0,
            'packet_loss_pct': 5.0,
            'minimum_rtt_ms': 4.0,
            'min_rtt_ms': 4.0,
            'maximum_rtt_ms': 25.0,
            'max_rtt_ms': 25.0,
            'average_rtt_ms': 8.5,
            'avg_rtt_ms': 8.5,
            'packet_loss_status': 'MODERATE'
        }
        device = {'id': 10, 'ip_address': '10.0.0.1', 'port': None}
        res = monitoring.check_device_connectivity(device)
        self.assertEqual(res['packet_loss_percentage'], 5.0)
        self.assertEqual(res['packet_loss_pct'], 5.0)
        self.assertEqual(res['packets_sent'], 20)
        self.assertEqual(res['packets_received'], 19)
        self.assertEqual(res['packets_lost'], 1)
        self.assertEqual(res['minimum_rtt_ms'], 4.0)
        self.assertEqual(res['maximum_rtt_ms'], 25.0)
        self.assertEqual(res['average_rtt_ms'], 8.5)
        self.assertEqual(res['packet_loss_status'], 'MODERATE')
        self.assertEqual(res['overall_status'], 'UP')

    def test_parse_ping_output_windows_partial_loss_canonical_fields(self):
        """Test parsing Windows ping output with partial packet loss and canonical field names."""
        stdout = (
            "Pinging 8.8.8.8 with 32 bytes of data:\n"
            "Reply from 8.8.8.8: bytes=32 time=45ms TTL=117\n"
            "Reply from 8.8.8.8: bytes=32 time=75ms TTL=117\n"
            "Request timed out.\n"
            "Reply from 8.8.8.8: bytes=32 time=385ms TTL=117\n\n"
            "Ping statistics for 8.8.8.8:\n"
            "    Packets: Sent = 20, Received = 17, Lost = 3 (15% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 45ms, Maximum = 385ms, Average = 75ms\n"
        )
        res = monitoring.parse_ping_output(stdout, "", returncode=0, count=20, system="Windows")
        self.assertTrue(res['is_reachable'])
        self.assertTrue(res['reachable'])
        self.assertEqual(res['packets_sent'], 20)
        self.assertEqual(res['packets_received'], 17)
        self.assertEqual(res['packets_lost'], 3)
        self.assertEqual(res['packet_loss_percentage'], 15.0)
        self.assertEqual(res['packet_loss_pct'], 15.0)
        self.assertEqual(res['minimum_rtt_ms'], 45.0)
        self.assertEqual(res['min_rtt_ms'], 45.0)
        self.assertEqual(res['maximum_rtt_ms'], 385.0)
        self.assertEqual(res['max_rtt_ms'], 385.0)
        self.assertEqual(res['average_rtt_ms'], 75.0)
        self.assertEqual(res['avg_rtt_ms'], 75.0)
        self.assertEqual(res['packet_loss_status'], 'HIGH')

    @patch('monitoring.ping_host')
    def test_device_status_remains_up_during_packet_loss(self, mock_ping):
        """Ensure device classification remains UP when packet loss is experienced as long as reachable."""
        mock_ping.return_value = {
            'is_reachable': True,
            'reachable': True,
            'response_time_ms': 75.0,
            'fault_category': 'NONE',
            'fault_details': None,
            'packets_sent': 20,
            'packets_received': 17,
            'packets_lost': 3,
            'packet_loss_percentage': 15.0,
            'packet_loss_pct': 15.0,
            'minimum_rtt_ms': 45.0,
            'min_rtt_ms': 45.0,
            'maximum_rtt_ms': 385.0,
            'max_rtt_ms': 385.0,
            'average_rtt_ms': 75.0,
            'avg_rtt_ms': 75.0,
            'packet_loss_status': 'HIGH'
        }
        device = {'id': 'test-dev-1', 'ip_address': '8.8.8.8', 'port': None}
        check_res = monitoring.check_device_connectivity(device)
        self.assertEqual(check_res['overall_status'], 'UP')
        self.assertEqual(check_res['reachability_status'], 'REACHABLE')
        self.assertEqual(check_res['packet_loss_percentage'], 15.0)
        self.assertEqual(check_res['packets_sent'], 20)
        self.assertEqual(check_res['packets_lost'], 3)

if __name__ == '__main__':
    unittest.main()
