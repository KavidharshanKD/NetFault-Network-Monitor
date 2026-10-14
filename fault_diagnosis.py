"""
Intelligent Fault Localization and Diagnosis Engine for NetFault.
Analyzes multi-layer probe telemetry (ICMP ping, TCP sockets, latency history,
hop-by-hop traceroute paths, and peer subnet devices) to determine probable root causes,
evidence trails, confidence ratings, and actionable remediation steps.
"""

import uuid
import ipaddress
from datetime import datetime, timezone

# Diagnostic Categories supported by NetFault
CAT_HOST_UNREACHABLE = "HOST_UNREACHABLE"
CAT_SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
CAT_CONNECTION_REFUSED = "CONNECTION_REFUSED"
CAT_CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
CAT_DNS_FAILURE = "DNS_RESOLUTION_FAILURE"
CAT_LATENCY_DEGRADATION = "LATENCY_DEGRADATION"
CAT_PACKET_LOSS = "PACKET_LOSS"
CAT_HOP_TIMEOUT = "INTERMEDIATE_HOP_TIMEOUT"
CAT_SHARED_GATEWAY = "SHARED_GATEWAY_FAILURE"
CAT_DEST_UNREACHABLE = "DESTINATION_UNREACHABLE"
CAT_RECOVERED = "RECOVERED"
CAT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

CATEGORY_HUMAN_NAMES = {
    CAT_HOST_UNREACHABLE: "Host Unreachable",
    CAT_SERVICE_UNAVAILABLE: "TCP Service Unavailable",
    CAT_CONNECTION_REFUSED: "Connection Refused",
    CAT_CONNECTION_TIMEOUT: "Connection Timeout",
    CAT_DNS_FAILURE: "DNS Resolution Failure",
    CAT_LATENCY_DEGRADATION: "Increased Network Latency",
    CAT_PACKET_LOSS: "Measured Packet Loss",
    CAT_HOP_TIMEOUT: "Intermediate Traceroute Hop Timeout",
    CAT_SHARED_GATEWAY: "Possible Gateway or Upstream Network Problem",
    CAT_DEST_UNREACHABLE: "Destination Unreachable",
    CAT_RECOVERED: "Recovered Device",
    CAT_INSUFFICIENT: "Insufficient Evidence"
}

UNDETERMINED_CAUSE = (
    "Probable cause undetermined. Available monitoring evidence is insufficient to identify the exact cause."
)

def generate_incident_id():
    """Generates a human-friendly unique incident identifier, e.g. INC-20261014-A1B2."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:4].upper()
    return f"INC-{date_str}-{unique_suffix}"

def _is_same_subnet(ip1_str, ip2_str, prefixlen=24):
    """Checks if two IPv4 addresses belong to the same subnet."""
    try:
        ip1 = ipaddress.ip_address(ip1_str)
        ip2 = ipaddress.ip_address(ip2_str)
        if ip1.version != ip2.version:
            return False
        net1 = ipaddress.ip_network(f"{ip1_str}/{prefixlen}", strict=False)
        return ip2 in net1
    except Exception:
        return False

def diagnose_check(device, current_check, history=None, traceroutes=None,
                   peer_devices=None, settings=None, last_successful_check=None):
    """
    Performs intelligent multi-layer root-cause fault diagnosis on a device check.
    
    Parameters:
      - device: dict with id, device_name, ip_address, port
      - current_check: dict returned by monitoring.check_device_connectivity
      - history: list of past monitoring_history records for this device
      - traceroutes: list of traceroute_history records for this device
      - peer_devices: list of other registered devices with their latest status
      - settings: dict with latency_threshold_ms, packet_loss_threshold_pct, etc.
      - last_successful_check: ISO timestamp of last UP check if known
      
    Returns:
      A structured diagnostic incident dictionary.
    """
    history = history or []
    traceroutes = traceroutes or []
    peer_devices = peer_devices or []
    settings = settings or {}

    dev_id = str(device.get('id', ''))
    dev_name = device.get('device_name', 'Unknown Device')
    ip = str(device.get('ip_address', '')).strip()
    port = device.get('port')
    has_port = port is not None and str(port).strip() != ''

    overall_status = current_check.get('overall_status', 'UNKNOWN')
    reachability = current_check.get('reachability_status', 'UNCHECKED')
    service_status = current_check.get('service_status', 'NOT_CONFIGURED')
    response_time = current_check.get('response_time_ms')
    raw_cat = current_check.get('fault_category') or 'NONE'
    raw_details = current_check.get('fault_details') or ''
    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine last successful check from history if not explicitly passed
    if not last_successful_check:
        for h in history:
            if h.get('overall_status') == 'UP':
                last_successful_check = h.get('checked_at')
                break

    # Thresholds
    latency_threshold = settings.get('latency_threshold_ms', 200)

    # Historical average latency
    past_latencies = [
        float(h['response_time_ms'])
        for h in history
        if h.get('response_time_ms') is not None and h.get('overall_status') == 'UP'
    ][:10]
    avg_past_latency = (
        round(sum(past_latencies) / len(past_latencies), 1)
        if past_latencies else None
    )

    evidence = []
    probable_cause = ""
    category = CAT_INSUFFICIENT
    severity = "INFO"
    confidence = "Medium"
    recommended_action = ""
    is_fault = False
    is_recovery = False

    # -------------------------------------------------------------------------
    # Case 1: Device is completely DOWN
    # -------------------------------------------------------------------------
    if overall_status == 'DOWN':
        is_fault = True
        severity = "CRITICAL"
        evidence.append(f"Confirmed Observation: ICMP echo probe reported '{reachability}'.")
        if has_port:
            evidence.append(f"Confirmed Observation: TCP handshake on port {port} reported '{service_status}'.")
        if raw_details:
            evidence.append(f"Probe Error: {raw_details}")

        # Check multi-device correlation (Shared Gateway / Subnet failure)
        unreachable_peers = []
        for p in peer_devices:
            if str(p.get('id')) != dev_id and p.get('overall_status') in ('DOWN', 'FAULT'):
                p_ip = str(p.get('ip_address', ''))
                if _is_same_subnet(ip, p_ip):
                    unreachable_peers.append(f"{p.get('device_name')} ({p_ip})")

        # Traceroute correlation if available
        latest_trace = traceroutes[0] if traceroutes else None
        trace_fault_hop = None
        if latest_trace:
            trace_fault_hop = latest_trace.get('fault_hop')
            if latest_trace.get('destination_reached'):
                evidence.append("Historical Trace Observation: Route previously reached target successfully.")
            elif trace_fault_hop is not None:
                evidence.append(
                    f"Traceroute Finding: Upstream packet loss detected at Hop {trace_fault_hop}."
                )

        if len(unreachable_peers) >= 1:
            category = CAT_SHARED_GATEWAY
            confidence = "High" if len(unreachable_peers) >= 2 else "Medium"
            probable_cause = (
                f"Probable Explanation: Common gateway or subnet failure. Multiple hosts on the same network "
                f"are simultaneously unreachable: {', '.join(unreachable_peers[:3])}."
            )
            recommended_action = (
                f"Inspect the common default gateway router, upstream switch, or VLAN trunk for subnet {ip}/24. "
                f"Verify physical link lights and ARP tables."
            )
        elif trace_fault_hop == 1:
            category = CAT_SHARED_GATEWAY
            confidence = "High"
            probable_cause = (
                "Probable Explanation: Local default gateway failure. Traceroute indicates packet loss immediately at Hop 1."
            )
            recommended_action = (
                "Verify the local network interface, DHCP lease, and reachability of the local default gateway router."
            )
        elif "destination host unreachable" in raw_details.lower():
            category = CAT_DEST_UNREACHABLE
            confidence = "High"
            probable_cause = (
                "Confirmed Observation: Upstream router returned ICMP Type 3 (Destination Host Unreachable). "
                "The target host is offline or the routing table has no route to the destination."
            )
            recommended_action = (
                "Check power state of target host. Verify router interface IP configuration and static/dynamic routes."
            )
        elif "timed out" in raw_details.lower() or raw_cat == "NETWORK_TIMEOUT":
            category = CAT_HOST_UNREACHABLE
            confidence = "Medium"
            probable_cause = (
                "Probable Explanation: Host is powered off, disconnected from the network, "
                "or dropping all incoming packets with a silent drop firewall rule."
            )
            recommended_action = (
                "Confirm physical network cabling and power status on the target device. "
                "Check if any local host firewall (e.g. Windows Firewall, iptables) is dropping ICMP and TCP traffic."
            )
        else:
            category = CAT_HOST_UNREACHABLE
            confidence = "Low"
            probable_cause = UNDETERMINED_CAUSE
            recommended_action = (
                "Verify end-to-end IP routing from the monitoring agent to the target host and examine server logs."
            )

    # -------------------------------------------------------------------------
    # Case 2: Host reachable, but configured TCP service is FAULT
    # -------------------------------------------------------------------------
    elif overall_status == 'FAULT':
        is_fault = True
        severity = "HIGH"
        evidence.append(f"Confirmed Observation: Host is reachable via ICMP ping ({response_time} ms latency).")
        evidence.append(f"Confirmed Observation: Configured TCP service on port {port} failed: {service_status}.")
        if raw_details:
            evidence.append(f"Probe Error: {raw_details}")

        if service_status == "REFUSED" or raw_cat == "SERVICE_REFUSED" or "refused" in raw_details.lower():
            category = CAT_CONNECTION_REFUSED
            confidence = "High"
            probable_cause = (
                f"Confirmed Observation: The host actively returned a TCP RST packet on port {port}. "
                f"The operating system is online, but no listening daemon is bound to port {port}, "
                f"or the service process has crashed."
            )
            recommended_action = (
                f"Connect to {ip} and verify that the target daemon is running and listening on port {port} "
                f"(e.g., systemctl status <service> or netstat -an | findstr :{port})."
            )
        elif service_status == "TIMEOUT" or raw_cat == "SERVICE_TIMEOUT" or "timed out" in raw_details.lower():
            category = CAT_CONNECTION_TIMEOUT
            confidence = "Medium"
            probable_cause = (
                f"Probable Explanation: TCP SYN packet to port {port} was silently discarded. "
                f"A network firewall, security group, or local software firewall is actively filtering port {port}."
            )
            recommended_action = (
                f"Inspect firewall ACLs, security group ingress rules, or local iptables/Windows Firewall on {ip} "
                f"to ensure TCP port {port} is permitted."
            )
        else:
            category = CAT_SERVICE_UNAVAILABLE
            confidence = "Medium"
            probable_cause = (
                f"Probable Explanation: The application service on port {port} is not accepting connections."
            )
            recommended_action = f"Check application server logs and process status for port {port} on {ip}."

    # -------------------------------------------------------------------------
    # Case 3: Device is UP, but check for sustained latency degradation
    # -------------------------------------------------------------------------
    elif overall_status == 'UP':
        evidence.append(f"Confirmed Observation: Reachability status is '{reachability}'.")
        if has_port:
            evidence.append(f"Confirmed Observation: TCP port {port} is OPEN ({response_time} ms).")
        else:
            evidence.append(f"Confirmed Observation: Host responded to ICMP echo probe ({response_time} ms).")

        # Check for critical packet loss threshold crossing
        # (Exclude ICMP_FILTERED devices where ICMP is deliberately blocked by firewall while TCP is UP)
        pkt_loss_critical = float(settings.get('packet_loss_critical_pct') or settings.get('packet_loss_threshold_pct') or 10.0)
        pkt_loss_warning = float(settings.get('packet_loss_warning_pct') or 5.0)
        loss_pct = current_check.get('packet_loss_pct')

        if reachability != 'ICMP_FILTERED' and raw_cat != 'FIREWALL_FILTERED' and loss_pct is not None and loss_pct >= pkt_loss_critical:
            is_fault = True
            category = CAT_PACKET_LOSS
            severity = "WARNING"
            confidence = "High"
            probable_cause = (
                f"Confirmed Observation: Measured packet loss of {loss_pct:.2f}% exceeds configured critical threshold "
                f"({pkt_loss_critical}%). Probe Transmission: {current_check.get('packets_lost', 0)} of "
                f"{current_check.get('packets_sent', 20)} echo probes dropped."
            )
            evidence.append(f"Packet Loss Threshold Violation: Observed {loss_pct:.2f}% packet loss >= critical limit {pkt_loss_critical}%.")
            evidence.append(f"Probe Transmission Audit: {current_check.get('packets_sent', 20)} sent, {current_check.get('packets_received', 0)} received, {current_check.get('packets_lost', 0)} lost.")
            if current_check.get('avg_rtt_ms'):
                evidence.append(f"ICMP Latency Statistics: min={current_check.get('min_rtt_ms')} ms, avg={current_check.get('avg_rtt_ms')} ms, max={current_check.get('max_rtt_ms')} ms.")
            recommended_action = (
                f"Perform hop-by-hop route trace to isolate intermediate hop packet loss or inspect network interface counters on {ip}."
            )
        # Check for significant latency degradation
        elif response_time is not None and response_time >= latency_threshold:
            # Check if this is a spike or sustained
            recent_high = sum(
                1 for h in history[:3]
                if h.get('response_time_ms') is not None and h.get('response_time_ms') >= latency_threshold
            )
            is_fault = True
            category = CAT_LATENCY_DEGRADATION
            severity = "WARNING"
            confidence = "High" if recent_high >= 2 else "Medium"
            probable_cause = (
                f"Confirmed Observation: Response time ({response_time} ms) significantly exceeds "
                f"the configured threshold ({latency_threshold} ms)."
                + (f" Baseline historical average: {avg_past_latency} ms." if avg_past_latency else "")
            )
            evidence.append(f"Threshold Violation: Observed {response_time} ms >= configured limit {latency_threshold} ms.")
            if avg_past_latency:
                evidence.append(f"Baseline Comparison: Normal average is {avg_past_latency} ms ({round(response_time/avg_past_latency, 1)}x increase).")

            # Check if traceroute shows hop where latency rose
            latest_trace = traceroutes[0] if traceroutes else None
            if latest_trace and latest_trace.get('hops'):
                for h in latest_trace['hops']:
                    if h.get('avg_rtt_ms') and h['avg_rtt_ms'] > 100:
                        evidence.append(
                            f"Unverified Hypothesis: Traceroute indicates elevated latency begins near Hop {h['hop']} ({h.get('ip')})."
                        )
                        break

            recommended_action = (
                f"Run a hop-by-hop route trace to isolate routing congestion or intermediate ISP latency bottlenecks. "
                f"Verify CPU/bandwidth utilization on {ip}."
            )
        else:
            # Healthy UP
            category = CAT_RECOVERED
            severity = "INFO"
            probable_cause = "All monitored parameters are within nominal thresholds."
            recommended_action = "No action required. Host and configured services are fully operational."
            is_recovery = True

    # -------------------------------------------------------------------------
    # Case 4: UNKNOWN or Inconclusive
    # -------------------------------------------------------------------------
    else:
        severity = "WARNING"
        confidence = "Low"
        category = CAT_INSUFFICIENT
        probable_cause = UNDETERMINED_CAUSE
        evidence.append(f"Raw Monitoring Status: {overall_status}")
        evidence.append(f"Details: {raw_details or 'No diagnostic data returned by probe.'}")
        recommended_action = "Retry the manual check and verify network interface status on the monitoring host."

    return {
        'incident_id': generate_incident_id(),
        'device_id': dev_id,
        'device_name': dev_name,
        'ip_address': ip,
        'port': port,
        'current_status': overall_status,
        'fault_category': category,
        'fault_category_name': CATEGORY_HUMAN_NAMES.get(category, category),
        'severity': severity,
        'probable_cause': probable_cause,
        'evidence': evidence,
        'confidence_level': confidence,
        'recommended_action': recommended_action,
        'detection_timestamp': now_iso,
        'last_successful_check': last_successful_check,
        'response_time_ms': response_time,
        'packets_sent': current_check.get('packets_sent'),
        'packets_received': current_check.get('packets_received'),
        'packets_lost': current_check.get('packets_lost'),
        'packet_loss_pct': current_check.get('packet_loss_pct'),
        'min_rtt_ms': current_check.get('min_rtt_ms'),
        'max_rtt_ms': current_check.get('max_rtt_ms'),
        'avg_rtt_ms': current_check.get('avg_rtt_ms'),
        'packet_loss_status': current_check.get('packet_loss_status'),
        'is_fault': is_fault,
        'is_recovery': is_recovery
    }

def analyze_hop_by_hop_comparison(current_trace, past_traces=None):
    """
    Compares a new traceroute execution against past historical traces.
    Correctly accounts for router ICMP deprioritization vs genuine route breaks.
    """
    past_traces = past_traces or []
    current_hops = current_trace.get('hops', [])
    dest_reached = current_trace.get('destination_reached', False)
    target_ip = current_trace.get('target_ip', '')

    findings = []
    
    # Rule 1: Intermediate timeout when destination reached is non-fatal
    if dest_reached:
        timed_out_hops = [h['hop'] for h in current_hops if h.get('status') == 'TIMED_OUT']
        if timed_out_hops:
            findings.append({
                'type': 'OBSERVATION',
                'summary': (
                    f"Intermediate hop(s) {', '.join(map(str, timed_out_hops))} did not respond, "
                    f"but destination {target_ip} was reached successfully. "
                    f"Intermediate routers commonly filter or deprioritize ICMP TTL-exceeded replies."
                ),
                'actionable': False
            })

    # Rule 2: Persistent latency elevation check
    elevated_hop = None
    for i, h in enumerate(current_hops):
        if h.get('avg_rtt_ms') and h['avg_rtt_ms'] > 120:
            # Check if later hops also remain elevated
            later_hops = current_hops[i+1:]
            if later_hops and all(lh.get('avg_rtt_ms', 0) > 100 for lh in later_hops if lh.get('avg_rtt_ms')):
                elevated_hop = h
                break

    if elevated_hop:
        findings.append({
            'type': 'HYPOTHESIS',
            'summary': (
                f"Possible network-path issue: Latency increases at Hop {elevated_hop['hop']} ({elevated_hop.get('ip')}) "
                f"and remains elevated across downstream hops. Requires further inspection."
            ),
            'actionable': True
        })

    # Rule 3: Compare with past trace if available
    if past_traces and len(past_traces) > 0:
        prev = past_traces[0]
        prev_hops = prev.get('hops', [])
        if len(prev_hops) != len(current_hops) and dest_reached and prev.get('destination_reached'):
            diff = len(current_hops) - len(prev_hops)
            findings.append({
                'type': 'OBSERVATION',
                'summary': f"Route path changed: Total hops shifted by {diff:+d} (from {len(prev_hops)} to {len(current_hops)}).",
                'actionable': False
            })

    return findings

def get_localization_for_incident(incident):
    """
    Computes a comprehensive Fault Localization assessment for any incident record.
    Returns:
      - layer: Network layer (Layer 3, Layer 4, Layer 7, Gateway)
      - localized_boundary: Exact network component where failure was localized
      - observation_type: Confirmed Observation vs Probable Explanation vs Unverified Hypothesis
      - summary: Clear human explanation of the failure boundary
      - path: Visual path topology nodes for UI display
    """
    cat = incident.get('fault_category', '')
    port = incident.get('port')
    ip = incident.get('ip_address', 'N/A')
    dev_name = incident.get('device_name', 'Device')
    status = incident.get('current_status') or incident.get('incident_status')

    if cat in (CAT_CONNECTION_REFUSED, CAT_CONNECTION_TIMEOUT, CAT_SERVICE_UNAVAILABLE) or (port and 'PORT' in str(cat)):
        layer = "Layer 4 (Transport / TCP Service Socket)"
        boundary = f"Port {port} on {dev_name} ({ip})"
        if cat == CAT_CONNECTION_REFUSED:
            obs_type = "Confirmed Observation"
            summary = f"Failure localized to destination port {port}. Host network stack is online and actively returned TCP RST."
        elif cat == CAT_CONNECTION_TIMEOUT:
            obs_type = "Probable Explanation"
            summary = f"Failure localized to service firewall or ingress ACL. TCP SYN packets to port {port} are silently dropped."
        else:
            obs_type = "Confirmed Observation"
            summary = f"Failure localized to TCP service port {port}. Port is unresponsive to connection handshakes."

        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': 'Local Gateway', 'status': 'OK', 'desc': 'Transit OK'},
            {'name': f'Target Host ({ip})', 'status': 'OK', 'desc': 'ICMP Echo Reply OK'},
            {'name': f'TCP Port {port}', 'status': 'FAULT', 'desc': f'Localized: {cat}'}
        ]

    elif cat == CAT_SHARED_GATEWAY:
        layer = "Layer 3 (Default Gateway / Subnet Router)"
        boundary = f"Upstream Gateway for Subnet {ip}/24"
        obs_type = "Probable Explanation"
        summary = f"Failure localized to shared network gateway. Multiple devices on subnet {ip}/24 are simultaneously unreachable."
        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': f'Gateway (Subnet {ip}/24)', 'status': 'DOWN', 'desc': 'Localized: Packet loss / break'},
            {'name': f'{dev_name} ({ip})', 'status': 'UNREACHABLE', 'desc': 'Upstream transit blocked'}
        ]

    elif cat == CAT_LATENCY_DEGRADATION:
        layer = "Layer 3 (Network Transit Congestion / Intermediate ISP)"
        boundary = f"Transit Path to {ip}"
        obs_type = "Confirmed Observation"
        summary = "Sustained round-trip probe latency exceeds configured threshold along the routing path."
        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': 'Intermediate Routing Path', 'status': 'WARNING', 'desc': 'Localized: Elevated RTT'},
            {'name': f'{dev_name} ({ip})', 'status': 'OK', 'desc': 'Host responding with delay'}
        ]

    elif cat == CAT_DEST_UNREACHABLE:
        layer = "Layer 3 (Routing / Target Subnet)"
        boundary = f"Intermediate Router to {ip}"
        obs_type = "Confirmed Observation"
        summary = "Router returned ICMP Destination Host Unreachable (Type 3). No active route or host ARP resolution."
        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': 'Upstream Router', 'status': 'FAULT', 'desc': 'Localized: ICMP Type 3 Unreachable'},
            {'name': f'{dev_name} ({ip})', 'status': 'DOWN', 'desc': 'Unreachable'}
        ]

    elif cat == CAT_RECOVERED:
        layer = "All Layers Nominal"
        boundary = f"{dev_name} ({ip})"
        obs_type = "Confirmed Observation"
        summary = "Device has fully recovered. All reachability and configured port probes verified nominal."
        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': 'Local Gateway', 'status': 'OK', 'desc': 'Transit OK'},
            {'name': f'{dev_name} ({ip})', 'status': 'OK', 'desc': 'Online & Nominal'}
        ]

    else:
        layer = "Layer 3 (Network / Host Stack)"
        boundary = f"Target Host {dev_name} ({ip})"
        obs_type = "Confirmed Observation" if status == 'DOWN' else "Unverified Hypothesis"
        summary = f"Failure localized to destination host network interface or power state. No response to ICMP or TCP probes."
        path = [
            {'name': 'NetFault Station', 'status': 'OK', 'desc': 'Probe dispatched'},
            {'name': 'Local Gateway', 'status': 'OK', 'desc': 'Transit OK'},
            {'name': f'{dev_name} ({ip})', 'status': 'DOWN', 'desc': 'Localized: Total packet drop'}
        ]

    return {
        'layer': layer,
        'localized_boundary': boundary,
        'observation_type': obs_type,
        'summary': summary,
        'path': path
    }
