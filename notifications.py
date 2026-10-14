"""
Immediate Email Notification and Alert Dispatcher Service for NetFault.
Provides reliable, non-blocking email dispatch, duplicate alert suppression,
timezone-aware formatting (Asia/Kolkata), multi-part HTML/Plaintext templates,
and delivery audit logging to Supabase notification_history.
"""

import sys
import smtplib
import logging
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor

from config import Config
import database

logger = logging.getLogger(__name__)

# Bounded thread pool for non-blocking asynchronous email delivery
_email_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="NetFault-Mailer")

def format_local_timestamp(iso_or_dt_str, tz_name=None):
    """
    Converts a UTC ISO timestamp or datetime string to a human-readable
    timezone-aware representation (defaults to Asia/Kolkata).
    Example: 2026-10-14 17:30:15 IST
    """
    if not iso_or_dt_str:
        return "N/A (No prior record)"

    tz_name = tz_name or Config.APP_TIMEZONE or 'Asia/Kolkata'
    try:
        if isinstance(iso_or_dt_str, datetime):
            dt = iso_or_dt_str
        else:
            clean_str = str(iso_or_dt_str).replace('Z', '+00:00')
            dt = datetime.fromisoformat(clean_str)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        target_tz = ZoneInfo(tz_name)
        local_dt = dt.astimezone(target_tz)
        tz_abbr = local_dt.tzname() or tz_name
        return f"{local_dt.strftime('%Y-%m-%d %H:%M:%S')} {tz_abbr}"
    except Exception as e:
        logger.debug(f"Timestamp conversion fallback: {e}")
        return str(iso_or_dt_str)

def format_duration(start_iso, end_iso):
    """Calculates human-readable outage duration between two timestamps."""
    try:
        s_dt = datetime.fromisoformat(str(start_iso).replace('Z', '+00:00'))
        e_dt = datetime.fromisoformat(str(end_iso).replace('Z', '+00:00'))
        delta = e_dt - s_dt
        total_seconds = int(max(0, delta.total_seconds()))

        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if hours > 0:
            parts.append(f"{hours} hr{'s' if hours > 1 else ''}")
        if minutes > 0:
            parts.append(f"{minutes} min{'s' if minutes > 1 else ''}")
        parts.append(f"{seconds} sec{'s' if seconds != 1 else ''}")
        return " ".join(parts)
    except Exception:
        return "Unknown duration"

def build_fault_email(incident, settings=None):
    """
    Builds subject, plain-text body, and HTML body for a newly detected fault incident.
    """
    settings = settings or {}
    public_url = (
        settings.get('netfault_public_url') or 
        Config.NETFAULT_PUBLIC_URL or 
        'http://127.0.0.1:5000'
    ).rstrip('/')

    dev_name = incident.get('device_name', 'Unknown Device')
    ip = incident.get('ip_address', 'N/A')
    port = incident.get('port')
    port_str = f":{port}" if port else ""
    status = incident.get('current_status', 'FAULT')
    severity = incident.get('severity', 'CRITICAL')
    category_name = incident.get('fault_category_name') or incident.get('fault_category')
    detected_at = format_local_timestamp(incident.get('detection_timestamp') or incident.get('first_detected_at'))
    last_success = format_local_timestamp(incident.get('last_successful_check'))
    probable_cause = incident.get('probable_cause') or "Probable cause undetermined."
    evidence_list = incident.get('evidence') or []
    if isinstance(evidence_list, str):
        evidence_list = [evidence_list]
    confidence = incident.get('confidence_level', 'Medium')
    recommended_action = incident.get('recommended_action', 'Verify device connectivity.')
    inc_id = incident.get('incident_id', 'INC-UNKNOWN')
    latency = incident.get('response_time_ms')
    latency_str = f"{latency} ms" if latency is not None else "N/A (Packet loss / unreachable)"

    # Subject line based on status & severity
    if status == 'DOWN':
        subject = f"[NetFault CRITICAL] Device DOWN — {dev_name} ({ip})"
    elif status == 'FAULT':
        subject = f"[NetFault FAULT] TCP Service Unavailable — {dev_name} ({ip}{port_str})"
    else:
        subject = f"[NetFault {severity}] {category_name} — {dev_name} ({ip})"

    # Fault Localization
    loc = incident.get('fault_localization')
    if not loc:
        try:
            import fault_diagnosis
            loc = fault_diagnosis.get_localization_for_incident(incident)
        except Exception:
            loc = None
    loc_layer = loc.get('layer', 'Layer 3/4 Boundary') if loc else 'Layer 3/4 Boundary'
    loc_boundary = loc.get('localized_boundary', f'{dev_name} ({ip})') if loc else f'{dev_name} ({ip})'

    # Plain text version
    evidence_text = "\n".join(f"  - {e}" for e in evidence_list) if evidence_list else "  - None reported"
    plain_text = f"""NETFAULT — IMMEDIATE FAULT ALERT

Incident ID: {inc_id}
Device Name: {dev_name}
IP Address: {ip}
Configured Port: {port if port else 'None'}
Status: {status} (Severity: {severity})
Fault Localization: {loc_layer} — {loc_boundary}
Failure Detected At: {detected_at}
Last Successful Check: {last_success}
Current Latency: {latency_str}
Fault Category: {category_name}
Confidence Level: {confidence}

Probable Cause:
{probable_cause}

Supporting Evidence:
{evidence_text}

Recommended Action:
{recommended_action}

Dashboard Link:
{public_url}/devices/{incident.get('device_id', '')}
"""

    # Rich HTML version
    evidence_html = "".join(f"<li style='margin-bottom: 6px;'>{e}</li>" for e in evidence_list) if evidence_list else "<li>No evidence records available</li>"

    status_color = "#dc2626" if status == "DOWN" else ("#ea580c" if status == "FAULT" else "#eab308")

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }}
  .container {{ max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
  .header {{ background: #0f172a; padding: 24px; color: #ffffff; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background: {status_color}; color: #ffffff; }}
  .content {{ padding: 24px; }}
  .grid {{ display: table; width: 100%; margin-bottom: 20px; }}
  .row {{ display: table-row; }}
  .label {{ display: table-cell; padding: 6px 12px 6px 0; color: #64748b; font-size: 13px; font-weight: 600; width: 38%; }}
  .value {{ display: table-cell; padding: 6px 0; color: #0f172a; font-size: 13.5px; }}
  .section {{ margin-top: 20px; padding: 14px 16px; border-radius: 8px; background: #f1f5f9; border-left: 4px solid {status_color}; }}
  .section-title {{ font-size: 12.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #475569; margin-bottom: 6px; }}
  .action-box {{ margin-top: 20px; padding: 14px 16px; border-radius: 8px; background: #eff6ff; border-left: 4px solid #3b82f6; }}
  .btn {{ display: inline-block; margin-top: 24px; padding: 12px 22px; background: #0f172a; color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 13.5px; }}
  .footer {{ padding: 16px 24px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11.5px; color: #94a3b8; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h2 style="margin: 0; font-size: 18px; font-weight: 700; letter-spacing: -0.3px;">NetFault Network Alert</h2>
      <span class="badge">{severity} &bull; {status}</span>
    </div>
    <div style="font-size: 12.5px; color: #94a3b8; margin-top: 6px;">Incident ID: <strong>{inc_id}</strong></div>
  </div>

  <div class="content">
    <div class="grid">
      <div class="row"><div class="label">Device Name:</div><div class="value"><strong>{dev_name}</strong></div></div>
      <div class="row"><div class="label">IP Address:</div><div class="value"><code>{ip}{port_str}</code></div></div>
      <div class="row"><div class="label">Fault Category:</div><div class="value">{category_name}</div></div>
      <div class="row"><div class="label">Fault Localization:</div><div class="value"><strong style="color: #0f172a;">{loc_layer}</strong> &bull; <span style="color: #b91c1c; font-weight: 600;">{loc_boundary}</span></div></div>
      <div class="row"><div class="label">Failure Detected At:</div><div class="value">{detected_at}</div></div>
      <div class="row"><div class="label">Last Successful Check:</div><div class="value">{last_success}</div></div>
      <div class="row"><div class="label">Current Latency:</div><div class="value">{latency_str}</div></div>
      <div class="row"><div class="label">Diagnosis Confidence:</div><div class="value"><strong>{confidence}</strong></div></div>
    </div>

    <div class="section">
      <div class="section-title">Probable Cause</div>
      <div style="font-size: 13.5px; line-height: 1.5; color: #1e293b;">{probable_cause}</div>
    </div>

    <div class="section" style="border-left-color: #64748b;">
      <div class="section-title">Supporting Evidence</div>
      <ul style="margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.5; color: #334155;">
        {evidence_html}
      </ul>
    </div>

    <div class="action-box">
      <div class="section-title" style="color: #1d4ed8;">Recommended Troubleshooting Action</div>
      <div style="font-size: 13.5px; line-height: 1.5; color: #1e3a8a;">{recommended_action}</div>
    </div>

    <div style="text-align: center;">
      <a href="{public_url}/devices/{incident.get('device_id', '')}" class="btn">Inspect in NetFault Console &rarr;</a>
    </div>
  </div>

  <div class="footer">
    Automated Fault Detection System &bull; Intelligent Network Telemetry & Immediate Notification Engine
  </div>
</div>
</body>
</html>"""

    return subject, plain_text, html_content

def build_recovery_email(incident, recovery_timestamp=None, settings=None):
    """
    Builds subject and body for a device recovery event.
    """
    settings = settings or {}
    public_url = (
        settings.get('netfault_public_url') or 
        Config.NETFAULT_PUBLIC_URL or 
        'http://127.0.0.1:5000'
    ).rstrip('/')

    dev_name = incident.get('device_name', 'Unknown Device')
    ip = incident.get('ip_address', 'N/A')
    port = incident.get('port')
    port_str = f":{port}" if port else ""
    inc_id = incident.get('incident_id', 'INC-UNKNOWN')
    category_name = incident.get('fault_category_name') or incident.get('fault_category', 'Outage')
    
    first_detected = incident.get('first_detected_at') or incident.get('detection_timestamp')
    first_detected_str = format_local_timestamp(first_detected)
    rec_time = recovery_timestamp or datetime.now(timezone.utc).isoformat()
    recovery_str = format_local_timestamp(rec_time)
    duration_str = format_duration(first_detected, rec_time)

    subject = f"[NetFault RECOVERED] {dev_name} is UP"

    plain_text = f"""NETFAULT — INCIDENT RESOLUTION / RECOVERY

Incident ID: {inc_id}
Device Name: {dev_name}
IP Address: {ip}{port_str}
Current Status: UP (Recovered)
Original Failure Time: {first_detected_str}
Recovery Detected At: {recovery_str}
Total Outage Duration: {duration_str}
Previous Fault Category: {category_name}

Recovery Evidence:
Host and configured service responded successfully to active probes. Nominal latency restored.

Dashboard Link:
{public_url}/devices/{incident.get('device_id', '')}
"""

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }}
  .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
  .header {{ background: #065f46; padding: 24px; color: #ffffff; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: #10b981; color: #ffffff; }}
  .content {{ padding: 24px; }}
  .grid {{ display: table; width: 100%; margin-bottom: 20px; }}
  .row {{ display: table-row; }}
  .label {{ display: table-cell; padding: 6px 12px 6px 0; color: #64748b; font-size: 13px; font-weight: 600; width: 40%; }}
  .value {{ display: table-cell; padding: 6px 0; color: #0f172a; font-size: 13.5px; }}
  .box {{ margin-top: 16px; padding: 14px 16px; border-radius: 8px; background: #f0fdf4; border-left: 4px solid #10b981; font-size: 13.5px; color: #065f46; }}
  .btn {{ display: inline-block; margin-top: 24px; padding: 12px 22px; background: #065f46; color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 13.5px; }}
  .footer {{ padding: 16px 24px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11.5px; color: #94a3b8; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h2 style="margin: 0; font-size: 18px; font-weight: 700;">Service Recovered</h2>
      <span class="badge">RECOVERED &bull; UP</span>
    </div>
    <div style="font-size: 12.5px; color: #a7f3d0; margin-top: 6px;">Resolved Incident: <strong>{inc_id}</strong></div>
  </div>

  <div class="content">
    <div class="grid">
      <div class="row"><div class="label">Device Name:</div><div class="value"><strong>{dev_name}</strong></div></div>
      <div class="row"><div class="label">IP Address:</div><div class="value"><code>{ip}{port_str}</code></div></div>
      <div class="row"><div class="label">Initial Failure Time:</div><div class="value">{first_detected_str}</div></div>
      <div class="row"><div class="label">Recovery Detected At:</div><div class="value">{recovery_str}</div></div>
      <div class="row"><div class="label">Total Outage Duration:</div><div class="value"><strong>{duration_str}</strong></div></div>
      <div class="row"><div class="label">Previous Fault Category:</div><div class="value">{category_name}</div></div>
    </div>

    <div class="box">
      <strong>Recovery Verified:</strong> Active ICMP/TCP probes confirmed host reachability and service availability. Incident is marked RESOLVED.
    </div>

    <div style="text-align: center;">
      <a href="{public_url}/devices/{incident.get('device_id', '')}" class="btn">View Device History &rarr;</a>
    </div>
  </div>

  <div class="footer">
    NetFault Automated Monitoring &bull; All Systems Nominal
  </div>
</div>
</body>
</html>"""

    return subject, plain_text, html_content

def _send_smtp_message(recipient_email, subject, plain_text, html_content=None, settings=None):
    """
    Synchronous SMTP dispatch. Raises on failure.
    Validates credentials and uses TLS encryption.
    """
    settings = settings or {}
    
    host = settings.get('smtp_host') or Config.SMTP_HOST
    port = settings.get('smtp_port') or Config.SMTP_PORT
    try:
        port = int(port)
    except Exception:
        port = 587

    user = settings.get('smtp_username') or Config.SMTP_USERNAME
    pwd = settings.get('smtp_password') or Config.SMTP_PASSWORD
    use_tls = bool(settings.get('smtp_use_tls', Config.SMTP_USE_TLS))
    sender = settings.get('alert_sender_email') or Config.ALERT_SENDER_EMAIL or 'netfault-alerts@local'

    if not host:
        raise ValueError("SMTP_HOST is not configured. Please define SMTP host in Settings or .env file.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient_email
    msg['Date'] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    part1 = MIMEText(plain_text, 'plain', 'utf-8')
    msg.attach(part1)

    if html_content:
        part2 = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(part2)

    logger.info(f"Connecting to SMTP server {host}:{port} to send email to {recipient_email}...")
    server = smtplib.SMTP(host, port, timeout=12)
    try:
        server.ehlo()
        if use_tls:
            server.starttls()
            server.ehlo()
        if user and pwd:
            server.login(user, pwd)
        server.sendmail(sender, [recipient_email], msg.as_string())
        logger.info(f"Email successfully delivered to {recipient_email}: '{subject}'")
        return True
    finally:
        try:
            server.quit()
        except Exception:
            pass

def dispatch_notification_async(incident_record_id, recipient_email, notification_type,
                                subject, plain_text, html_content=None, settings=None, client=None, sync=False):
    """
    Dispatches an email notification asynchronously in the background.
    Logs delivery status (SENT or FAILED) directly into Supabase notification_history.
    """
    resolved_client = client or database.get_supabase_client()

    def _worker():
        try:
            _send_smtp_message(
                recipient_email=recipient_email,
                subject=subject,
                plain_text=plain_text,
                html_content=html_content,
                settings=settings
            )
            # Log successful delivery
            try:
                database.log_notification(
                    incident_id=incident_record_id,
                    recipient_email=recipient_email,
                    notification_type=notification_type,
                    subject=subject,
                    delivery_status='SENT',
                    error_message=None,
                    client=resolved_client
                )
            except Exception as db_err:
                logger.error(f"Failed to log SENT notification to Supabase: {db_err}")

        except Exception as e:
            err_msg = str(e)
            logger.error(f"Email delivery failed to {recipient_email}: {err_msg}")
            try:
                database.log_notification(
                    incident_id=incident_record_id,
                    recipient_email=recipient_email,
                    notification_type=notification_type,
                    subject=subject,
                    delivery_status='FAILED',
                    error_message=err_msg,
                    client=resolved_client
                )
            except Exception as db_err:
                logger.error(f"Failed to log FAILED notification to Supabase: {db_err}")

    # Auto-detect synchronous execution during unit testing or explicit sync flag
    should_run_sync = (
        sync or
        ('pytest' in sys.modules) or
        (resolved_client is not None and type(resolved_client).__name__ == 'MockSupabaseClient')
    )
    if should_run_sync:
        _worker()
    else:
        _email_executor.submit(_worker)

def handle_incident_notifications(device, diagnosis, current_check, client=None, sync=False):
    """
    Master handler called during monitoring sweep:
    1. If diagnosis is a FAULT / DOWN (or latency degradation):
       - Checks for existing OPEN incident for this device.
       - If no open incident: creates incident and sends IMMEDIATE fault email!
       - If existing open incident: updates last_observed_at and evidence, does NOT resend initial email.
    2. If diagnosis is UP (Recovery):
       - Checks for existing OPEN incident for this device.
       - If an open incident exists: marks it RESOLVED and sends ONE recovery email!
    """
    dev_id = str(device.get('id', ''))
    settings = database.get_settings(client=client)
    notifications_enabled = bool(settings.get('email_notifications_enabled', 0))
    recipients_str = settings.get('alert_recipient_email', '') or Config.ALERT_RECIPIENT_EMAIL or ''
    recipients = [r.strip() for r in recipients_str.split(',') if r.strip() and '@' in r]

    # Check active open incident in Supabase
    open_incident = database.get_active_incident_for_device(dev_id, client=client)

    if diagnosis.get('is_fault'):
        status = diagnosis.get('current_status')
        cat = diagnosis.get('fault_category')
        
        # Check alert preferences
        alert_wanted = True
        if status == 'DOWN' and not bool(settings.get('alert_on_down', 1)):
            alert_wanted = False
        elif status == 'FAULT' and not bool(settings.get('alert_on_fault', 1)):
            alert_wanted = False
        elif cat == 'LATENCY_DEGRADATION' and not bool(settings.get('alert_on_latency', 1)):
            alert_wanted = False

        if not open_incident:
            # CREATE NEW INCIDENT
            inc_record = database.create_incident(
                device_id=dev_id,
                user_id=device.get('user_id'),
                fault_category=diagnosis['fault_category'],
                severity=diagnosis['severity'],
                error_details=current_check.get('fault_details'),
                diagnostic_summary=diagnosis.get('probable_cause'),
                probable_cause=diagnosis.get('probable_cause'),
                evidence=diagnosis.get('evidence', []),
                confidence_level=diagnosis.get('confidence_level', 'Medium'),
                recommended_action=diagnosis.get('recommended_action'),
                last_successful_check=diagnosis.get('last_successful_check'),
                client=client
            )

            # DISPATCH IMMEDIATE EMAIL ALERT
            if notifications_enabled and alert_wanted and recipients:
                subj, plain, html = build_fault_email(diagnosis, settings=settings)
                for rec in recipients:
                    dispatch_notification_async(
                        incident_record_id=inc_record.get('id'),
                        recipient_email=rec,
                        notification_type='NEW_FAULT' if cat != 'LATENCY_DEGRADATION' else 'LATENCY_WARNING',
                        subject=subj,
                        plain_text=plain,
                        html_content=html,
                        settings=settings,
                        client=client,
                        sync=sync
                    )
            return inc_record
        else:
            # PERSISTENT FAULT: Update ongoing incident
            database.update_incident_observation(
                incident_id=open_incident['id'],
                error_details=current_check.get('fault_details'),
                evidence=diagnosis.get('evidence', []),
                client=client
            )
            return open_incident

    elif diagnosis.get('is_recovery') and open_incident:
        # RESOLVE INCIDENT & SEND RECOVERY EMAIL
        now_iso = datetime.now(timezone.utc).isoformat()
        resolved_inc = database.resolve_incident(
            incident_id=open_incident['id'],
            recovered_at=now_iso,
            client=client
        )

        recovery_wanted = bool(settings.get('alert_on_recovery', 1))
        if notifications_enabled and recovery_wanted and recipients:
            # Attach device metadata for template
            open_incident['device_name'] = device.get('device_name')
            open_incident['ip_address'] = device.get('ip_address')
            open_incident['port'] = device.get('port')

            subj, plain, html = build_recovery_email(open_incident, recovery_timestamp=now_iso, settings=settings)
            for rec in recipients:
                dispatch_notification_async(
                    incident_record_id=open_incident['id'],
                    recipient_email=rec,
                    notification_type='RECOVERY',
                    subject=subj,
                    plain_text=plain,
                    html_content=html,
                    settings=settings,
                    client=client,
                    sync=sync
                )

        return resolved_inc

    return None

def send_test_email(recipient_email, custom_settings=None, client=None):
    """
    Sends a test email immediately to verify SMTP configuration.
    Returns (success: bool, message: str).
    """
    if not recipient_email or '@' not in recipient_email:
        return False, "Please enter a valid recipient email address."

    settings = custom_settings or database.get_settings(client=client)
    host = settings.get('smtp_host') or Config.SMTP_HOST
    if not host:
        return False, "SMTP Host is not configured. Please fill in the SMTP host settings."

    subject = "[NetFault TEST] SMTP Notification Engine Verification"
    timestamp = format_local_timestamp(datetime.now(timezone.utc))

    plain = f"""NETFAULT — SMTP NOTIFICATION TEST

This is an automated test email from NetFault Automated Fault Detection System.
If you are reading this, your SMTP settings and network outbound delivery are working correctly!

Timestamp: {timestamp}
SMTP Host: {host}
Sender Address: {settings.get('alert_sender_email') or Config.ALERT_SENDER_EMAIL}
Recipient Address: {recipient_email}
"""

    html = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, sans-serif; background: #f8fafc; padding: 24px; color: #1e293b;">
<div style="max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; padding: 28px;">
  <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
    <h2 style="margin: 0; color: #0f172a; font-size: 18px;">NetFault SMTP Verification</h2>
  </div>
  <p style="font-size: 14px; line-height: 1.5; color: #334155;">
    This is a diagnostic test email verifying that your SMTP server connection, encryption, authentication, and outbound delivery are functioning correctly.
  </p>
  <div style="background: #f1f5f9; padding: 14px; border-radius: 8px; font-size: 12.5px; margin: 20px 0;">
    <div><strong>Dispatched At:</strong> {timestamp}</div>
    <div><strong>SMTP Host:</strong> {host}</div>
    <div><strong>Recipient:</strong> {recipient_email}</div>
  </div>
  <div style="font-size: 11.5px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 14px;">
    NetFault &bull; Immediate Fault Notification Engine
  </div>
</div>
</body>
</html>"""

    try:
        _send_smtp_message(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain,
            html_content=html,
            settings=settings
        )
        return True, f"Test email successfully sent to {recipient_email}!"
    except Exception as e:
        err = str(e)
        logger.error(f"Test email failed: {err}")
        return False, f"Failed to send email: {err}"
