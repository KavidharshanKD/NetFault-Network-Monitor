"""
Configuration module for Automated Fault Detection System.
Defines project paths, environment variable loading for Supabase PostgreSQL,
monitoring defaults, and runtime constants.
"""

import os
from datetime import datetime
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# Load environment variables from .env file
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Ensure runtime logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

class Config:
    APP_NAME = "Automated Fault Detection System"
    APP_VERSION = "2.1.0"
    SECRET_KEY = os.environ.get('SECRET_KEY', 'afds-supabase-network-monitor-key-2026-secure')
    
    # Supabase PostgreSQL Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '').strip()
    SUPABASE_SERVICE_ROLE_KEY = (
        os.environ.get('SUPABASE_SERVICE_ROLE_KEY') or 
        os.environ.get('SUPABASE_KEY', '')
    ).strip()
    
    # Default Admin Credentials (Email & Password authentication without Supabase Auth)
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@supabase.local').strip().lower()
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123').strip()

    LOG_FILE_PATH = os.path.join(LOGS_DIR, 'app.log')
    APP_START_TIME = datetime.now()
    
    # Default Monitoring Parameters
    DEFAULT_MONITOR_INTERVAL = 30  # seconds between periodic cycles
    DEFAULT_PING_TIMEOUT = 2       # ICMP ping timeout in seconds
    DEFAULT_TCP_TIMEOUT = 2        # TCP connection timeout in seconds
    DEFAULT_PING_COUNT = 1         # ICMP ping packet count per check
    DEFAULT_CONCURRENCY_LIMIT = 5  # Bounded worker threads for parallel checks
    DEFAULT_AUTO_MONITOR = 1       # 1 = enabled, 0 = disabled
    
    # Email Notification & SMTP Configuration
    SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
    try:
        SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    except (ValueError, TypeError):
        SMTP_PORT = 587
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '').strip()
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', '1').strip().lower() in ('1', 'true', 'yes')
    ALERT_SENDER_EMAIL = os.environ.get('ALERT_SENDER_EMAIL', 'netfault-alerts@local').strip()
    ALERT_RECIPIENT_EMAIL = os.environ.get('ALERT_RECIPIENT_EMAIL', '').strip()
    NETFAULT_PUBLIC_URL = os.environ.get('NETFAULT_PUBLIC_URL', 'http://127.0.0.1:5000').strip()
    APP_TIMEZONE = os.environ.get('APP_TIMEZONE', 'Asia/Kolkata').strip()

    # Fault Diagnosis & Alert Defaults
    DEFAULT_EMAIL_NOTIFICATIONS = 0  # 1 = enabled, 0 = disabled
    DEFAULT_ALERT_ON_DOWN = 1
    DEFAULT_ALERT_ON_FAULT = 1
    DEFAULT_ALERT_ON_LATENCY = 1
    DEFAULT_ALERT_ON_RECOVERY = 1
    DEFAULT_LATENCY_THRESHOLD_MS = 200
    DEFAULT_PACKET_LOSS_THRESHOLD_PCT = 50

    # Validation Boundaries
    MIN_MONITOR_INTERVAL = 5
    MAX_MONITOR_INTERVAL = 3600
    MIN_PING_TIMEOUT = 1
    MAX_PING_TIMEOUT = 30
    MIN_TCP_TIMEOUT = 1
    MAX_TCP_TIMEOUT = 30
    MIN_PING_COUNT = 1
    MAX_PING_COUNT = 10
    MIN_CONCURRENCY_LIMIT = 1
    MAX_CONCURRENCY_LIMIT = 20
    MIN_LATENCY_THRESHOLD_MS = 10
    MAX_LATENCY_THRESHOLD_MS = 10000
    MIN_PACKET_LOSS_THRESHOLD_PCT = 1
    MAX_PACKET_LOSS_THRESHOLD_PCT = 100

