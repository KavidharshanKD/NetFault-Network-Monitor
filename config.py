"""
Configuration module for Automated Fault Detection System.
Defines project paths, monitoring defaults, and runtime constants.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# Ensure runtime directories exist
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'afds-college-networks-project-key-2026')
    DATABASE_PATH = os.path.join(INSTANCE_DIR, 'network_monitor.db')
    LOG_FILE_PATH = os.path.join(LOGS_DIR, 'app.log')
    
    # Default Monitoring Parameters
    DEFAULT_MONITOR_INTERVAL = 30  # seconds between periodic cycles
    DEFAULT_PING_TIMEOUT = 2       # ICMP ping timeout in seconds
    DEFAULT_TCP_TIMEOUT = 3        # TCP connection timeout in seconds
    DEFAULT_PING_COUNT = 2         # ICMP ping packet count per check
    
    # Validation Boundaries
    MIN_MONITOR_INTERVAL = 5
    MAX_MONITOR_INTERVAL = 3600
    MIN_PING_TIMEOUT = 1
    MAX_PING_TIMEOUT = 30
    MIN_TCP_TIMEOUT = 1
    MAX_TCP_TIMEOUT = 30
    MIN_PING_COUNT = 1
    MAX_PING_COUNT = 10
