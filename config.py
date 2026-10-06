"""
Configuration module for NetFault.
Contains environment settings, paths, and monitoring constants.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'netfault-college-project-secure-key-2026')
    DATABASE_PATH = os.path.join(DATA_DIR, 'netfault.db')
    
    # Monitoring Configuration
    DEFAULT_MONITOR_INTERVAL = 30  # seconds between background monitoring cycles
    PING_TIMEOUT_SECONDS = 2       # ICMP ping timeout in seconds
    TCP_TIMEOUT_SECONDS = 3        # TCP socket connect timeout in seconds
    MAX_HISTORY_RECORDS = 500      # Maximum records to keep in history view
