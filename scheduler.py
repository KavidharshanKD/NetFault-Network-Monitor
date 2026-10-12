"""
Background Scheduler Module for Automated Fault Detection System.
Provides thread-safe periodic network monitoring, on-demand execution,
and start/stop lifecycle management without blocking Flask.
"""

import time
import threading
import logging
from config import Config
import database
import monitoring

logger = logging.getLogger(__name__)

class MonitoringScheduler:
    """
    Singleton Background Worker that continuously monitors all registered
    network devices at a configurable interval.
    """
    def __init__(self):
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._is_running = False
        self._device_locks = {}  # device_id -> Lock to prevent duplicate concurrent checks
        self._global_device_lock = threading.Lock()
        self._last_cycle_time = None

    def _get_device_lock(self, device_id):
        with self._global_device_lock:
            if device_id not in self._device_locks:
                self._device_locks[device_id] = threading.Lock()
            return self._device_locks[device_id]

    def is_running(self):
        """Returns True if periodic monitoring worker is actively running."""
        with self._lock:
            return self._is_running

    def get_last_cycle_time(self):
        """Returns formatted timestamp of the last executed cycle."""
        return self._last_cycle_time

    def check_single_device(self, device_id):
        """
        Executes a monitoring check for a single device immediately in a thread-safe manner.
        Saves the result to SQLite and returns the result dictionary.
        """
        device = database.get_device_by_id(device_id)
        if not device:
            return None

        dev_lock = self._get_device_lock(device_id)
        # Attempt to acquire lock; if already running a check, wait briefly
        acquired = dev_lock.acquire(timeout=10.0)
        if not acquired:
            logger.warning(f"Device {device_id} is already undergoing a check; skipping duplicate execution.")
            return None

        try:
            settings = database.get_settings()
            result = monitoring.check_device_connectivity(device, settings)
            database.record_monitoring_result(
                device_id=device_id,
                reachability_status=result['reachability_status'],
                service_status=result['service_status'],
                overall_status=result['overall_status'],
                response_time_ms=result['response_time_ms'],
                fault_details=result['fault_details']
            )
            return result
        except Exception as e:
            logger.error(f"Error during check of device {device_id}: {e}")
            database.record_monitoring_result(
                device_id=device_id,
                reachability_status="ERROR",
                service_status="ERROR",
                overall_status="DOWN",
                response_time_ms=None,
                fault_details=f"Monitoring execution error: {str(e)}"
            )
            return None
        finally:
            dev_lock.release()

    def check_all_devices(self):
        """
        Iterates through all registered devices and checks each one.
        Handles failures gracefully so one failure does not halt the entire cycle.
        """
        devices = database.get_all_devices()
        results = []
        for dev in devices:
            if self._stop_event.is_set():
                break
            res = self.check_single_device(dev['id'])
            if res:
                results.append(res)
        self._last_cycle_time = time.strftime("%Y-%m-%d %H:%M:%S")
        return results

    def _worker_loop(self):
        """Main loop executed by the background thread."""
        logger.info("Background monitoring thread started.")
        while not self._stop_event.is_set():
            try:
                self.check_all_devices()
            except Exception as e:
                logger.error(f"Unexpected error in scheduler loop: {e}")

            # Fetch latest interval from database settings
            settings = database.get_settings()
            interval = max(Config.MIN_MONITOR_INTERVAL, settings.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL))

            # Sleep in 1-second chunks so we can stop immediately when requested
            for _ in range(interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        logger.info("Background monitoring thread stopped cleanly.")

    def start(self):
        """Starts the background monitoring loop if not already running."""
        with self._lock:
            if self._is_running:
                return False

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="NetworkMonitorScheduler")
            self._thread.start()
            self._is_running = True
            logger.info("Monitoring scheduler started successfully.")
            return True

    def stop(self):
        """Stops the background monitoring loop."""
        with self._lock:
            if not self._is_running:
                return False

            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                # Allow thread a brief moment to finish
                self._thread.join(timeout=2.0)
            self._is_running = False
            logger.info("Monitoring scheduler stopped.")
            return True

# Global scheduler instance
scheduler = MonitoringScheduler()
