"""
Background Scheduler Module for Automated Fault Detection System.
Provides thread-safe periodic network monitoring, bounded concurrent execution,
on-demand single/batch device checks, and start/stop lifecycle management.
"""

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Config
import database
import monitoring

logger = logging.getLogger(__name__)

class MonitoringScheduler:
    """
    Thread-safe Background Worker that periodically audits registered devices
    using bounded thread concurrency.
    """
    def __init__(self):
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._is_running = False
        self._device_locks = {}
        self._global_device_lock = threading.Lock()
        self._last_cycle_time = None

    def _get_device_lock(self, device_id):
        with self._global_device_lock:
            if device_id not in self._device_locks:
                self._device_locks[device_id] = threading.Lock()
            return self._device_locks[device_id]

    def is_running(self):
        """Returns True if periodic monitoring worker is running."""
        with self._lock:
            return self._is_running

    def get_last_cycle_time(self):
        """Returns formatted timestamp of the last executed cycle."""
        return self._last_cycle_time

    def check_single_device(self, device_id):
        """
        Executes a monitoring check for a single device immediately.
        Persists result in SQLite and returns the result dictionary.
        """
        device = database.get_device_by_id(device_id)
        if not device:
            return None

        dev_lock = self._get_device_lock(device_id)
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
                fault_category=result.get('fault_category'),
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
                fault_category="GENERAL_FAILURE",
                fault_details=f"Monitoring execution error: {str(e)}"
            )
            return None
        finally:
            dev_lock.release()

    def check_all_devices(self, only_enabled=False):
        """
        Executes checks across devices using a bounded thread pool.
        Catches device-specific errors so one device does not block others.
        """
        devices = database.get_all_devices()
        if only_enabled:
            devices = [d for d in devices if d.get('monitoring_enabled', 1) == 1]

        if not devices:
            self._last_cycle_time = time.strftime("%Y-%m-%d %H:%M:%S")
            return []

        settings = database.get_settings()
        concurrency = settings.get('concurrency_limit', Config.DEFAULT_CONCURRENCY_LIMIT)
        concurrency = max(Config.MIN_CONCURRENCY_LIMIT, min(concurrency, Config.MAX_CONCURRENCY_LIMIT))

        results = []
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="AFDS-Worker") as executor:
            future_to_id = {executor.submit(self.check_single_device, d['id']): d['id'] for d in devices}
            for future in as_completed(future_to_id):
                if self._stop_event.is_set():
                    break
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception as exc:
                    dev_id = future_to_id[future]
                    logger.error(f"Worker generated exception for device {dev_id}: {exc}")

        self._last_cycle_time = time.strftime("%Y-%m-%d %H:%M:%S")
        return results

    def _worker_loop(self):
        """Main periodic audit loop executed by the background thread."""
        logger.info("Background monitoring thread started.")
        while not self._stop_event.is_set():
            try:
                settings = database.get_settings()
                if settings.get('auto_monitoring', 1) == 1:
                    self.check_all_devices(only_enabled=True)
            except Exception as e:
                logger.error(f"Unexpected error in scheduler loop: {e}")

            settings = database.get_settings()
            interval = max(Config.MIN_MONITOR_INTERVAL, settings.get('monitor_interval', Config.DEFAULT_MONITOR_INTERVAL))

            # Sleep in 1-second chunks for responsive cancellation
            for _ in range(interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        logger.info("Background monitoring thread stopped cleanly.")

    def start(self):
        """Starts the background monitoring loop if not active."""
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
                self._thread.join(timeout=3.0)
            self._is_running = False
            logger.info("Monitoring scheduler stopped.")
            return True

# Global scheduler instance
scheduler = MonitoringScheduler()
