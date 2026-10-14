"""
Background Scheduler Module for Automated Fault Detection System (AFDS).
Provides thread-safe periodic network monitoring, bounded concurrent execution,
on-demand single/batch device checks, and Supabase persistent audit recording.
"""

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import Config
import database
import monitoring
import fault_diagnosis
import notifications

logger = logging.getLogger(__name__)

class MonitoringScheduler:
    """
    Thread-safe Background Worker that periodically audits registered devices
    using bounded thread concurrency, performs intelligent fault diagnosis,
    and dispatches immediate email notifications upon incident detection or recovery.
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
        dev_key = str(device_id)
        with self._global_device_lock:
            if dev_key not in self._device_locks:
                self._device_locks[dev_key] = threading.Lock()
            return self._device_locks[dev_key]

    def is_running(self):
        """Returns True if periodic monitoring worker is running."""
        with self._lock:
            return self._is_running

    def get_last_cycle_time(self):
        """Returns formatted timestamp of the last executed cycle."""
        return self._last_cycle_time

    def check_single_device(self, device_id):
        """
        Executes a monitoring check for a single device immediately:
        1. Runs ICMP/TCP probes.
        2. Persists audit record to Supabase.
        3. Runs intelligent multi-layer fault diagnosis.
        4. Triggers immediate email notifications for new faults or recovery.
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
            try:
                database.record_monitoring_result(
                    device_id=device['id'],
                    reachability_status=result['reachability_status'],
                    service_status=result['service_status'],
                    overall_status=result['overall_status'],
                    response_time_ms=result['response_time_ms'],
                    fault_category=result.get('fault_category'),
                    fault_details=result['fault_details'],
                    packets_sent=result.get('packets_sent'),
                    packets_received=result.get('packets_received'),
                    packets_lost=result.get('packets_lost'),
                    packet_loss_pct=result.get('packet_loss_pct'),
                    packet_loss_percentage=result.get('packet_loss_percentage'),
                    min_rtt_ms=result.get('min_rtt_ms'),
                    minimum_rtt_ms=result.get('minimum_rtt_ms'),
                    max_rtt_ms=result.get('max_rtt_ms'),
                    maximum_rtt_ms=result.get('maximum_rtt_ms'),
                    avg_rtt_ms=result.get('avg_rtt_ms'),
                    average_rtt_ms=result.get('average_rtt_ms'),
                    packet_loss_status=result.get('packet_loss_status')
                )
            except Exception as db_err:
                logger.error(f"Failed to persist monitoring check to Supabase for device {device_id}: {db_err}")

            # Intelligent Fault Diagnosis & Immediate Email Notifications
            try:
                dev_hist = database.get_device_history(device['id'], limit=10)
                dev_traces = database.get_device_traceroutes(device['id'], limit=2)
                peers = database.get_all_devices(user_id=device.get('user_id'))
                
                diagnosis = fault_diagnosis.diagnose_check(
                    device=device,
                    current_check=result,
                    history=dev_hist,
                    traceroutes=dev_traces,
                    peer_devices=peers,
                    settings=settings
                )
                result['diagnosis'] = diagnosis

                # Immediately handle incident creation, persistence, and email dispatch
                incident = notifications.handle_incident_notifications(
                    device=device,
                    diagnosis=diagnosis,
                    current_check=result
                )
                if incident:
                    result['incident'] = incident

            except Exception as diag_err:
                logger.error(f"Error executing intelligent diagnosis / notification for device {device_id}: {diag_err}")

            return result
        except Exception as e:
            logger.error(f"Error during check of device {device_id}: {e}")
            try:
                database.record_monitoring_result(
                    device_id=device['id'],
                    reachability_status="ERROR",
                    service_status="ERROR",
                    overall_status="DOWN",
                    response_time_ms=None,
                    fault_category="GENERAL_FAILURE",
                    fault_details=f"Monitoring execution error: {str(e)}"
                )
            except Exception as db_err:
                logger.error(f"Failed to record failure status to Supabase: {db_err}")
            return None
        finally:
            dev_lock.release()

    def check_all_devices(self, only_enabled=False):
        """
        Executes checks across devices using a bounded thread pool.
        Catches device-specific errors so one device does not block others.
        """
        try:
            devices = database.get_all_devices()
        except Exception as e:
            logger.error(f"Error retrieving devices for scheduled check: {e}")
            return []

        if only_enabled:
            devices = [d for d in devices if bool(d.get('monitoring_enabled', True))]

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
                if bool(settings.get('auto_monitoring', 1)):
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
