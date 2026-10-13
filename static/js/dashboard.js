/**
 * Automated Fault Detection System - Dashboard JavaScript Module
 * Handles asynchronous triggers, background polling, and real-time Chart.js rendering.
 */

let trendChartInstance = null;

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// ---------------------------------------------------------
// Chart.js Trend Visualizer
// ---------------------------------------------------------

async function loadTrendChart() {
    try {
        const response = await fetch('/api/chart/history');
        if (!response.ok) return;
        const data = await response.json();

        const canvas = document.getElementById('trendChart');
        const emptyMsg = document.getElementById('chart-no-data');

        if (!canvas) return;

        // Check if sufficient actual data exists
        const validValues = (data.response_times || []).filter(v => v !== null && v !== undefined);
        if (!validValues || validValues.length === 0) {
            canvas.style.display = 'none';
            if (emptyMsg) emptyMsg.style.display = 'flex';
            return;
        }

        canvas.style.display = 'block';
        if (emptyMsg) emptyMsg.style.display = 'none';

        if (trendChartInstance) {
            trendChartInstance.destroy();
        }

        const ctx = canvas.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(37, 99, 235, 0.16)');
        gradient.addColorStop(1, 'rgba(37, 99, 235, 0.00)');

        trendChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels || [],
                datasets: [{
                    label: 'Latency (ms)',
                    data: data.response_times || [],
                    borderColor: '#2563eb',
                    backgroundColor: gradient,
                    borderWidth: 2.5,
                    pointBackgroundColor: '#2563eb',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleFont: { size: 11, family: 'Inter, sans-serif' },
                        bodyFont: { size: 12, family: 'JetBrains Mono, monospace' },
                        padding: 10,
                        cornerRadius: 8,
                        callbacks: {
                            label: function(context) {
                                return ` Latency: ${context.parsed.y} ms`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, color: '#64748b' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: '#f1f5f9' },
                        ticks: { font: { size: 10, family: 'JetBrains Mono, monospace' }, color: '#64748b' }
                    }
                }
            }
        });
    } catch (e) {
        console.error("Error loading trend chart:", e);
    }
}

// ---------------------------------------------------------
// Device Checks & Status Operations
// ---------------------------------------------------------

async function checkSingleDevice(deviceId) {
    const btn = document.getElementById(`check-btn-${deviceId}`);
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Checking...";
    }

    try {
        const response = await fetch(`/api/devices/${deviceId}/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            }
        });

        const data = await response.json();
        if (data.success && data.device) {
            updateDeviceRow(data.device);
            await refreshSummaryStats();
            await loadTrendChart();
            showToast(`Probe completed for ${data.device.device_name}: ${data.device.overall_status}`);
        } else {
            showToast(data.error || "Check failed", true);
        }
    } catch (error) {
        console.error("Probe error:", error);
        showToast("Network error executing probe", true);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Check Now";
        }
    }
}

async function checkAllDevices() {
    const btn = document.getElementById('btn-check-all');
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Checking All...";
    }

    try {
        const response = await fetch('/api/check-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            }
        });

        const data = await response.json();
        if (data.success) {
            if (data.devices) {
                data.devices.forEach(dev => updateDeviceRow(dev));
            }
            if (data.summary) {
                applySummaryData(data.summary);
            }
            await loadTrendChart();
            const timeElem = document.getElementById('last-updated-time');
            if (timeElem) {
                const now = new Date().toLocaleTimeString();
                timeElem.textContent = `Last check cycle: ${now}`;
            }
            showToast(`Audit cycle finished: checked ${data.checked_count} devices.`);
        }
    } catch (error) {
        console.error("Batch check error:", error);
        showToast("Error checking all devices", true);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Check All";
        }
    }
}

async function toggleScheduler() {
    const btn = document.getElementById('btn-toggle-scheduler');
    const btnText = document.getElementById('scheduler-btn-text');

    try {
        const statusResp = await fetch('/api/scheduler/status');
        const statusData = await statusResp.json();
        const endpoint = statusData.running ? '/api/scheduler/stop' : '/api/scheduler/start';

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            }
        });

        const data = await response.json();
        if (data.success) {
            updateSchedulerUI(data.running);
            showToast(data.message);
        }
    } catch (error) {
        console.error("Scheduler toggle error:", error);
        showToast("Error updating scheduler state", true);
    }
}

function updateSchedulerUI(isRunning) {
    const btnText = document.getElementById('scheduler-btn-text');
    if (btnText) {
        btnText.textContent = isRunning ? "■ Stop Monitoring" : "▶ Start Monitoring";
    }

    const dot = document.getElementById('status-dot-worker');
    const text = document.getElementById('status-text-worker');
    if (dot && text) {
        if (isRunning) {
            dot.className = "status-dot status-dot-up";
            text.textContent = "Scheduler Active";
        } else {
            dot.className = "status-dot status-dot-down";
            text.textContent = "Scheduler Idle";
        }
    }

    const sideStatus = document.getElementById('sidebar-scheduler-status');
    if (sideStatus) {
        sideStatus.innerHTML = isRunning 
            ? '<span class="badge badge-up">ACTIVE</span>' 
            : '<span class="badge badge-neutral">STOPPED</span>';
    }
}

function updateDeviceRow(device) {
    const row = document.getElementById(`device-row-${device.id}`);
    if (!row) return;

    // Reachability Badge
    let reachBadge = '<span class="badge badge-neutral">—</span>';
    if (device.reachability_status === 'REACHABLE') {
        reachBadge = '<span class="badge badge-up">REACHABLE</span>';
    } else if (device.reachability_status === 'UNREACHABLE') {
        reachBadge = '<span class="badge badge-down">UNREACHABLE</span>';
    } else if (device.reachability_status === 'ICMP_FILTERED') {
        reachBadge = '<span class="badge badge-fault">FILTERED</span>';
    }

    // Service Badge
    let servBadge = '<span class="badge badge-neutral">—</span>';
    if (device.service_status === 'OPEN') {
        servBadge = '<span class="badge badge-up">OPEN</span>';
    } else if (device.service_status === 'REFUSED') {
        servBadge = '<span class="badge badge-fault">REFUSED</span>';
    } else if (device.service_status === 'TIMEOUT') {
        servBadge = '<span class="badge badge-fault">TIMEOUT</span>';
    } else if (device.service_status === 'CLOSED') {
        servBadge = '<span class="badge badge-down">CLOSED</span>';
    } else if (device.service_status === 'NOT_CONFIGURED') {
        servBadge = '<span class="badge badge-neutral">NONE</span>';
    }

    // Overall Status Badge
    let overallBadge = '<span class="badge badge-neutral">○ UNCHECKED</span>';
    if (device.overall_status === 'UP') {
        overallBadge = '<span class="badge badge-up">● UP</span>';
    } else if (device.overall_status === 'FAULT') {
        overallBadge = '<span class="badge badge-fault">▲ FAULT</span>';
    } else if (device.overall_status === 'DOWN') {
        overallBadge = '<span class="badge badge-down">✕ DOWN</span>';
    }

    const latencyText = device.response_time_ms !== null && device.response_time_ms !== undefined 
        ? `${device.response_time_ms} ms` 
        : '<span class="text-muted">—</span>';

    const lastChecked = device.last_checked || 'Just now';

    row.cells[3].innerHTML = reachBadge;
    row.cells[4].innerHTML = servBadge;
    row.cells[5].innerHTML = overallBadge;
    row.cells[6].innerHTML = latencyText;
    row.cells[7].textContent = lastChecked;
}

function applySummaryData(summary) {
    const elTotal = document.getElementById('stat-total');
    const elUp = document.getElementById('stat-up');
    const elDown = document.getElementById('stat-down');
    const elFault = document.getElementById('stat-fault');
    const elAvg = document.getElementById('stat-avg');

    if (elTotal) elTotal.textContent = summary.total_devices;
    if (elUp) elUp.textContent = summary.up_count;
    if (elDown) elDown.textContent = summary.down_count;
    if (elFault) elFault.textContent = summary.fault_count;
    if (elAvg) {
        elAvg.innerHTML = summary.avg_response_time_ms !== null 
            ? `${summary.avg_response_time_ms}<span style="font-size: 14px; font-weight: normal;"> ms</span>` 
            : '—';
    }
}

async function refreshSummaryStats() {
    try {
        const response = await fetch('/api/summary');
        if (response.ok) {
            const summary = await response.json();
            applySummaryData(summary);
        }
    } catch (e) {
        console.error("Error fetching summary stats:", e);
    }
}

async function refreshDashboard() {
    await refreshSummaryStats();
    try {
        const devResp = await fetch('/api/devices');
        if (devResp.ok) {
            const devices = await devResp.json();
            devices.forEach(dev => updateDeviceRow(dev));
        }
    } catch (e) {
        console.error("Error refreshing devices:", e);
    }
    await loadTrendChart();
    showToast("Dashboard metrics refreshed");
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTrendChart();
    // Periodic UI sync every 15 seconds
    setInterval(async () => {
        try {
            const statResp = await fetch('/api/scheduler/status');
            if (statResp.ok) {
                const stat = await statResp.json();
                updateSchedulerUI(stat.running);
                if (stat.last_cycle) {
                    const topUpdated = document.getElementById('top-last-updated');
                    if (topUpdated) topUpdated.textContent = stat.last_cycle;
                }
            }
        } catch (e) {}
    }, 15000);
});
