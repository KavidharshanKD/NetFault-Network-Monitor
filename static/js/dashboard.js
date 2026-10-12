/**
 * Automated Fault Detection System
 * Dashboard Frontend Interactivity & Live Monitoring Controller
 */

let isSchedulerRunning = false;
let pollingIntervalId = null;

document.addEventListener('DOMContentLoaded', () => {
    // Check initial scheduler status
    fetchSchedulerStatus();

    // Start passive UI polling every 10 seconds to sync background check results
    pollingIntervalId = setInterval(passiveSyncDashboard, 10000);
});

async function fetchSchedulerStatus() {
    try {
        const resp = await fetch('/api/scheduler/status');
        if (!resp.ok) return;
        const data = await resp.json();
        isSchedulerRunning = data.running;
        updateSchedulerUI(data.running, data.last_cycle);
    } catch (e) {
        console.error("Failed to fetch scheduler status:", e);
    }
}

function updateSchedulerUI(running, lastCycle) {
    const btn = document.getElementById('toggle-scheduler-btn');
    const indicator = document.getElementById('scheduler-indicator');
    const lastCycleEl = document.getElementById('last-updated-time');

    if (btn) {
        if (running) {
            btn.textContent = '■ Stop Monitoring';
            btn.classList.add('btn-primary');
        } else {
            btn.textContent = '▶ Start Monitoring';
            btn.classList.remove('btn-primary');
        }
    }

    if (indicator) {
        indicator.innerHTML = `Background Monitoring: <strong>${running ? 'ACTIVE (Auto-cycles enabled)' : 'STOPPED'}</strong>`;
    }

    if (lastCycleEl && lastCycle) {
        lastCycleEl.textContent = `Last cycle: ${lastCycle}`;
    }
}

async function toggleScheduler() {
    const btn = document.getElementById('toggle-scheduler-btn');
    if (!btn) return;

    btn.disabled = true;
    const endpoint = isSchedulerRunning ? '/api/scheduler/stop' : '/api/scheduler/start';

    try {
        const resp = await fetch(endpoint, { method: 'POST' });
        const data = await resp.json();
        isSchedulerRunning = data.running;
        updateSchedulerUI(data.running);
        showToast(data.message || (data.running ? 'Periodic monitoring started' : 'Periodic monitoring stopped'));
    } catch (e) {
        showToast("Error updating scheduler state: " + e.message);
    } finally {
        btn.disabled = false;
    }
}

async function checkSingleDevice(deviceId) {
    const btn = document.getElementById(`check-btn-${deviceId}`);
    const originalText = btn ? btn.textContent : '';
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Testing...';
    }

    try {
        const resp = await fetch(`/api/devices/${deviceId}/check`, { method: 'POST' });
        const data = await resp.json();
        if (data.success) {
            showToast(`Check complete for device #${deviceId}: ${data.result ? data.result.overall_status : 'Done'}`);
            await refreshDashboard();
        } else {
            showToast(`Error: ${data.error || 'Failed to check device'}`);
        }
    } catch (e) {
        showToast("Network error checking device: " + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = originalText;
        }
    }
}

async function checkAllDevices() {
    const btn = document.getElementById('check-all-btn');
    if (!btn) return;

    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Checking All...';

    try {
        const resp = await fetch('/api/check-all', { method: 'POST' });
        const data = await resp.json();
        if (data.success) {
            showToast(`Checked ${data.checked_count} device(s) successfully.`);
            updateSummaryData(data.summary);
            renderDeviceRows(data.devices);
        } else {
            showToast('Failed to check all devices.');
        }
    } catch (e) {
        showToast("Network error executing check: " + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function refreshDashboard() {
    const btn = document.getElementById('refresh-dashboard-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Refreshing...';
    }

    try {
        await passiveSyncDashboard();
        showToast("Dashboard data refreshed.");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Refresh';
        }
    }
}

async function passiveSyncDashboard() {
    try {
        const [sumResp, devResp, schedResp] = await Promise.all([
            fetch('/api/summary'),
            fetch('/api/devices'),
            fetch('/api/scheduler/status')
        ]);

        if (sumResp.ok) {
            const sumData = await sumResp.json();
            updateSummaryData(sumData);
        }

        if (devResp.ok) {
            const devData = await devResp.json();
            renderDeviceRows(devData);
        }

        if (schedResp.ok) {
            const schedData = await schedResp.json();
            isSchedulerRunning = schedData.running;
            updateSchedulerUI(schedData.running, schedData.last_cycle);
        }
    } catch (e) {
        console.warn("Passive sync warning:", e);
    }
}

function updateSummaryData(sum) {
    if (!sum) return;
    const elTotal = document.getElementById('stat-total');
    const elUp = document.getElementById('stat-up');
    const elDown = document.getElementById('stat-down');
    const elFault = document.getElementById('stat-fault');
    const elAvg = document.getElementById('stat-avg');

    if (elTotal) elTotal.textContent = sum.total_devices;
    if (elUp) elUp.textContent = sum.up_count;
    if (elDown) elDown.textContent = sum.down_count;
    if (elFault) elFault.textContent = sum.fault_count;
    if (elAvg) {
        elAvg.innerHTML = sum.avg_response_time_ms !== null 
            ? `${sum.avg_response_time_ms}<span style="font-size: 16px;"> ms</span>` 
            : '—';
    }
}

function renderDeviceRows(devices) {
    const tbody = document.getElementById('devices-tbody');
    if (!tbody || !devices) return;

    if (devices.length === 0) {
        // Leave empty state handled by template
        return;
    }

    tbody.innerHTML = '';
    devices.forEach(dev => {
        const tr = document.createElement('tr');
        tr.id = `device-row-${dev.id}`;

        let statusBadgeHtml = '';
        if (dev.overall_status === 'UP') {
            statusBadgeHtml = '<span class="status-badge status-up">● UP</span>';
        } else if (dev.overall_status === 'DOWN') {
            statusBadgeHtml = '<span class="status-badge status-down">✕ DOWN</span>';
        } else if (dev.overall_status === 'FAULT') {
            statusBadgeHtml = '<span class="status-badge status-fault">▲ FAULT</span>';
        } else {
            statusBadgeHtml = '<span class="status-badge status-pending">○ UNCHECKED</span>';
        }

        const portDisplay = dev.port ? dev.port : '<span class="text-muted">—</span>';
        const respTimeDisplay = dev.response_time_ms !== null && dev.response_time_ms !== undefined
            ? `${dev.response_time_ms} ms`
            : '<span class="text-muted">—</span>';
        const lastCheckedDisplay = dev.last_checked ? dev.last_checked : 'Never';
        const faultDisplay = dev.fault_details ? dev.fault_details : '<span class="text-muted">—</span>';
        const descDisplay = dev.description ? `<div class="text-small text-muted">${escapeHtml(dev.description)}</div>` : '';

        tr.innerHTML = `
            <td>
                <strong><a href="/devices/${dev.id}" style="color: inherit; text-decoration: underline;">${escapeHtml(dev.device_name)}</a></strong>
                ${descDisplay}
            </td>
            <td class="mono">${escapeHtml(dev.ip_address)}</td>
            <td class="mono">${portDisplay}</td>
            <td>${statusBadgeHtml}</td>
            <td class="mono">${respTimeDisplay}</td>
            <td class="text-small text-muted mono">${lastCheckedDisplay}</td>
            <td class="text-small">${escapeHtml(faultDisplay)}</td>
            <td style="text-align: right;">
                <div class="action-group" style="justify-content: flex-end;">
                    <button class="btn btn-sm" onclick="checkSingleDevice(${dev.id})" id="check-btn-${dev.id}">
                        Check Now
                    </button>
                    <a href="/devices/${dev.id}" class="btn btn-sm">
                        Details
                    </a>
                    <a href="/devices/${dev.id}/edit" class="btn btn-sm">
                        Edit
                    </a>
                    <form method="POST" action="/devices/${dev.id}/delete" style="display: inline;" onsubmit="return confirm('Are you sure you want to permanently delete device ${escapeHtml(dev.device_name)} and its history?');">
                        <button type="submit" class="btn btn-sm btn-danger">
                            Delete
                        </button>
                    </form>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
