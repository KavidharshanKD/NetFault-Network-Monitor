/**
 * NetFault – Dashboard & Monitoring Controller JS
 * Handles asynchronous ICMP/TCP checks, live polling, filters, and UI interactions.
 */

// Toast notification helper
function showToast(message, type = 'info') {
    const flashContainer = document.getElementById('flash-container');
    if (!flashContainer) return;

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show d-flex align-items-center gap-2 shadow-sm`;
    alertDiv.role = 'alert';

    let iconClass = 'fa-circle-info text-info';
    if (type === 'success') iconClass = 'fa-circle-check text-success';
    if (type === 'danger') iconClass = 'fa-triangle-exclamation text-danger';

    alertDiv.innerHTML = `
        <i class="fa-solid ${iconClass}"></i>
        <div>${message}</div>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    flashContainer.prepend(alertDiv);

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 300);
    }, 4000);
}

// Trigger manual check on all registered devices
function triggerCheckAll(button) {
    if (!button) return;
    const originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Checking All...</span>';

    fetch('/api/monitor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(`Monitoring complete! Checked ${data.results.length} device(s).`, 'success');
            // Refresh stats and table
            fetchDashboardData();
        } else {
            showToast(data.error || 'Failed to complete network monitoring.', 'danger');
        }
    })
    .catch(error => {
        showToast('Network error while checking devices: ' + error.message, 'danger');
    })
    .finally(() => {
        button.disabled = false;
        button.innerHTML = originalHtml;
    });
}

// Trigger manual check on a single device
function checkSingleDevice(deviceId, button) {
    if (!button) return;
    const originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

    fetch(`/api/devices/${deviceId}/check`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const res = data.result;
            showToast(`Checked ${res.device_name}: Status is ${res.status}`, res.status === 'UP' ? 'success' : 'danger');
            updateDeviceRow(res);
            fetchDashboardStatsOnly();
        } else {
            showToast(data.error || 'Error checking device.', 'danger');
        }
    })
    .catch(error => {
        showToast('Error checking device: ' + error.message, 'danger');
    })
    .finally(() => {
        button.disabled = false;
        button.innerHTML = originalHtml;
    });
}

// Update a specific table row in the dashboard DOM
function updateDeviceRow(result) {
    const row = document.getElementById(`device-row-${result.device_id}`);
    if (!row) return;

    row.setAttribute('data-status', result.status);

    // Update Status Badge Cell
    const statusCell = row.children[3];
    let badgeClass = 'status-pending';
    if (result.status === 'UP') badgeClass = 'status-up';
    else if (result.status === 'DOWN') badgeClass = 'status-down';
    else if (result.status === 'FAULT') badgeClass = 'status-fault';

    statusCell.innerHTML = `
        <span class="status-badge ${badgeClass}">
            <span class="status-dot"></span> ${result.status}
        </span>
    `;

    // Update Response Time Cell
    const rtCell = row.children[4];
    if (result.response_time !== null && result.response_time !== undefined) {
        rtCell.innerHTML = `<span class="fw-semibold text-light font-mono">${result.response_time} ms</span>`;
    } else {
        rtCell.innerHTML = `<span class="text-secondary">N/A</span>`;
    }

    // Update Last Checked Cell
    const lcCell = row.children[5];
    const nowStr = new Date().toLocaleString();
    lcCell.innerHTML = `<span class="last-checked-val">${nowStr}</span>`;

    // Update Fault Information Cell
    const faultCell = row.children[6];
    if (result.status === 'DOWN') {
        faultCell.innerHTML = `
            <span class="text-danger fw-semibold fs-xs d-flex align-items-center gap-1">
                <i class="fa-solid fa-circle-exclamation"></i>
                <span>${result.fault_info || 'Device unreachable'}</span>
            </span>
        `;
    } else if (result.status === 'FAULT') {
        faultCell.innerHTML = `
            <span class="text-warning fw-semibold fs-xs d-flex align-items-center gap-1">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>${result.fault_info || 'Device reachable but service/port unavailable'}</span>
            </span>
        `;
    } else {
        faultCell.innerHTML = `<span class="text-secondary fs-xs">-</span>`;
    }
}

// Fetch dashboard stats only
function fetchDashboardStatsOnly() {
    fetch('/api/dashboard')
    .then(res => res.json())
    .then(data => {
        if (data.success && data.stats) {
            updateMetrics(data.stats);
        }
    })
    .catch(() => {});
}

// Fetch complete dashboard data (stats + devices)
function fetchDashboardData() {
    fetch('/api/dashboard')
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateMetrics(data.stats);
            if (data.devices) {
                data.devices.forEach(dev => {
                    if (dev.status) {
                        updateDeviceRow({
                            device_id: dev.id,
                            device_name: dev.device_name,
                            status: dev.status,
                            response_time: dev.response_time,
                            fault_info: dev.fault_info
                        });
                    }
                });
            }
        }
    })
    .catch(() => {});
}

// Update summary metrics cards
function updateMetrics(stats) {
    const elTotal = document.getElementById('stat-total');
    const elUp = document.getElementById('stat-up');
    const elDown = document.getElementById('stat-down');
    const elFault = document.getElementById('stat-fault');

    if (elTotal) elTotal.innerText = stats.total_devices;
    if (elUp) elUp.innerText = stats.up_devices;
    if (elDown) elDown.innerText = stats.down_devices;
    if (elFault) elFault.innerText = stats.fault_devices;
}

// Filter table by status pill buttons (All, UP, DOWN, FAULT)
function filterTableByStatus(status, button) {
    if (button) {
        const btnGroup = button.parentElement;
        Array.from(btnGroup.children).forEach(b => b.classList.remove('active'));
        button.classList.add('active');
    }

    const rows = document.querySelectorAll('#devicesTableBody tr[id^="device-row-"]');
    rows.forEach(row => {
        const rowStatus = row.getAttribute('data-status');
        if (status === 'ALL' || rowStatus === status) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Search filter in device table
function filterDeviceTable() {
    const query = document.getElementById('deviceSearchInput')?.value.toLowerCase().trim() || '';
    const rows = document.querySelectorAll('#devicesTableBody tr[id^="device-row-"]');

    rows.forEach(row => {
        const searchText = row.getAttribute('data-search') || '';
        if (searchText.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Modal delete confirmation helper
function confirmDeleteDevice(deviceId, deviceName) {
    const nameEl = document.getElementById('deleteDeviceName');
    const formEl = document.getElementById('deleteForm');
    if (nameEl) nameEl.innerText = deviceName;
    if (formEl) formEl.action = `/api/devices/${deviceId}/delete`;

    const modalEl = document.getElementById('deleteConfirmModal');
    if (modalEl) {
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    }
}

// Auto-sync polling every 8 seconds if on dashboard
document.addEventListener('DOMContentLoaded', () => {
    const tableBody = document.getElementById('devicesTableBody');
    if (tableBody) {
        // Dashboard is active, start live polling
        setInterval(fetchDashboardData, 8000);
    }
});
