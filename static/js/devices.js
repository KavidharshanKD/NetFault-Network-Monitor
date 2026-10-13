/**
 * Automated Fault Detection System - Devices Inventory JavaScript
 */

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

async function checkDeviceFromInventory(deviceId) {
    const btn = document.getElementById(`check-btn-${deviceId}`);
    if (btn) {
        btn.disabled = true;
        btn.textContent = "...";
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
            updateInventoryRow(data.device);
            showToast(`Probe completed for ${data.device.device_name}: ${data.device.overall_status}`);
        } else {
            showToast(data.error || "Check failed", true);
        }
    } catch (e) {
        console.error(e);
        showToast("Error checking device", true);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Check";
        }
    }
}

async function checkAllDevicesFromInventory() {
    const btn = document.getElementById('btn-check-all-inventory');
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Checking...";
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
                data.devices.forEach(dev => updateInventoryRow(dev));
            }
            showToast(`Batch probe complete: ${data.checked_count} devices audited.`);
        }
    } catch (e) {
        console.error(e);
        showToast("Error checking all devices", true);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Check All";
        }
    }
}

function updateInventoryRow(device) {
    const row = document.getElementById(`device-row-${device.id}`);
    if (!row) return;

    let reachBadge = '<span class="badge badge-neutral">—</span>';
    if (device.reachability_status === 'REACHABLE') reachBadge = '<span class="badge badge-up">REACHABLE</span>';
    else if (device.reachability_status === 'UNREACHABLE') reachBadge = '<span class="badge badge-down">UNREACHABLE</span>';
    else if (device.reachability_status === 'ICMP_FILTERED') reachBadge = '<span class="badge badge-fault">FILTERED</span>';

    let servBadge = '<span class="badge badge-neutral">—</span>';
    if (device.service_status === 'OPEN') servBadge = '<span class="badge badge-up">OPEN</span>';
    else if (device.service_status === 'REFUSED') servBadge = '<span class="badge badge-fault">REFUSED</span>';
    else if (device.service_status === 'TIMEOUT') servBadge = '<span class="badge badge-fault">TIMEOUT</span>';
    else if (device.service_status === 'CLOSED') servBadge = '<span class="badge badge-down">CLOSED</span>';
    else if (device.service_status === 'NOT_CONFIGURED') servBadge = '<span class="badge badge-neutral">NONE</span>';

    let overallBadge = '<span class="badge badge-neutral">○ UNCHECKED</span>';
    if (device.overall_status === 'UP') overallBadge = '<span class="badge badge-up">● UP</span>';
    else if (device.overall_status === 'FAULT') overallBadge = '<span class="badge badge-fault">▲ FAULT</span>';
    else if (device.overall_status === 'DOWN') overallBadge = '<span class="badge badge-down">✕ DOWN</span>';

    const latencyText = device.response_time_ms !== null && device.response_time_ms !== undefined 
        ? `${device.response_time_ms} ms` 
        : '<span class="text-muted">—</span>';

    row.cells[4].innerHTML = reachBadge;
    row.cells[5].innerHTML = servBadge;
    row.cells[6].innerHTML = overallBadge;
    row.cells[7].innerHTML = latencyText;
    row.cells[9].textContent = device.last_checked || 'Just now';
}
