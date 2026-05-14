const API_BASE_URL = "http://localhost:8000";
const API_KEY = "dev-zero-soc-key";

const systemStatus = document.getElementById("systemStatus");
const metricsStatus = document.getElementById("metricsStatus");
const eventSummary = document.getElementById("eventSummary");
const alertsPanel = document.getElementById("alertsPanel");
const eventsTable = document.getElementById("eventsTable");
const devicesTable = document.getElementById("devicesTable");
const lastUpdated = document.getElementById("lastUpdated");
const refreshButton = document.getElementById("refreshButton");
const apiStatusIndicator = document.getElementById("apiStatusIndicator");
const apiStatusText = document.getElementById("apiStatusText");

async function fetchApi(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
            "X-API-Key": API_KEY
        }
    });

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
    }

    return response.json();
}

async function postApi(endpoint, payload) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
    }

    return response.json();
}

function formatUptime(seconds) {
    if (seconds === null || seconds === undefined) {
        return "Unknown";
    }

    const totalSeconds = Number(seconds);

    if (Number.isNaN(totalSeconds)) {
        return "Unknown";
    }

    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);

    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    }

    return `${minutes}m`;
}

function formatTimestamp(value) {
    if (!value) {
        return "N/A";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short"
    }).format(date);
}

function formatValue(value) {
    if (value === null || value === undefined || value === "") {
        return "N/A";
    }

    return value;
}

function renderStatusRows(data) {
    return Object.entries(data)
        .map(([key, value]) => {
            if (typeof value === "object" && value !== null) {
                value = JSON.stringify(value);
            }

            return `
                <div class="status-row">
                    <span class="status-label">${key}</span>
                    <span class="status-value">${formatValue(value)}</span>
                </div>
            `;
        })
        .join("");
}

function renderSystem(data) {
    const disk = data.disk || {};

    const system = {
        "Hostname": data.hostname,
        "Platform": data.platform,
        "Platform Release": data.platform_release,
        "Platform Version": data.platform_version,
        "Machine": data.machine,
        "Python Version": data.python_version,
        "Uptime": formatUptime(data.uptime_seconds),
        "Current Time": formatTimestamp(data.current_time),
        "CPU Temp": data.cpu_temp_c ? `${data.cpu_temp_c} °C` : "N/A",
        "Disk Total": disk.total_gb ? `${disk.total_gb} GB` : "N/A",
        "Disk Used": disk.used_gb ? `${disk.used_gb} GB` : "N/A",
        "Disk Free": disk.free_gb ? `${disk.free_gb} GB` : "N/A"
    };

    systemStatus.innerHTML = renderStatusRows(system);
}

function renderMetrics(data) {
    const requests = data.requests || {};
    const events = data.events || {};
    const devices = data.devices || {};

    const metrics = {
        "Total Requests": requests.total_requests_logged,
        "Recent Errors": requests.recent_error_count,
        "Average Latency": requests.average_latency_ms
            ? `${requests.average_latency_ms} ms`
            : "N/A",
        "Total Events": events.total_events,
        "Low Events": events.severity_counts?.low,
        "Medium Events": events.severity_counts?.medium,
        "High Events": events.severity_counts?.high,
        "Recent Devices": devices.total_recent_devices
    };

    metricsStatus.innerHTML = renderStatusRows(metrics);
}

function getCountMap(summary, primaryKey, fallbackKey) {
    return summary?.[primaryKey] || summary?.[fallbackKey] || {};
}

function renderCountList(items, emptyText) {
    if (items.length === 0) {
        return `<p class="muted">${emptyText}</p>`;
    }

    return `
        <div class="count-list">
            ${items.map(([label, count]) => `
                <div class="count-row">
                    <span>${formatValue(label)}</span>
                    <strong>${formatValue(count)}</strong>
                </div>
            `).join("")}
        </div>
    `;
}

function renderEventSummary(summary) {
    const severityCounts = getCountMap(summary, "by_severity", "severity_counts");
    const eventTypeCounts = getCountMap(summary, "by_event_type", "event_type_counts");
    const tagCounts = getCountMap(summary, "by_tag", "tag_counts");
    const latestEvent = summary.latest_event;

    const sortedSeverities = ["critical", "high", "medium", "low", "unknown"]
        .filter(severity => severityCounts[severity] !== undefined)
        .map(severity => [severity, severityCounts[severity]]);

    const topTypes = Object.entries(eventTypeCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    const topTags = Object.entries(tagCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6);

    eventSummary.innerHTML = `
        <div class="summary-detail-grid">
            <div>
                <h3>Total Events</h3>
                <p class="summary-total">${formatValue(summary.total_events)}</p>
                ${latestEvent ? `
                    <p class="latest-event">
                        Latest: ${severityBadge(latestEvent.severity)}
                        ${formatValue(latestEvent.event_type)}
                        <span>${formatTimestamp(latestEvent.timestamp)}</span>
                    </p>
                ` : `<p class="muted">No latest event yet.</p>`}
            </div>
            <div>
                <h3>Severity</h3>
                ${renderCountList(sortedSeverities, "No severity counts.")}
            </div>
            <div>
                <h3>Event Types</h3>
                ${renderCountList(topTypes, "No event type counts.")}
            </div>
            <div>
                <h3>Tags</h3>
                ${renderCountList(topTags, "No tag counts.")}
            </div>
        </div>
    `;
}

function setApiStatus(statusClass, text) {
    apiStatusIndicator.classList.remove("status-good", "status-warning", "status-danger", "status-neutral");
    apiStatusIndicator.classList.add(statusClass);
    apiStatusText.textContent = text;
}

function setSummaryCardStatus(cardId, labelId, statusClass, labelText) {
    const card = document.getElementById(cardId);
    const label = document.getElementById(labelId);

    if (!card || !label) {
        return;
    }

    card.classList.remove(
        "status-good",
        "status-warning",
        "status-danger",
        "status-neutral"
    );

    card.classList.add(statusClass);
    label.textContent = labelText;
}

function severityBadge(severity) {
    const cleanSeverity = String(severity || "low").toLowerCase();

    if (cleanSeverity === "critical") {
        return `<span class="badge badge-critical">critical</span>`;
    }

    if (cleanSeverity === "high") {
        return `<span class="badge badge-high">high</span>`;
    }

    if (cleanSeverity === "medium") {
        return `<span class="badge badge-medium">medium</span>`;
    }

    return `<span class="badge badge-low">${cleanSeverity}</span>`;
}

function renderAlerts(data) {
    const alerts = Array.isArray(data) ? data : data.alerts || [];

    if (alerts.length === 0) {
        alertsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No active alerts</strong>
                <span>High-priority event signals are clear.</span>
            </div>
        `;
        return;
    }

    alertsPanel.innerHTML = `
        <div class="alert-list">
            ${alerts.map(alert => `
                <article class="alert-item alert-${String(alert.severity || "low").toLowerCase()}">
                    <div class="alert-header">
                        ${severityBadge(alert.severity)}
                        <span class="status-pill">${formatValue(alert.status || "open")}</span>
                    </div>
                    <div class="alert-body">
                        <h3>${formatValue(alert.event_type)}</h3>
                        <p>${formatValue(alert.message)}</p>
                    </div>
                    <div class="alert-meta">
                        <span>${formatTimestamp(alert.timestamp)}</span>
                        <span>${formatValue(alert.source_ip)}</span>
                    </div>
                    <div class="alert-actions">
                        ${String(alert.status || "open").toLowerCase() === "open" ? `
                            <button type="button" data-alert-id="${alert.id}" data-alert-status="acknowledged">
                                Acknowledge
                            </button>
                        ` : ""}
                        <button type="button" data-alert-id="${alert.id}" data-alert-status="resolved">
                            Resolve
                        </button>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

async function updateAlertStatus(alertId, status) {
    await postApi(`/api/v1/alerts/${encodeURIComponent(alertId)}/status`, {
        status
    });

    await loadDashboard();
}

function renderEvents(data) {
    const events = Array.isArray(data) ? data : data.events || [];

    if (events.length === 0) {
        eventsTable.innerHTML = "<p>No security events found.</p>";
        return;
    }

    eventsTable.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                ${events.map(event => `
                    <tr>
                        <td>${formatValue(event.id)}</td>
                        <td>${formatValue(event.event_type || event.type)}</td>
                        <td>${severityBadge(event.severity)}</td>
                        <td>${formatValue(event.message || event.description)}</td>
                        <td>${formatTimestamp(event.timestamp || event.created_at)}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

function renderDevices(data) {
    const devices = Array.isArray(data) ? data : data.devices || [];

    if (devices.length === 0) {
        devicesTable.innerHTML = "<p>No network devices found.</p>";
        return;
    }

    devicesTable.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
                ${devices.map(device => `
                    <tr>
                        <td>${formatValue(device.ip || device.ip_address)}</td>
                        <td>${formatValue(device.mac || device.mac_address)}</td>
                        <td>${formatValue(device.hostname)}</td>
                        <td>${formatValue(device.status || device.device_status || "unknown")}</td>
                        <td>${formatTimestamp(device.last_seen)}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

function updateSummaryCards(system, events, alerts, devices, metrics, eventSummaryData) {
    const systemStatusCard = document.getElementById("summary-system-status");
    const alertsCard = document.getElementById("summary-alerts");
    const devicesCard = document.getElementById("summary-devices");
    const eventsCard = document.getElementById("summary-events");
    const apiCard = document.getElementById("summary-api");

    const eventList = events.events || events || [];
    const alertList = alerts.alerts || alerts || [];
    const alertSummary = alerts.summary || {};
    const deviceList = devices.devices || devices || [];
    const severityCounts = getCountMap(eventSummaryData, "by_severity", "severity_counts");

    systemStatusCard.textContent = "Online";
    const recentErrors = metrics.requests?.recent_error_count || 0;
    const totalRequests = metrics.requests?.total_requests_logged || 0;

    if (recentErrors > 0) {
        apiCard.textContent = `${recentErrors} errors`;
    } else {
        apiCard.textContent = `${totalRequests} requests`;
    }
    eventsCard.textContent = eventSummaryData.total_events ?? eventList.length;
    alertsCard.textContent = alertSummary.open_alerts ?? alertList.length;
    devicesCard.textContent = deviceList.length;

    setSummaryCardStatus(
        "system-summary-card",
        "system-summary-label",
        "status-good",
        "Online"
    );

    const highEvents = (severityCounts.high || 0) + (severityCounts.critical || 0);

    const mediumEvents = severityCounts.medium || 0;

    if (highEvents > 0) {
        setSummaryCardStatus(
            "events-summary-card",
            "events-summary-label",
            "status-danger",
            "High Risk"
        );
    } else if (mediumEvents > 0 || eventList.length > 0) {
        setSummaryCardStatus(
            "events-summary-card",
            "events-summary-label",
            "status-warning",
            "Review"
        );
    } else {
        setSummaryCardStatus(
            "events-summary-card",
            "events-summary-label",
            "status-good",
            "Clear"
        );
    }

    const criticalAlerts = alertList.filter(alert =>
        String(alert.severity || "").toLowerCase() === "critical"
    ).length;

    const highAlerts = alertList.filter(alert =>
        String(alert.severity || "").toLowerCase() === "high"
    ).length;

    if (criticalAlerts > 0) {
        setSummaryCardStatus(
            "alerts-summary-card",
            "alerts-summary-label",
            "status-danger",
            "Critical"
        );
    } else if (highAlerts > 0 || alertList.length > 0) {
        setSummaryCardStatus(
            "alerts-summary-card",
            "alerts-summary-label",
            "status-warning",
            "Open"
        );
    } else {
        setSummaryCardStatus(
            "alerts-summary-card",
            "alerts-summary-label",
            "status-good",
            "Clear"
        );
    }

    const unknownDevices = deviceList.filter(device =>
        String(device.status || device.device_status || "").toLowerCase() === "unknown"
    ).length;

    if (unknownDevices > 0) {
        setSummaryCardStatus(
            "devices-summary-card",
            "devices-summary-label",
            "status-warning",
            "Unknown"
        );
    } else if (deviceList.length > 0) {
        setSummaryCardStatus(
            "devices-summary-card",
            "devices-summary-label",
            "status-good",
            "Known"
        );
    } else {
        setSummaryCardStatus(
            "devices-summary-card",
            "devices-summary-label",
            "status-neutral",
            "No Devices"
        );
    }

    if (recentErrors > 0) {
        setSummaryCardStatus(
            "api-summary-card",
            "api-summary-label",
            "status-warning",
            "Errors"
        );
    } else {
        setSummaryCardStatus(
            "api-summary-card",
            "api-summary-label",
            "status-good",
            "Healthy"
        );
    }
}

async function loadDashboard() {
    systemStatus.innerHTML = "Loading system data...";
    metricsStatus.innerHTML = "Loading metrics...";
    eventSummary.innerHTML = "Loading event summary...";
    alertsPanel.innerHTML = "Loading alerts...";
    eventsTable.innerHTML = "Loading events...";
    devicesTable.innerHTML = "Loading devices...";
    setApiStatus("status-neutral", "API checking");

    try {
        const [systemData, metricsData, eventsSummaryData, alertsData, eventsData, devicesData] = await Promise.all([
            fetchApi("/api/v1/system"),
            fetchApi("/api/v1/metrics"),
            fetchApi("/api/v1/events/summary"),
            fetchApi("/api/v1/alerts"),
            fetchApi("/api/v1/events"),
            fetchApi("/api/v1/devices")
        ]);

        const system = systemData.data || systemData;
        const metrics = metricsData.data || metricsData;
        const eventSummaryData = eventsSummaryData.data || eventsSummaryData;
        const alerts = alertsData.data || alertsData;
        const events = eventsData.data || eventsData;
        const devices = devicesData.data || devicesData;

        renderSystem(system);
        renderMetrics(metrics);
        renderEventSummary(eventSummaryData);
        renderAlerts(alerts);
        renderEvents(events);
        renderDevices(devices);

        updateSummaryCards(system, events, alerts, devices, metrics, eventSummaryData);

        lastUpdated.textContent = `Last updated: ${formatTimestamp(new Date().toISOString())}`;
        setApiStatus("status-good", "API online");
    } catch (error) {
        systemStatus.innerHTML = `<p class="error">${error.message}</p>`;
        metricsStatus.innerHTML = `<p class="error">${error.message}</p>`;
        eventSummary.innerHTML = `<p class="error">${error.message}</p>`;
        alertsPanel.innerHTML = `<p class="error">${error.message}</p>`;
        eventsTable.innerHTML = `<p class="error">${error.message}</p>`;
        devicesTable.innerHTML = `<p class="error">${error.message}</p>`;
        setApiStatus("status-danger", "API offline");


        setSummaryCardStatus(
            "system-summary-card",
            "system-summary-label",
            "status-danger",
            "Offline"
        );

        setSummaryCardStatus(
            "events-summary-card",
            "events-summary-label",
            "status-neutral",
            "Unknown"
        );

        setSummaryCardStatus(
            "alerts-summary-card",
            "alerts-summary-label",
            "status-neutral",
            "Unknown"
        );

        setSummaryCardStatus(
            "devices-summary-card",
            "devices-summary-label",
            "status-neutral",
            "Unknown"
        );

        setSummaryCardStatus(
            "api-summary-card",
            "api-summary-label",
            "status-danger",
            "Unavailable"
        );
    }
}

refreshButton.addEventListener("click", loadDashboard);

alertsPanel.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-alert-id][data-alert-status]");

    if (!button) {
        return;
    }

    button.disabled = true;
    button.textContent = "Updating...";

    try {
        await updateAlertStatus(button.dataset.alertId, button.dataset.alertStatus);
    } catch (error) {
        button.disabled = false;
        button.textContent = "Retry";
        setApiStatus("status-danger", error.message);
    }
});

loadDashboard();
