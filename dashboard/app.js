const API_BASE_URL = "http://localhost:8000";
const API_KEY = "dev-zero-soc-key";

const systemStatus = document.getElementById("systemStatus");
const metricsStatus = document.getElementById("metricsStatus");
const eventsTable = document.getElementById("eventsTable");
const devicesTable = document.getElementById("devicesTable");
const lastUpdated = document.getElementById("lastUpdated");
const refreshButton = document.getElementById("refreshButton");

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
        "Current Time": data.current_time,
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

    if (cleanSeverity === "high") {
        return `<span class="badge badge-high">high</span>`;
    }

    if (cleanSeverity === "medium") {
        return `<span class="badge badge-medium">medium</span>`;
    }

    return `<span class="badge badge-low">${cleanSeverity}</span>`;
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
                        <td>${formatValue(event.timestamp || event.created_at)}</td>
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
                        <td>${formatValue(device.last_seen)}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

function updateSummaryCards(system, events, devices, metrics) {
    const systemStatusCard = document.getElementById("summary-system-status");
    const devicesCard = document.getElementById("summary-devices");
    const eventsCard = document.getElementById("summary-events");
    const apiCard = document.getElementById("summary-api");

    const eventList = events.events || events || [];
    const deviceList = devices.devices || devices || [];

    systemStatusCard.textContent = "Online";
    const recentErrors = metrics.requests?.recent_error_count || 0;
    const totalRequests = metrics.requests?.total_requests_logged || 0;

    if (recentErrors > 0) {
        apiCard.textContent = `${recentErrors} errors`;
    } else {
        apiCard.textContent = `${totalRequests} requests`;
    }
    eventsCard.textContent = eventList.length;
    devicesCard.textContent = deviceList.length;

    setSummaryCardStatus(
        "system-summary-card",
        "system-summary-label",
        "status-good",
        "Online"
    );

    const highEvents = eventList.filter(event =>
        String(event.severity || "").toLowerCase() === "high"
    ).length;

    const mediumEvents = eventList.filter(event =>
        String(event.severity || "").toLowerCase() === "medium"
    ).length;

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
    eventsTable.innerHTML = "Loading events...";
    devicesTable.innerHTML = "Loading devices...";

    try {
        const [systemData, metricsData, eventsData, devicesData] = await Promise.all([
            fetchApi("/api/v1/system"),
            fetchApi("/api/v1/metrics"),
            fetchApi("/api/v1/events"),
            fetchApi("/api/v1/devices")
        ]);

        const system = systemData.data || systemData;
        const metrics = metricsData.data || metricsData;
        const events = eventsData.data || eventsData;
        const devices = devicesData.data || devicesData;

        renderSystem(system);
        renderMetrics(metrics);
        renderEvents(events);
        renderDevices(devices);

        updateSummaryCards(system, events, devices, metrics);

        lastUpdated.textContent = `Last updated: ${new Date().toLocaleString()}`;
    } catch (error) {
        systemStatus.innerHTML = `<p class="error">${error.message}</p>`;
        metricsStatus.innerHTML = `<p class="error">${error.message}</p>`;
        eventsTable.innerHTML = `<p class="error">${error.message}</p>`;
        devicesTable.innerHTML = `<p class="error">${error.message}</p>`;


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

loadDashboard();