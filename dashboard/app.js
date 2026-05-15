const API_BASE_URL = "http://localhost:8000";
const API_KEY = "dev-zero-soc-key";

const systemStatus = document.getElementById("systemStatus");
const metricsStatus = document.getElementById("metricsStatus");
const eventSummary = document.getElementById("eventSummary");
const alertsPanel = document.getElementById("alertsPanel");
const incidentGroupsPanel = document.getElementById("incidentGroupsPanel");
const incidentActivityPanel = document.getElementById("incidentActivityPanel");
const incidentOwnerFilter = document.getElementById("incidentOwnerFilter");
const incidentStatusFilter = document.getElementById("incidentStatusFilter");
const exportIncidentActivityButton = document.getElementById("exportIncidentActivityButton");
const resolvedAlertsPanel = document.getElementById("resolvedAlertsPanel");
const alertNotificationsPanel = document.getElementById("alertNotificationsPanel");
const alertReportsPanel = document.getElementById("alertReportsPanel");
const reportActivityPanel = document.getElementById("reportActivityPanel");
const eventsTable = document.getElementById("eventsTable");
const eventSearchInput = document.getElementById("eventSearchInput");
const severityFilter = document.getElementById("severityFilter");
const devicesTable = document.getElementById("devicesTable");
const lastUpdated = document.getElementById("lastUpdated");
const refreshButton = document.getElementById("refreshButton");
const notifyAlertsButton = document.getElementById("notifyAlertsButton");
const notifyWebhookButton = document.getElementById("notifyWebhookButton");
const alertSeverityFilters = document.getElementById("alertSeverityFilters");
const alertSearchInput = document.getElementById("alertSearchInput");
const exportAlertsButton = document.getElementById("exportAlertsButton");
const exportIncidentsButton = document.getElementById("exportIncidentsButton");
const reportStatusFilters = document.getElementById("reportStatusFilters");
const reportSearchInput = document.getElementById("reportSearchInput");
const reportActivityFilters = document.getElementById("reportActivityFilters");
const exportReportActivityButton = document.getElementById("exportReportActivityButton");
const apiStatusIndicator = document.getElementById("apiStatusIndicator");
const apiStatusText = document.getElementById("apiStatusText");
let activeAlertSeverity = "all";
let activeAlertSearch = "";
let activeIncidentKey = "";
let activeIncidentOwner = "";
let activeIncidentStatus = "all";
let activeReportStatus = "all";
let activeReportSearch = "";
let activeReportActivityAction = "all";
let severityChartInstance = null;
let eventTypeChartInstance = null;

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

async function fetchFile(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
            "X-API-Key": API_KEY
        }
    });

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
    }

    return response.blob();
}

async function fetchText(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
            "X-API-Key": API_KEY
        }
    });

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
    }

    return response.text();
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

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatHtmlValue(value) {
    return escapeHtml(formatValue(value));
}

function formatAttribute(value) {
    return escapeHtml(value ?? "");
}

function buildQueryString(params) {
    const searchParams = new URLSearchParams();

    Object.entries(params).forEach(([key, value]) => {
        if (value !== null && value !== undefined && value !== "" && value !== "all") {
            searchParams.set(key, value);
        }
    });

    const queryString = searchParams.toString();
    return queryString ? `?${queryString}` : "";
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

    renderSummaryCharts(summary);

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

function renderSummaryCharts(summary) {
    const severityCounts = getCountMap(summary, "by_severity", "severity_counts");
    const eventTypeCounts = getCountMap(summary, "by_event_type", "event_type_counts");

    renderSeverityChart(severityCounts);
    renderEventTypeChart(eventTypeCounts);
}

function renderSeverityChart(severityCounts) {
    const chartElement = document.getElementById("severityChart");

    if (!chartElement || typeof Chart === "undefined") {
        return;
    }

    chartElement.width = 300;
    chartElement.height = 210;
    chartElement.style.width = "300px";
    chartElement.style.height = "210px";

    const labels = Object.keys(severityCounts);
    const values = Object.values(severityCounts);

    if (severityChartInstance) {
        severityChartInstance.destroy();
    }

    severityChartInstance = new Chart(chartElement, {
        type: "doughnut",
        data: {
            labels,
            datasets: [
                {
                    label: "Events by Severity",
                    data: values
                }
            ]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            cutout: "55%",
            plugins: {
                legend: {
                    position: "top",
                    labels: {
                        color: "#f9fafb",
                        boxWidth: 16,
                        padding: 12
                    }
                }
            }
        }
    });
}

function renderEventTypeChart(eventTypeCounts) {
    const chartElement = document.getElementById("eventTypeChart");

    if (!chartElement || typeof Chart === "undefined") {
        return;
    }

    chartElement.width = 520;
    chartElement.height = 220;
    chartElement.style.width = "520px";
    chartElement.style.height = "220px";
    chartElement.style.maxWidth = "100%";

    const labels = Object.keys(eventTypeCounts);
    const values = Object.values(eventTypeCounts);

    if (eventTypeChartInstance) {
        eventTypeChartInstance.destroy();
    }

    eventTypeChartInstance = new Chart(chartElement, {
        type: "bar",
        data: {
            labels,
            datasets: [
                {
                    label: "Events by Type",
                    data: values
                }
            ]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: {
                        color: "#f9fafb",
                        font: {
                            size: 10
                        }
                    },
                    grid: {
                        color: "#374151"
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#f9fafb",
                        precision: 0
                    },
                    grid: {
                        color: "#374151"
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}
function filterSecurityEvents(events) {
    const searchValue = eventSearchInput
        ? eventSearchInput.value.toLowerCase().trim()
        : "";

    const selectedSeverity = severityFilter
        ? severityFilter.value
        : "all";

    return events.filter((event) => {
        const severity = String(event.severity || "").toLowerCase();

        const searchableText = [
            event.id,
            event.timestamp,
            event.created_at,
            event.source_ip,
            event.event_type,
            event.type,
            event.severity,
            event.tag,
            event.message,
            event.description
        ]
            .join(" ")
            .toLowerCase();

        const matchesSearch = searchableText.includes(searchValue);
        const matchesSeverity =
            selectedSeverity === "all" || severity === selectedSeverity;

        return matchesSearch && matchesSeverity;
    });
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

function priorityBadge(alert) {
    const label = String(alert.priority_label || "low").toLowerCase();
    const score = Number(alert.priority_score || 0);

    return `<span class="priority-pill priority-${formatAttribute(label)}">${formatHtmlValue(label)} ${score}</span>`;
}

function renderAlertCard(alert, mode = "active") {
    const status = String(alert.status || "open").toLowerCase();
    const note = String(alert.note || "").trim();
    const alertId = formatAttribute(alert.id);

    return `
        <article class="alert-item alert-${String(alert.severity || "low").toLowerCase()} alert-status-${status}">
            <div class="alert-header">
                ${severityBadge(alert.severity)}
                ${priorityBadge(alert)}
                <span class="status-pill">${formatHtmlValue(alert.status || "open")}</span>
            </div>
            <div class="alert-body">
                <h3>${formatHtmlValue(alert.event_type)}</h3>
                <p>${formatHtmlValue(alert.message)}</p>
            </div>
            <div class="alert-meta">
                <span>${formatTimestamp(alert.timestamp)}</span>
                <span>${formatHtmlValue(alert.source_ip)}</span>
            </div>
            <div class="alert-meta">
                <span>Incident ${formatHtmlValue(alert.incident_key || "unassigned")}</span>
            </div>
            ${alert.status_updated_at ? `
                <div class="alert-meta">
                    <span>Updated ${formatTimestamp(alert.status_updated_at)}</span>
                </div>
            ` : ""}
            ${note ? `
                <div class="alert-note">
                    <span>Acknowledgement note</span>
                    <p>${escapeHtml(note)}</p>
                </div>
            ` : ""}
            <div class="alert-actions">
                ${mode === "resolved" ? `
                    <button type="button" data-alert-id="${alertId}" data-alert-status="open" data-alert-note="${formatAttribute(note)}">
                        Reopen
                    </button>
                ` : `
                    ${status === "open" ? `
                        <button type="button" data-alert-id="${alertId}" data-alert-status="acknowledged" data-alert-note="${formatAttribute(note)}">
                            Acknowledge
                        </button>
                    ` : ""}
                    <button type="button" data-alert-id="${alertId}" data-alert-status="resolved" data-alert-note="${formatAttribute(note)}">
                        Resolve
                    </button>
                    <button type="button" data-alert-report-id="${alertId}">
                        Save Report
                    </button>
                `}
            </div>
        </article>
    `;
}

function renderIncidentGroups(data) {
    const allIncidents = Array.isArray(data) ? data : data.incidents || [];
    const ownerFilter = activeIncidentOwner.toLowerCase();
    const incidents = allIncidents.filter(incident => {
        const owner = String(incident.owner || "").toLowerCase();
        const status = String(incident.status || "open").toLowerCase();
        const ownerMatches = !ownerFilter || owner.includes(ownerFilter);
        const statusMatches = activeIncidentStatus === "all" || status === activeIncidentStatus;
        return ownerMatches && statusMatches;
    });

    if (incidents.length === 0) {
        incidentGroupsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No incident groups</strong>
                <span>No incidents match the current owner/status filters.</span>
            </div>
        `;
        return;
    }

    incidentGroupsPanel.innerHTML = `
        ${activeIncidentKey ? `
            <div class="incident-focus-bar">
                <span>Focused on ${formatHtmlValue(activeIncidentKey)}</span>
                <button type="button" data-incident-clear>Show All</button>
            </div>
        ` : ""}
        <div class="incident-list">
            ${incidents.map(incident => `
                <article
                    class="incident-item priority-${formatAttribute(incident.highest_priority_label)} ${activeIncidentKey === incident.id ? "active" : ""}"
                    data-incident-key="${formatAttribute(incident.id)}"
                >
                    <div class="incident-header">
                        <h4>${formatHtmlValue(incident.event_type)}</h4>
                        <span class="priority-pill priority-${formatAttribute(incident.highest_priority_label)}">
                            ${formatHtmlValue(incident.highest_priority_label)} ${formatHtmlValue(incident.highest_priority_score)}
                        </span>
                    </div>
                    <div class="alert-meta">
                        <span>${formatHtmlValue(incident.source_ip)}</span>
                        <span>${formatHtmlValue(incident.alert_count)} alerts</span>
                    </div>
                    <div class="alert-meta">
                        <span>${formatHtmlValue(incident.open_alerts)} unresolved</span>
                        <span>Latest ${formatTimestamp(incident.latest_timestamp)}</span>
                    </div>
                    <div class="incident-state">
                        <span>Status ${formatHtmlValue(incident.status || "open")}</span>
                        <span>Owner ${formatHtmlValue(incident.owner || "Unassigned")}</span>
                        <span>${incident.note ? formatHtmlValue(incident.note) : "No incident note"}</span>
                    </div>
                    <div class="incident-alert-ids">
                        ${incident.alert_ids.map(alertId => `<span>${formatHtmlValue(alertId)}</span>`).join("")}
                    </div>
                    <div class="alert-actions">
                        <button
                            type="button"
                            data-incident-state-id="${formatAttribute(incident.id)}"
                            data-incident-owner="${formatAttribute(incident.owner || "")}"
                            data-incident-note="${formatAttribute(incident.note || "")}"
                        >
                            Assign
                        </button>
                        <select
                            data-incident-status-id="${formatAttribute(incident.id)}"
                            aria-label="Incident status"
                        >
                            ${["open", "investigating", "contained", "resolved"].map(status => `
                                <option value="${status}" ${status === (incident.status || "open") ? "selected" : ""}>
                                    ${status}
                                </option>
                            `).join("")}
                        </select>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

function renderIncidentActivity(data) {
    const activity = Array.isArray(data) ? data : data.activity || [];

    if (activity.length === 0) {
        incidentActivityPanel.innerHTML = `
            <div class="empty-state">
                <strong>No incident activity</strong>
                <span>Incident owner, note, and status changes will appear here.</span>
            </div>
        `;
        return;
    }

    incidentActivityPanel.innerHTML = `
        <div class="activity-list">
            ${activity.map(item => `
                <article class="activity-item">
                    <div class="activity-header">
                        <strong>${formatHtmlValue(item.action).replace(/_/g, " ")}</strong>
                        <span>${formatTimestamp(item.created_at)}</span>
                    </div>
                    <p>${formatHtmlValue(item.details || "Incident activity recorded.")}</p>
                    <div class="alert-meta">
                        <span>${formatHtmlValue(item.incident_id)}</span>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

function renderAlerts(data) {
    const allAlerts = Array.isArray(data) ? data : data.alerts || [];
    const alerts = activeIncidentKey
        ? allAlerts.filter(alert => alert.incident_key === activeIncidentKey)
        : allAlerts;
    const filter = activeAlertSeverity === "all"
        ? "active"
        : `${activeAlertSeverity} active`;
    const searchText = activeAlertSearch
        ? ` matching "${activeAlertSearch}"`
        : "";

    if (alerts.length === 0) {
        alertsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No active alerts</strong>
                <span>No ${formatHtmlValue(filter)} alerts${formatHtmlValue(searchText)} are currently visible.</span>
            </div>
        `;
        renderIncidentGroups(data);
        return;
    }

    alertsPanel.innerHTML = `
        ${activeIncidentKey ? `
            <div class="incident-focus-bar">
                <span>Showing ${formatHtmlValue(activeIncidentKey)}</span>
                <button type="button" data-incident-clear>Show All</button>
            </div>
        ` : ""}
        <div class="alert-list">
            ${alerts.map(alert => renderAlertCard(alert)).join("")}
        </div>
    `;
    renderIncidentGroups(data);
}

function renderResolvedAlerts(data) {
    const alerts = Array.isArray(data) ? data : data.alerts || [];

    if (alerts.length === 0) {
        resolvedAlertsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No resolved alerts</strong>
                <span>Resolved alert history will appear here.</span>
            </div>
        `;
        return;
    }

    resolvedAlertsPanel.innerHTML = `
        <div class="alert-list">
            ${alerts.map(alert => renderAlertCard(alert, "resolved")).join("")}
        </div>
    `;
}

function renderAlertNotifications(data) {
    const notifications = Array.isArray(data) ? data : data.notifications || [];

    if (notifications.length === 0) {
        alertNotificationsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No alert notifications</strong>
                <span>Delivered alert notifications will appear here.</span>
            </div>
        `;
        return;
    }

    alertNotificationsPanel.innerHTML = `
        <div class="notification-list">
            ${notifications.map(notification => `
                <article class="notification-item">
                    <div class="notification-header">
                        <span class="status-pill">${formatHtmlValue(notification.status)}</span>
                        <span>${formatTimestamp(notification.created_at)}</span>
                    </div>
                    <p>${formatHtmlValue(notification.message)}</p>
                    ${notification.details ? `
                        <p class="notification-details">${formatHtmlValue(notification.details)}</p>
                    ` : ""}
                    <div class="alert-meta">
                        <span>${formatHtmlValue(notification.channel)}</span>
                        <span>${formatHtmlValue(notification.alert_id)}</span>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

function renderAlertReports(data) {
    const reports = Array.isArray(data) ? data : data.reports || [];

    if (reports.length === 0) {
        const emptyText = activeReportStatus === "archived"
            ? "Archived investigation reports will appear here."
            : activeReportStatus === "all"
            ? "Saved alert investigation reports will appear here."
            : `No ${activeReportStatus} investigation reports match this filter.`;

        alertReportsPanel.innerHTML = `
            <div class="empty-state">
                <strong>No investigation reports</strong>
                <span>${formatHtmlValue(emptyText)}</span>
            </div>
        `;
        return;
    }

    alertReportsPanel.innerHTML = `
        <div class="report-list">
            ${reports.map(report => {
                const isArchived = Boolean(report.archived_at);
                const nextStatus = report.status === "final" ? "draft" : "final";
                const statusLabel = report.status === "final" ? "Reopen Draft" : "Mark Final";

                return `
                <article class="report-item">
                    <div class="report-header">
                        <h3>${formatHtmlValue(report.title)}</h3>
                        <span class="status-pill">${formatHtmlValue(isArchived ? "archived" : report.status)}</span>
                    </div>
                    <p data-report-summary>${formatHtmlValue(report.summary)}</p>
                    <div class="alert-meta">
                        <span>${formatTimestamp(report.created_at)}</span>
                        <span>${formatHtmlValue(report.alert_id)}</span>
                    </div>
                    ${isArchived ? `
                        <div class="alert-meta">
                            <span>Archived ${formatTimestamp(report.archived_at)}</span>
                        </div>
                    ` : ""}
                    <div class="alert-actions">
                        ${isArchived ? `
                            <button type="button" data-report-restore-id="${formatAttribute(report.id)}">
                                Restore
                            </button>
                        ` : `
                            <button type="button" data-report-edit-id="${formatAttribute(report.id)}">
                                Edit
                            </button>
                            <button
                                type="button"
                                data-report-status-id="${formatAttribute(report.id)}"
                                data-report-status="${formatAttribute(nextStatus)}"
                            >
                                ${statusLabel}
                            </button>
                        `}
                        <button type="button" data-report-print-id="${formatAttribute(report.id)}">
                            Print
                        </button>
                        <button type="button" data-report-export-id="${formatAttribute(report.id)}">
                            Export
                        </button>
                        ${isArchived ? "" : `
                            <button type="button" data-report-archive-id="${formatAttribute(report.id)}">
                                Archive
                            </button>
                        `}
                    </div>
                </article>
            `;
            }).join("")}
        </div>
    `;
}

function renderReportActivity(data) {
    const activity = Array.isArray(data) ? data : data.activity || [];

    if (activity.length === 0) {
        reportActivityPanel.innerHTML = `
            <div class="empty-state">
                <strong>No report activity</strong>
                <span>Report changes will appear here.</span>
            </div>
        `;
        return;
    }

    reportActivityPanel.innerHTML = `
        <div class="activity-list">
            ${activity.map(item => `
                <article class="activity-item">
                    <div class="activity-header">
                        <strong>${formatHtmlValue(item.action).replace(/_/g, " ")}</strong>
                        <span>${formatTimestamp(item.created_at)}</span>
                    </div>
                    <p>${formatHtmlValue(item.details || "Report activity recorded.")}</p>
                    <div class="alert-meta">
                        <span>${formatHtmlValue(item.report_title)}</span>
                        <span>${formatHtmlValue(item.report_id)}</span>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

async function updateAlertStatus(alertId, status, note) {
    const payload = {
        status
    };

    if (note !== undefined) {
        payload.note = note;
    }

    await postApi(`/api/v1/alerts/${encodeURIComponent(alertId)}/status`, payload);

    await loadDashboard();
}

async function deliverAlertNotifications(channel = "dashboard") {
    await postApi("/api/v1/alerts/notifications", {
        channel,
        cooldown_seconds: 900
    });

    await loadDashboard();
}

async function exportAlertsCsv() {
    const endpoint = `/api/v1/alerts/export${buildQueryString({
        severity: activeAlertSeverity,
        q: activeAlertSearch
    })}`;
    const blob = await fetchFile(endpoint);
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    link.href = objectUrl;
    link.download = `zerosoc-alerts-${timestamp}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

async function exportIncidentsCsv() {
    const endpoint = `/api/v1/alerts/incidents/export${buildQueryString({
        severity: activeAlertSeverity,
        q: activeAlertSearch
    })}`;
    const blob = await fetchFile(endpoint);
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    link.href = objectUrl;
    link.download = `zerosoc-alert-incidents-${timestamp}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

async function exportIncidentActivity() {
    const endpoint = `/api/v1/alerts/incidents/activity/export${buildQueryString({
        incident_id: activeIncidentKey
    })}`;
    const blob = await fetchFile(endpoint);
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    link.href = objectUrl;
    link.download = `zerosoc-incident-activity-${timestamp}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

async function updateIncidentState(incidentId, owner, note) {
    await postApi(`/api/v1/alerts/incidents/${encodeURIComponent(incidentId)}/state`, {
        owner,
        note
    });

    await loadDashboard();
}

async function updateIncidentStatus(incidentId, status) {
    await postApi(`/api/v1/alerts/incidents/${encodeURIComponent(incidentId)}/state`, {
        status
    });

    await loadDashboard();
}

async function exportAlertReport(reportId) {
    const blob = await fetchFile(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/export`);
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    link.href = objectUrl;
    link.download = `zerosoc-report-${reportId}-${timestamp}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

async function exportReportActivity() {
    const endpoint = `/api/v1/alerts/reports/activity/export${buildQueryString({
        action: activeReportActivityAction
    })}`;
    const blob = await fetchFile(endpoint);
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    link.href = objectUrl;
    link.download = `zerosoc-report-activity-${timestamp}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

async function saveAlertReport(alertId, title, summary) {
    await postApi(`/api/v1/alerts/${encodeURIComponent(alertId)}/report`, {
        title,
        summary,
        status: "draft"
    });

    await loadDashboard();
}

async function updateAlertReportStatus(reportId, status) {
    await postApi(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/status`, {
        status
    });

    await loadDashboard();
}

async function updateAlertReportDetails(reportId, title, summary) {
    await postApi(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/details`, {
        title,
        summary
    });

    await loadDashboard();
}

async function archiveAlertReport(reportId) {
    await postApi(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/archive`, {});

    await loadDashboard();
}

async function restoreAlertReport(reportId) {
    await postApi(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/restore`, {});

    await loadDashboard();
}

async function openPrintableReport(reportId) {
    const html = await fetchText(`/api/v1/alerts/reports/${encodeURIComponent(reportId)}/print`);
    const blob = new Blob([html], {
        type: "text/html"
    });
    const objectUrl = URL.createObjectURL(blob);

    window.open(objectUrl, "_blank", "noopener");

    setTimeout(() => {
        URL.revokeObjectURL(objectUrl);
    }, 60000);
}

function renderEvents(data) {
    const events = Array.isArray(data) ? data : data.events || [];
    const visibleEvents = filterSecurityEvents(events);

    if (events.length === 0) {
        eventsTable.innerHTML = "<p>No security events found.</p>";
        return;
    }

    if (visibleEvents.length === 0) {
        eventsTable.innerHTML = "<p>No matching security events found.</p>";
        return;
    }

    eventsTable.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Source IP</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Tag</th>
                    <th>Message</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                ${visibleEvents.map(event => `
                    <tr>
                        <td>${formatHtmlValue(event.id)}</td>
                        <td>${formatHtmlValue(event.source_ip)}</td>
                        <td>${formatHtmlValue(event.event_type || event.type)}</td>
                        <td>${severityBadge(event.severity)}</td>
                        <td>${formatHtmlValue(event.tag)}</td>
                        <td>${formatHtmlValue(event.message || event.description)}</td>
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

function updateSummaryCards(system, events, alerts, devices, metrics, eventSummaryData, alertNotifications, alertReports) {
    const systemStatusCard = document.getElementById("summary-system-status");
    const alertsCard = document.getElementById("summary-alerts");
    const notificationsCard = document.getElementById("summary-notifications");
    const reportsCard = document.getElementById("summary-reports");
    const devicesCard = document.getElementById("summary-devices");
    const eventsCard = document.getElementById("summary-events");
    const apiCard = document.getElementById("summary-api");

    const eventList = events.events || events || [];
    const alertList = alerts.alerts || alerts || [];
    const alertSummary = alerts.summary || {};
    const notificationSummary = alertNotifications.summary || {};
    const reportSummary = alertReports.summary || {};
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
    notificationsCard.textContent = notificationSummary.failed_notifications
        ? `${notificationSummary.failed_notifications} failed`
        : `${notificationSummary.delivered_notifications || 0} sent`;
    reportsCard.textContent = `${reportSummary.active_reports || 0} active`;
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

    if ((alertSummary.highest_priority_score || 0) >= 85) {
        setSummaryCardStatus(
            "alerts-summary-card",
            "alerts-summary-label",
            "status-danger",
            `${alertSummary.incident_count || 0} incidents`
        );
    } else if (criticalAlerts > 0) {
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

    if ((notificationSummary.failed_notifications || 0) > 0) {
        setSummaryCardStatus(
            "notifications-summary-card",
            "notifications-summary-label",
            "status-danger",
            "Failed"
        );
    } else if ((notificationSummary.skipped_notifications || 0) > 0) {
        setSummaryCardStatus(
            "notifications-summary-card",
            "notifications-summary-label",
            "status-warning",
            "Skipped"
        );
    } else if ((notificationSummary.delivered_notifications || 0) > 0) {
        setSummaryCardStatus(
            "notifications-summary-card",
            "notifications-summary-label",
            "status-good",
            "Delivered"
        );
    } else {
        setSummaryCardStatus(
            "notifications-summary-card",
            "notifications-summary-label",
            "status-neutral",
            "None"
        );
    }

    if ((reportSummary.archived_reports || 0) > 0) {
        setSummaryCardStatus(
            "reports-summary-card",
            "reports-summary-label",
            "status-warning",
            `${reportSummary.archived_reports} archived`
        );
    } else if ((reportSummary.final_reports || 0) > 0) {
        setSummaryCardStatus(
            "reports-summary-card",
            "reports-summary-label",
            "status-good",
            `${reportSummary.final_reports} final`
        );
    } else if ((reportSummary.draft_reports || 0) > 0) {
        setSummaryCardStatus(
            "reports-summary-card",
            "reports-summary-label",
            "status-warning",
            `${reportSummary.draft_reports} draft`
        );
    } else {
        setSummaryCardStatus(
            "reports-summary-card",
            "reports-summary-label",
            "status-neutral",
            "None"
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
    incidentGroupsPanel.innerHTML = "Loading incident groups...";
    incidentActivityPanel.innerHTML = "Loading incident activity...";
    alertNotificationsPanel.innerHTML = "Loading alert notifications...";
    alertReportsPanel.innerHTML = "Loading investigation reports...";
    reportActivityPanel.innerHTML = "Loading report activity...";
    resolvedAlertsPanel.innerHTML = "Loading resolved alerts...";
    eventsTable.innerHTML = "Loading events...";
    devicesTable.innerHTML = "Loading devices...";
    setApiStatus("status-neutral", "API checking");

    try {
        const activeAlertsEndpoint = `/api/v1/alerts${buildQueryString({
            severity: activeAlertSeverity,
            q: activeAlertSearch
        })}`;
        const reportQuery = activeReportStatus === "archived"
            ? {
                include_archived: "only",
                q: activeReportSearch
            }
            : {
                status: activeReportStatus,
                q: activeReportSearch
            };
        const alertReportsEndpoint = `/api/v1/alerts/reports${buildQueryString(reportQuery)}`;

        const reportActivityEndpoint = `/api/v1/alerts/reports/activity${buildQueryString({
            action: activeReportActivityAction
        })}`;

        const incidentActivityEndpoint = `/api/v1/alerts/incidents/activity${buildQueryString({
            incident_id: activeIncidentKey
        })}`;

        const [systemData, metricsData, eventsSummaryData, alertsData, incidentActivityData, alertNotificationsData, alertReportsData, reportActivityData, resolvedAlertsData, eventsData, devicesData] = await Promise.all([
            fetchApi("/api/v1/system"),
            fetchApi("/api/v1/metrics"),
            fetchApi("/api/v1/events/summary"),
            fetchApi(activeAlertsEndpoint),
            fetchApi(incidentActivityEndpoint),
            fetchApi("/api/v1/alerts/notifications"),
            fetchApi(alertReportsEndpoint),
            fetchApi(reportActivityEndpoint),
            fetchApi("/api/v1/alerts?status=resolved"),
            fetchApi("/api/v1/events"),
            fetchApi("/api/v1/devices")
        ]);

        const system = systemData.data || systemData;
        const metrics = metricsData.data || metricsData;
        const eventSummaryData = eventsSummaryData.data || eventsSummaryData;
        const alerts = alertsData.data || alertsData;
        const incidentActivity = incidentActivityData.data || incidentActivityData;
        const alertNotifications = alertNotificationsData.data || alertNotificationsData;
        const alertReports = alertReportsData.data || alertReportsData;
        const reportActivity = reportActivityData.data || reportActivityData;
        const resolvedAlerts = resolvedAlertsData.data || resolvedAlertsData;
        const events = eventsData.data || eventsData;
        const devices = devicesData.data || devicesData;

        renderSystem(system);
        renderMetrics(metrics);
        renderEventSummary(eventSummaryData);
        renderAlerts(alerts);
        renderIncidentActivity(incidentActivity);
        renderAlertNotifications(alertNotifications);
        renderAlertReports(alertReports);
        renderReportActivity(reportActivity);
        renderResolvedAlerts(resolvedAlerts);
        renderEvents(events);
        renderDevices(devices);

        updateSummaryCards(
            system,
            events,
            alerts,
            devices,
            metrics,
            eventSummaryData,
            alertNotifications,
            alertReports
        );

        lastUpdated.textContent = `Last updated: ${formatTimestamp(new Date().toISOString())}`;
        setApiStatus("status-good", "API online");
    } catch (error) {
        systemStatus.innerHTML = `<p class="error">${error.message}</p>`;
        metricsStatus.innerHTML = `<p class="error">${error.message}</p>`;
        eventSummary.innerHTML = `<p class="error">${error.message}</p>`;
        alertsPanel.innerHTML = `<p class="error">${error.message}</p>`;
        alertNotificationsPanel.innerHTML = `<p class="error">${error.message}</p>`;
        incidentGroupsPanel.innerHTML = `<p class="error">${error.message}</p>`;
        incidentActivityPanel.innerHTML = `<p class="error">${error.message}</p>`;
        alertReportsPanel.innerHTML = `<p class="error">${error.message}</p>`;
        reportActivityPanel.innerHTML = `<p class="error">${error.message}</p>`;
        resolvedAlertsPanel.innerHTML = `<p class="error">${error.message}</p>`;
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
            "notifications-summary-card",
            "notifications-summary-label",
            "status-neutral",
            "Unknown"
        );

        setSummaryCardStatus(
            "reports-summary-card",
            "reports-summary-label",
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

if (eventSearchInput) {
    eventSearchInput.addEventListener("input", loadDashboard);
}

if (severityFilter) {
    severityFilter.addEventListener("change", loadDashboard);
}

alertSeverityFilters.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-alert-severity]");

    if (!button) {
        return;
    }

    activeAlertSeverity = button.dataset.alertSeverity || "all";

    alertSeverityFilters
        .querySelectorAll("[data-alert-severity]")
        .forEach(filterButton => {
            filterButton.classList.toggle(
                "active",
                filterButton.dataset.alertSeverity === activeAlertSeverity
            );
        });

    await loadDashboard();
});

alertSearchInput.addEventListener("input", async () => {
    activeAlertSearch = alertSearchInput.value.trim();
    await loadDashboard();
});

exportAlertsButton.addEventListener("click", async () => {
    exportAlertsButton.disabled = true;
    exportAlertsButton.textContent = "Exporting...";

    try {
        await exportAlertsCsv();
        setApiStatus("status-good", "CSV exported");
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        exportAlertsButton.disabled = false;
        exportAlertsButton.textContent = "Export CSV";
    }
});

exportIncidentsButton.addEventListener("click", async () => {
    exportIncidentsButton.disabled = true;
    exportIncidentsButton.textContent = "Exporting...";

    try {
        await exportIncidentsCsv();
        setApiStatus("status-good", "Incidents exported");
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        exportIncidentsButton.disabled = false;
        exportIncidentsButton.textContent = "Export Incidents";
    }
});

incidentOwnerFilter.addEventListener("input", async () => {
    activeIncidentOwner = incidentOwnerFilter.value.trim();
    await loadDashboard();
});

incidentStatusFilter.addEventListener("change", async () => {
    activeIncidentStatus = incidentStatusFilter.value;
    await loadDashboard();
});

exportIncidentActivityButton.addEventListener("click", async () => {
    exportIncidentActivityButton.disabled = true;
    exportIncidentActivityButton.textContent = "Exporting...";

    try {
        await exportIncidentActivity();
        setApiStatus("status-good", "Incident activity exported");
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        exportIncidentActivityButton.disabled = false;
        exportIncidentActivityButton.textContent = "Export Activity";
    }
});

incidentGroupsPanel.addEventListener("click", (event) => {
    const stateButton = event.target.closest("[data-incident-state-id]");

    if (stateButton) {
        event.stopPropagation();

        const owner = window.prompt(
            "Incident owner",
            stateButton.dataset.incidentOwner || ""
        );

        if (owner === null) {
            return;
        }

        const note = window.prompt(
            "Incident note",
            stateButton.dataset.incidentNote || ""
        );

        if (note === null) {
            return;
        }

        stateButton.disabled = true;
        stateButton.textContent = "Saving...";

        updateIncidentState(stateButton.dataset.incidentStateId, owner, note)
            .then(() => setApiStatus("status-good", "Incident updated"))
            .catch(error => setApiStatus("status-danger", error.message))
            .finally(() => {
                stateButton.disabled = false;
                stateButton.textContent = "Assign";
            });

        return;
    }

    if (event.target.closest("[data-incident-clear]")) {
        activeIncidentKey = "";
        loadDashboard();
        return;
    }

    const incidentItem = event.target.closest("[data-incident-key]");

    if (!incidentItem) {
        return;
    }

    activeIncidentKey = incidentItem.dataset.incidentKey;
    loadDashboard();
});

incidentGroupsPanel.addEventListener("change", (event) => {
    const statusSelect = event.target.closest("[data-incident-status-id]");

    if (!statusSelect) {
        return;
    }

    statusSelect.disabled = true;

    updateIncidentStatus(statusSelect.dataset.incidentStatusId, statusSelect.value)
        .then(() => setApiStatus("status-good", "Incident status updated"))
        .catch(error => setApiStatus("status-danger", error.message))
        .finally(() => {
            statusSelect.disabled = false;
        });
});

alertsPanel.addEventListener("click", (event) => {
    if (!event.target.closest("[data-incident-clear]")) {
        return;
    }

    activeIncidentKey = "";
    loadDashboard();
});

reportStatusFilters.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-report-filter-status]");

    if (!button) {
        return;
    }

    activeReportStatus = button.dataset.reportFilterStatus;

    reportStatusFilters
        .querySelectorAll("button")
        .forEach(filterButton => {
            filterButton.classList.toggle(
                "active",
                filterButton.dataset.reportFilterStatus === activeReportStatus
            );
        });

    await loadDashboard();
});

reportSearchInput.addEventListener("input", async () => {
    activeReportSearch = reportSearchInput.value.trim();
    await loadDashboard();
});

reportActivityFilters.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-report-activity-action]");

    if (!button) {
        return;
    }

    activeReportActivityAction = button.dataset.reportActivityAction;

    reportActivityFilters
        .querySelectorAll("button")
        .forEach(filterButton => {
            filterButton.classList.toggle(
                "active",
                filterButton.dataset.reportActivityAction === activeReportActivityAction
            );
        });

    await loadDashboard();
});

exportReportActivityButton.addEventListener("click", async () => {
    exportReportActivityButton.disabled = true;
    exportReportActivityButton.textContent = "Exporting...";

    try {
        await exportReportActivity();
        setApiStatus("status-good", "Report activity exported");
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        exportReportActivityButton.disabled = false;
        exportReportActivityButton.textContent = "Export Activity";
    }
});

alertReportsPanel.addEventListener("click", async (event) => {
    const editButton = event.target.closest("[data-report-edit-id]");

    if (editButton) {
        const reportItem = editButton.closest(".report-item");
        const currentTitle = reportItem?.querySelector("h3")?.textContent.trim() || "";
        const currentSummary = reportItem?.querySelector("[data-report-summary]")?.textContent.trim() || "";
        const title = window.prompt("Investigation report title", currentTitle);

        if (title === null) {
            return;
        }

        const summary = window.prompt("Investigation summary", currentSummary);

        if (summary === null) {
            return;
        }

        editButton.disabled = true;
        editButton.textContent = "Saving...";

        try {
            await updateAlertReportDetails(editButton.dataset.reportEditId, title, summary);
            setApiStatus("status-good", "Report updated");
        } catch (error) {
            setApiStatus("status-danger", error.message);
        } finally {
            editButton.disabled = false;
            editButton.textContent = "Edit";
        }

        return;
    }

    const exportButton = event.target.closest("[data-report-export-id]");

    if (exportButton) {
        exportButton.disabled = true;
        exportButton.textContent = "Exporting...";

        try {
            await exportAlertReport(exportButton.dataset.reportExportId);
            setApiStatus("status-good", "Report exported");
        } catch (error) {
            setApiStatus("status-danger", error.message);
        } finally {
            exportButton.disabled = false;
            exportButton.textContent = "Export";
        }

        return;
    }

    const archiveButton = event.target.closest("[data-report-archive-id]");

    if (archiveButton) {
        const confirmed = window.confirm("Archive this investigation report?");

        if (!confirmed) {
            return;
        }

        archiveButton.disabled = true;
        archiveButton.textContent = "Archiving...";

        try {
            await archiveAlertReport(archiveButton.dataset.reportArchiveId);
            setApiStatus("status-good", "Report archived");
        } catch (error) {
            setApiStatus("status-danger", error.message);
        } finally {
            archiveButton.disabled = false;
            archiveButton.textContent = "Archive";
        }

        return;
    }

    const restoreButton = event.target.closest("[data-report-restore-id]");

    if (restoreButton) {
        restoreButton.disabled = true;
        restoreButton.textContent = "Restoring...";

        try {
            await restoreAlertReport(restoreButton.dataset.reportRestoreId);
            setApiStatus("status-good", "Report restored");
        } catch (error) {
            setApiStatus("status-danger", error.message);
        } finally {
            restoreButton.disabled = false;
            restoreButton.textContent = "Restore";
        }

        return;
    }

    const statusButton = event.target.closest("[data-report-status-id]");

    if (statusButton) {
        const nextStatus = statusButton.dataset.reportStatus;
        const readyText = nextStatus === "final" ? "Mark Final" : "Reopen Draft";

        statusButton.disabled = true;
        statusButton.textContent = nextStatus === "final" ? "Finalizing..." : "Reopening...";

        try {
            await updateAlertReportStatus(statusButton.dataset.reportStatusId, nextStatus);
            setApiStatus(
                "status-good",
                nextStatus === "final" ? "Report finalized" : "Report reopened"
            );
        } catch (error) {
            setApiStatus("status-danger", error.message);
        } finally {
            statusButton.disabled = false;
            statusButton.textContent = readyText;
        }

        return;
    }

    const button = event.target.closest("[data-report-print-id]");

    if (!button) {
        return;
    }

    button.disabled = true;
    button.textContent = "Opening...";

    try {
        await openPrintableReport(button.dataset.reportPrintId);
        setApiStatus("status-good", "Report opened");
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Print";
    }
});

async function handleNotificationButtonClick(button, channel, pendingText, readyText) {
    button.disabled = true;
    button.textContent = pendingText;

    try {
        await deliverAlertNotifications(channel);
    } catch (error) {
        setApiStatus("status-danger", error.message);
    } finally {
        button.disabled = false;
        button.textContent = readyText;
    }
}

notifyAlertsButton.addEventListener("click", async () => {
    await handleNotificationButtonClick(
        notifyAlertsButton,
        "dashboard",
        "Logging...",
        "Log Active Alerts"
    );
});

notifyWebhookButton.addEventListener("click", async () => {
    await handleNotificationButtonClick(
        notifyWebhookButton,
        "webhook",
        "Sending...",
        "Send Webhook"
    );
});

async function handleAlertActionClick(event) {
    const reportButton = event.target.closest("[data-alert-report-id]");

    if (reportButton) {
        const title = window.prompt(
            "Investigation report title",
            "Alert investigation"
        );

        if (title === null) {
            return;
        }

        const summary = window.prompt(
            "Investigation summary",
            "Document findings, evidence, and next steps."
        );

        if (summary === null) {
            return;
        }

        reportButton.disabled = true;
        reportButton.textContent = "Saving...";

        try {
            await saveAlertReport(reportButton.dataset.alertReportId, title, summary);
            setApiStatus("status-good", "Report saved");
        } catch (error) {
            reportButton.disabled = false;
            reportButton.textContent = "Retry report";
            setApiStatus("status-danger", error.message);
        }

        return;
    }

    const button = event.target.closest("[data-alert-id][data-alert-status]");

    if (!button) {
        return;
    }

    const status = button.dataset.alertStatus;
    let note;

    if (status === "acknowledged") {
        note = window.prompt(
            "Add an acknowledgement note",
            button.dataset.alertNote || ""
        );

        if (note === null) {
            return;
        }
    }

    button.disabled = true;
    button.textContent = "Updating...";

    try {
        await updateAlertStatus(button.dataset.alertId, status, note);
    } catch (error) {
        button.disabled = false;
        button.textContent = "Retry";
        setApiStatus("status-danger", error.message);
    }
}

alertsPanel.addEventListener("click", handleAlertActionClick);
resolvedAlertsPanel.addEventListener("click", handleAlertActionClick);

loadDashboard();
