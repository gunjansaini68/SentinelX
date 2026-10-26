/* =========================================================
   SentinelX – Dashboard JavaScript
   Calls the backend REST API and renders the results.
   No external libraries — plain fetch() and DOM APIs only.
   ========================================================= */

const API = '';   // same origin – no need for a full URL prefix

// -----------------------------------------------------------------------
// Startup: load everything when the page finishes loading
// -----------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    loadSummary();
    loadAlerts();
    loadEvents();

    // Re-run filters whenever the dropdowns change
    document.getElementById('filterSeverity').addEventListener('change', loadEvents);
    document.getElementById('filterType').addEventListener('change', loadEvents);
});

// -----------------------------------------------------------------------
// Health check – updates the status indicator in the navbar
// -----------------------------------------------------------------------
async function checkHealth() {
    const el     = document.getElementById('navStatus');
    const textEl = document.getElementById('navStatusText');
    try {
        const res = await fetch(`${API}/api/health`);
        const data = await res.json();
        if (data.status === 'UP') {
            textEl.textContent = 'Online';
            el.className = 'navbar-status online';
        } else {
            textEl.textContent = 'Degraded';
            el.className = 'navbar-status offline';
        }
    } catch {
        textEl.textContent = 'Offline';
        el.className = 'navbar-status offline';
    }
}

// -----------------------------------------------------------------------
// Summary cards
// -----------------------------------------------------------------------
async function loadSummary() {
    try {
        const res = await fetch(`${API}/api/summary`);
        if (!res.ok) throw new Error('Failed to load summary');
        const data = await res.json();

        setText('statTotal',    data.totalEvents   ?? 0);
        setText('statAlerts',   data.totalAlerts   ?? 0);
        setText('statLow',      data.bySeverity?.LOW      ?? 0);
        setText('statMedium',   data.bySeverity?.MEDIUM   ?? 0);
        setText('statHigh',     data.bySeverity?.HIGH     ?? 0);
        setText('statCritical', data.bySeverity?.CRITICAL ?? 0);
    } catch (err) {
        console.error('Summary load failed:', err);
    }
}

// -----------------------------------------------------------------------
// Alerts section
// -----------------------------------------------------------------------
async function loadAlerts() {
    const container = document.getElementById('alertsContainer');
    container.innerHTML = '<p class="state-msg">Loading alerts…</p>';

    try {
        const res = await fetch(`${API}/api/alerts`);
        if (!res.ok) throw new Error('Failed to load alerts');
        const alerts = await res.json();

        if (alerts.length === 0) {
            container.innerHTML = '<p class="no-alerts">✓ No active alerts detected.</p>';
            return;
        }

        container.innerHTML = alerts.map(alert => `
            <div class="alert-card">
                <div class="alert-header">
                    <span class="rule-name">${escHtml(alert.ruleName)}</span>
                    <span class="badge badge-${escHtml(alert.severity)}">${escHtml(alert.severity)}</span>
                    <span class="alert-meta">
                        IP: <strong>${escHtml(alert.sourceIp)}</strong> ·
                        Target: <strong>${escHtml(alert.affectedUsername)}</strong> ·
                        ${alert.eventCount} failed attempt${alert.eventCount === 1 ? '' : 's'}
                    </span>
                </div>
                <p class="explanation">${escHtml(alert.explanation)}</p>
                <p class="recommended">
                    <strong>Recommended action:</strong> ${escHtml(alert.recommendedAction)}
                </p>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<p class="state-msg error">Could not load alerts: ${escHtml(err.message)}</p>`;
    }
}

// -----------------------------------------------------------------------
// Events table (with filters)
// -----------------------------------------------------------------------
async function loadEvents() {
    const tbody = document.getElementById('eventsBody');
    const severity = document.getElementById('filterSeverity').value;
    const type     = document.getElementById('filterType').value;

    tbody.innerHTML = `<tr><td colspan="6" class="state-msg">Loading events…</td></tr>`;

    // Build query string only for non-empty filter values
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (type)     params.set('type', type);
    const qs = params.toString() ? `?${params}` : '';

    try {
        const res = await fetch(`${API}/api/events${qs}`);

        // Handle validation errors (400) from the backend
        if (res.status === 400) {
            const err = await res.json();
            tbody.innerHTML = `<tr><td colspan="6" class="state-msg error">${escHtml(err.error)}</td></tr>`;
            return;
        }

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const events = await res.json();

        if (events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="state-msg">No events match the selected filters.</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map(e => `
            <tr>
                <td>${escHtml(formatTime(e.timestamp))}</td>
                <td>${escHtml(e.username)}</td>
                <td><code>${escHtml(e.sourceIp)}</code></td>
                <td>${escHtml(e.eventType.replace(/_/g, ' '))}</td>
                <td><span class="badge badge-${escHtml(e.severity)}">${escHtml(e.severity)}</span></td>
                <td>${escHtml(e.description)}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="state-msg error">Could not load events: ${escHtml(err.message)}</td></tr>`;
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/** Sets the text content of an element by id. */
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

/**
 * Escapes HTML special characters to prevent XSS.
 * Always use this before inserting any server-supplied text into innerHTML.
 */
function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Formats an ISO timestamp into a short local time string.
 * e.g. "25 Oct, 23:04:12"
 */
function formatTime(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
        day: '2-digit', month: 'short',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}
