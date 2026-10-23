/*
 * assets/dashboard.js
 *
 * Polls the three PHP API endpoints every 2 seconds and updates
 * the page without reloading it.
 *
 * ---- HOW IT WORKS ----
 * 1. When the page loads, fetchAll() runs immediately.
 * 2. Then it repeats every 2000ms (2 seconds).
 * 3. fetchAll() calls three functions in parallel:
 *      - updateStats()   → fills the stat cards at the top
 *      - updateAlerts()  → fills the alerts table
 *      - updateChart()   → updates the live traffic chart
 */

// ── Chart setup ────────────────────────────────────────────────────
// We create the chart once and update its data on each poll.
// Chart.js must be loaded in index.php before this script.

let trafficChart = null;

function initChart() {
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],         // time labels  e.g. "14:01:50"
            datasets: [
                {
                    label: 'TCP',
                    data: [],
                    borderColor: '#3B82F6',   // blue
                    backgroundColor: 'rgba(59,130,246,0.1)',
                    tension: 0.3,
                    fill: true,
                },
                {
                    label: 'UDP',
                    data: [],
                    borderColor: '#10B981',   // green
                    backgroundColor: 'rgba(16,185,129,0.1)',
                    tension: 0.3,
                    fill: true,
                },
                {
                    label: 'ICMP',
                    data: [],
                    borderColor: '#F59E0B',   // amber
                    backgroundColor: 'rgba(245,158,11,0.1)',
                    tension: 0.3,
                    fill: true,
                },
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,           // disable animation for live updates
            plugins: {
                legend: { position: 'top' },
            },
            scales: {
                x: {
                    ticks: { maxTicksLimit: 10 }   // don't crowd the x axis
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// ── Update functions ───────────────────────────────────────────────

/*
 * updateStats — fetches stats.json and fills each stat card.
 * Each card has an element with id="stat-FIELDNAME", e.g. id="stat-total".
 */
async function updateStats() {
    try {
        const res  = await fetch('api/stats.php');
        const data = await res.json();

        // Helper: set inner text of an element by id (safely)
        function set(id, value) {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        }

        set('stat-total',      data.total      ?? 0);
        set('stat-tcp',        data.tcp        ?? 0);
        set('stat-udp',        data.udp        ?? 0);
        set('stat-icmp',       data.icmp       ?? 0);
        set('stat-unique-ips', data.unique_ips ?? 0);

        // Format uptime as HH:MM:SS
        const secs    = data.uptime_sec ?? 0;
        const h       = Math.floor(secs / 3600);
        const m       = Math.floor((secs % 3600) / 60);
        const s       = secs % 60;
        const uptime  = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
        set('stat-uptime', uptime);

    } catch (err) {
        // If the API is unreachable, silently ignore — don't crash the page
        console.warn('stats fetch failed:', err);
    }
}

/*
 * updateAlerts — fetches alerts.json and rebuilds the alerts table body.
 * Newest alerts appear at the top.
 */
async function updateAlerts() {
    try {
        const res    = await fetch('api/alerts.php');
        const alerts = await res.json();

        const tbody = document.getElementById('alerts-tbody');
        if (!tbody) return;

        // Clear existing rows
        tbody.innerHTML = '';

        if (alerts.length === 0) {
            // Show a friendly empty-state row
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="4" class="no-alerts">Aucune alerte pour le moment.</td>';
            tbody.appendChild(row);
            return;
        }

        // Show newest first — reverse a copy so we don't mutate the original
        const sorted = [...alerts].reverse();

        sorted.forEach(alert => {
            const row = document.createElement('tr');

            // Pick a CSS class based on alert type so she can style each differently
            const typeClass = {
                'PORT_SCAN':   'alert-port-scan',
                'BRUTE_FORCE': 'alert-brute-force',
                'PAYLOAD_HIT': 'alert-payload-hit',
            }[alert.type] || '';

            row.className = typeClass;

            // Build a readable French label for the type
            const typeLabel = {
                'PORT_SCAN':   '🔴 Scan de ports',
                'BRUTE_FORCE': '🟠 Force brute',
                'PAYLOAD_HIT': '🔴 Payload suspect',
            }[alert.type] || alert.type;

            row.innerHTML = `
                <td>${escapeHtml(alert.time      ?? '')}</td>
                <td>${typeLabel}</td>
                <td>${escapeHtml(alert.source_ip ?? '')}</td>
                <td>${escapeHtml(alert.detail    ?? '')}</td>
            `;

            tbody.appendChild(row);
        });

        // Update the alert count badge
        const badge = document.getElementById('alert-count');
        if (badge) badge.textContent = alerts.length;

    } catch (err) {
        console.warn('alerts fetch failed:', err);
    }
}

/*
 * updateChart — fetches traffic.json and updates the Chart.js line chart.
 */
async function updateChart() {
    if (!trafficChart) return;

    try {
        const res     = await fetch('api/traffic.php');
        const traffic = await res.json();

        if (!Array.isArray(traffic) || traffic.length === 0) return;

        trafficChart.data.labels            = traffic.map(entry => entry.t   ?? '');
        trafficChart.data.datasets[0].data  = traffic.map(entry => entry.tcp  ?? 0);
        trafficChart.data.datasets[1].data  = traffic.map(entry => entry.udp  ?? 0);
        trafficChart.data.datasets[2].data  = traffic.map(entry => entry.icmp ?? 0);

        trafficChart.update();

    } catch (err) {
        console.warn('traffic fetch failed:', err);
    }
}

// ── Safety: escape HTML to prevent XSS in the alerts table ────────
function escapeHtml(str) {
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}

// ── Main polling loop ──────────────────────────────────────────────
async function fetchAll() {
    // Run all three updates at the same time (don't wait for one before starting the next)
    await Promise.allSettled([
        updateStats(),
        updateAlerts(),
        updateChart(),
    ]);
}

// ── Entry point ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initChart();        // create the chart once on page load
    fetchAll();         // first fetch immediately
    setInterval(fetchAll, 2000);    // then every 2 seconds
});
