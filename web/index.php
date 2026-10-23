<?php
/*
 * index.php — SentinelNet Dashboard
 * Protected: requires login via login.php
 */
require_once 'auth.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelNet — Dashboard</title>
    <link rel="stylesheet" href="assets/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .logout-btn {
            background: none;
            border: 1px solid #334155;
            color: #94a3b8;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        .logout-btn:hover {
            border-color: #ef4444;
            color: #ef4444;
        }
        .navbar-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .navbar-user {
            font-size: 13px;
            color: #475569;
        }
    </style>
</head>
<body>

    <!-- ── Navigation bar ─────────────────────────────────────── -->
    <nav class="navbar">
        <span class="navbar-brand">⬡ SentinelNet</span>
        <div class="navbar-right">
            <span class="navbar-status">
                <span class="status-dot"></span>
                Surveillance active
            </span>
            <span class="navbar-user">
                👤 <?= htmlspecialchars($_SESSION['user'] ?? 'admin') ?>
            </span>
            <a href="logout.php" class="logout-btn">Se déconnecter</a>
        </div>
    </nav>

    <!-- ── Main content ───────────────────────────────────────── -->
    <main class="container">

        <!-- ── Stat cards ─────────────────────────────────────── -->
        <p class="section-title">Statistiques</p>
        <div class="stats-grid">

            <div class="stat-card card-total">
                <div class="stat-label">Total paquets</div>
                <div class="stat-value" id="stat-total">—</div>
            </div>

            <div class="stat-card card-tcp">
                <div class="stat-label">TCP</div>
                <div class="stat-value" id="stat-tcp">—</div>
            </div>

            <div class="stat-card card-udp">
                <div class="stat-label">UDP</div>
                <div class="stat-value" id="stat-udp">—</div>
            </div>

            <div class="stat-card card-icmp">
                <div class="stat-label">ICMP</div>
                <div class="stat-value" id="stat-icmp">—</div>
            </div>

            <div class="stat-card card-ips">
                <div class="stat-label">IPs uniques</div>
                <div class="stat-value" id="stat-unique-ips">—</div>
            </div>

            <div class="stat-card card-uptime">
                <div class="stat-label">Durée</div>
                <div class="stat-value" id="stat-uptime">—</div>
            </div>

        </div>

        <!-- ── Live traffic chart ─────────────────────────────── -->
        <p class="section-title">Trafic en temps réel</p>
        <div class="chart-wrapper">
            <canvas id="traffic-chart"></canvas>
        </div>

        <!-- ── Alerts table ───────────────────────────────────── -->
        <p class="section-title">Alertes détectées</p>
        <div class="table-wrapper">

            <div class="table-header">
                <span class="section-title" style="margin-bottom:0;">
                    Alertes
                    <span class="alert-badge" id="alert-count">0</span>
                </span>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Heure</th>
                        <th>Type</th>
                        <th>IP source</th>
                        <th>Détail</th>
                    </tr>
                </thead>
                <tbody id="alerts-tbody">
                    <tr>
                        <td colspan="4" class="no-alerts">
                            En attente de données...
                        </td>
                    </tr>
                </tbody>
            </table>

        </div>

    </main>

    <!-- ── Footer ─────────────────────────────────────────────── -->
    <footer class="footer">
        SentinelNet &mdash; Système de détection d'intrusion réseau
    </footer>

    <script src="assets/dashboard.js"></script>

</body>
</html>
