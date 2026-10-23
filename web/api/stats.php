<?php
require_once __DIR__ . "/../auth.php";
/*
 * api/stats.php
 * Reads stats.json written by SentinelNet (C) and sends it to the browser.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$path = '/var/sentinelnet/stats.json';

// If the file doesn't exist yet, return a zeroed-out stats object
if (!file_exists($path)) {
    echo json_encode([
        'total'      => 0,
        'tcp'        => 0,
        'udp'        => 0,
        'icmp'       => 0,
        'other'      => 0,
        'unique_ips' => 0,
        'uptime_sec' => 0,
    ]);
    exit;
}

echo file_get_contents($path);
