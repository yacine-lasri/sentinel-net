<?php
require_once __DIR__ . "/../auth.php";
/*
 * api/alerts.php
 * Reads alerts.json written by SentinelNet (C) and sends it to the browser.
 * The browser calls this every 2 seconds via JavaScript.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$path = '/var/sentinelnet/alerts.json';

// If the file doesn't exist yet (SentinelNet not started), return empty array
if (!file_exists($path)) {
    echo '[]';
    exit;
}

// Read and send the file contents as-is
echo file_get_contents($path);
