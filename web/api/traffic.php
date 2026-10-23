<?php
require_once __DIR__ . "/../auth.php";
/*
 * api/traffic.php
 * Reads traffic.json written by SentinelNet (C) and sends it to the browser.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$path = '/var/sentinelnet/traffic.json';

// If the file doesn't exist yet, return an empty array
if (!file_exists($path)) {
    echo '[]';
    exit;
}

echo file_get_contents($path);
