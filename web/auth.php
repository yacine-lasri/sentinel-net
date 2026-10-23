<?php
/*
 * auth.php — session guard
 *
 * Include this at the very top of every protected page:
 *
 *   require_once 'auth.php';
 *
 * If the user is not logged in, they get redirected to login.php
 * and the rest of the page never executes.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    header('Location: login.php');
    exit;
}
