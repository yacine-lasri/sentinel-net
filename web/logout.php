<?php
/*
 * logout.php — destroys the session and redirects to login page.
 * Called when the user clicks "Se déconnecter" in the dashboard.
 */

session_start();
session_destroy();

header('Location: login.php');
exit;
