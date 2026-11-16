<?php
/**
 * SECURE ADMIN SYSTEM - LOGOUT HANDLER
 * File: logout.php
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

startSecureSession();

if (isLoggedIn()) {
    logAudit('LOGOUT', 'Administrator mengakhiri sesi kerja');
}

// Hapus seluruh variabel sesi
$_SESSION = [];

// Hapus cookie sesi
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

session_destroy();

header('Location: login.php?msg=logged_out');
exit();
