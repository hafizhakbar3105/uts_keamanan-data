<?php
/**
 * ============================================================================
 * [TUGAS UTS]: MODUL PENGAMAN SISTEM & HELPER KEAMANAN
 * File: config/security.php
 * Cakupan Proteksi:
 * 1. Auto-config OpenSSL Windows & Laragon
 * 2. Session Hardening (HttpOnly, SameSite=Strict, Anti-Hijacking)
 * 3. CSRF Protection (Token random_bytes(32) & hash_equals)
 * 4. XSS Sanitization & Output Escaping (htmlspecialchars UTF-8)
 * 5. Rate Limiting login (Maks 5x percobaan per 10 menit)
 * 6. Audit Logger & Crypto Logger otomatis
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/database.php';

// -------------------------------------------------------------
// 1. AUTO-CONFIG OPENSSL (Khusus OS Windows & Laragon)
// -------------------------------------------------------------
if (!getenv('OPENSSL_CONF') || !file_exists(getenv('OPENSSL_CONF'))) {
    $phpDir = dirname(php_ini_loaded_file() ?: 'C:/laragon/bin/php/php-8.4.27-1-nts-Win32-vs17-x64');
    $possiblePaths = [
        $phpDir . '/extras/ssl/openssl.cnf',
        'C:/laragon/usr/ssl/openssl.cnf',
        'C:/laragon/etc/ssl/openssl.cnf',
        'C:/laragon/bin/apache/httpd-2.4.54-win64-VS16/conf/openssl.cnf',
    ];
    foreach ($possiblePaths as $path) {
        if (file_exists($path)) {
            putenv('OPENSSL_CONF=' . $path);
            $_ENV['OPENSSL_CONF'] = $path;
            break;
        }
    }
}

// -------------------------------------------------------------
// 2. KEAMANAN SESSION & HEADERS
// -------------------------------------------------------------
function sendSecurityHeaders(): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy yang kompatibel dengan Bootstrap 5 CDN & Font Awesome
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self';");
}

function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        if (!headers_sent()) {
            $isHttps = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
                       (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

            session_set_cookie_params([
                'lifetime' => 0,              // Session cookie berakhir saat browser ditutup
                'path'     => '/',
                'domain'   => '',
                'secure'   => $isHttps,       // Otomatis true jika HTTPS
                'httponly' => true,           // Mencegah pembacaan cookie oleh JavaScript (Mitigasi XSS)
                'samesite' => 'Strict',       // Perlindungan dari Cross-Site Request Forgery (CSRF)
            ]);

            session_name('SECURE_ADMIN_SESS');
        }
        @session_start();

        // Validasi Session Hijacking berdasarkan User-Agent
        $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        if (!isset($_SESSION['auth_user_agent'])) {
            $_SESSION['auth_user_agent'] = hash('sha256', $currentUserAgent);
        } elseif ($_SESSION['auth_user_agent'] !== hash('sha256', $currentUserAgent)) {
            // Sesi terdeteksi digunakan oleh client berbeda (indikasi Session Hijacking)
            session_unset();
            session_destroy();
            session_start();
            $_SESSION['auth_user_agent'] = hash('sha256', $currentUserAgent);
        }

        // Inactivity timeout: 30 Menit
        $maxLifetime = 1800; // 30 menit
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $maxLifetime)) {
            session_unset();
            session_destroy();
            session_start();
        }
        $_SESSION['last_activity'] = time();
    }
}

// -------------------------------------------------------------
// 3. CSRF PROTECTION
// -------------------------------------------------------------
function generateCSRFToken(): string
{
    startSecureSession();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken(?string $token): bool
{
    startSecureSession();
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

// -------------------------------------------------------------
// 4. SANITASI & ESCAPING (XSS Prevention)
// -------------------------------------------------------------
function e(?string $string): string
{
    return htmlspecialchars($string ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function sanitizeInput(string $data): string
{
    return trim(stripslashes($data));
}

// -------------------------------------------------------------
// 5. CLIENT IP & USER AGENT HELPER
// -------------------------------------------------------------
function getClientIP(): string
{
    $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ipList = explode(',', $_SERVER[$key]);
            $ip = trim($ipList[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

function getUserAgent(): string
{
    return substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown Agent', 0, 250);
}

// -------------------------------------------------------------
// 6. RATE LIMITING & BRUTE FORCE PREVENTER
// -------------------------------------------------------------
function isRateLimited(string $ip, int $maxAttempts = 5, int $decayMinutes = 10): bool
{
    $pdo = getDBConnection();
    $since = date('Y-m-d H:i:s', time() - ($decayMinutes * 60));
    
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at >= ?'
    );
    $stmt->execute([$ip, $since]);
    $failedCount = (int)$stmt->fetchColumn();

    return $failedCount >= $maxAttempts;
}

function recordLoginAttempt(string $ip, string $username, bool $success): void
{
    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        'INSERT INTO login_attempts (ip_address, username, success, attempted_at) VALUES (?, ?, ?, NOW())'
    );
    $stmt->execute([$ip, $username, $success ? 1 : 0]);
}

// -------------------------------------------------------------
// 7. AUDIT LOGGING HELPER
// -------------------------------------------------------------
function logAudit(string $action, ?string $details = null, ?int $adminId = null, ?string $adminUsername = null): void
{
    try {
        startSecureSession();
        $pdo = getDBConnection();

        if ($adminId === null && isset($_SESSION['admin_id'])) {
            $adminId = (int)$_SESSION['admin_id'];
        }
        if ($adminUsername === null) {
            $adminUsername = $_SESSION['admin_username'] ?? 'guest';
        }

        $ip = getClientIP();
        $ua = getUserAgent();

        $stmt = $pdo->prepare(
            'INSERT INTO audit_logs (admin_id, admin_username, action, ip_address, user_agent, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())'
        );
        $stmt->execute([$adminId, $adminUsername, $action, $ip, $ua, $details]);
    } catch (Exception $e) {
        error_log('Audit Log Failure: ' . $e->getMessage());
    }
}

// -------------------------------------------------------------
// 8. CRYPTO LOGGING HELPER
// -------------------------------------------------------------
function logCrypto(string $algorithm, string $operationType, string $status, ?float $execTimeMs = null, ?int $adminId = null): void
{
    try {
        startSecureSession();
        $pdo = getDBConnection();

        if ($adminId === null && isset($_SESSION['admin_id'])) {
            $adminId = (int)$_SESSION['admin_id'];
        }

        $stmt = $pdo->prepare(
            'INSERT INTO crypto_logs (admin_id, algorithm, operation_type, status, execution_time_ms, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())'
        );
        $stmt->execute([$adminId, $algorithm, $operationType, $status, $execTimeMs]);
    } catch (Exception $e) {
        error_log('Crypto Log Failure: ' . $e->getMessage());
    }
}

// -------------------------------------------------------------
// 9. AUTH GUARDS & ACCESS CONTROL
// -------------------------------------------------------------
function isLoggedIn(): bool
{
    startSecureSession();
    return !empty($_SESSION['admin_id']) && !empty($_SESSION['admin_username']) && !empty($_SESSION['is_authenticated']);
}

function requireAuth(): void
{
    startSecureSession();
    if (!isLoggedIn()) {
        header('Location: login.php?msg=auth_required');
        exit();
    }
}

function getCurrentAdmin(): ?array
{
    if (!isLoggedIn()) {
        return null;
    }
    return [
        'id'       => $_SESSION['admin_id'],
        'username' => $_SESSION['admin_username'],
        'email'    => $_SESSION['admin_email'] ?? '',
        'role'     => $_SESSION['admin_role'] ?? 'admin',
    ];
}
