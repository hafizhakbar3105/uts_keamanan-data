<?php
/**
 * ============================================================================
 * [TUGAS UTS]: KONFIGURASI BASIS DATA PDO (PHP DATA OBJECTS)
 * File: config/database.php
 * Standar Keamanan:
 * - Koneksi Singleton ke database secure_admin_system.
 * - ATTR_EMULATE_PREPARES dinonaktifkan untuk kebal mutlak SQL Injection.
 * ============================================================================
 */

declare(strict_types=1);

// Cegah direct access jika konstanta pengaman didefinisikan (opsional)
// Konfigurasi Kredensial Database
define('DB_HOST', 'localhost');
define('DB_PORT', 3306);
define('DB_NAME', 'secure_admin_system');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

/**
 * Mendapatkan instance koneksi PDO tunggal (Singleton pattern).
 *
 * @return PDO
 * @throws PDOException
 */
function getDBConnection(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            DB_HOST,
            DB_PORT,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // Mencegah SQL Injection di level engine
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'",
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Log error secara internal tanpa mengekspos kredensial ke publik
            error_log('Database Connection Error: ' . $e->getMessage());
            die('
                <div style="font-family:sans-serif; padding:2rem; background:#0f172a; color:#f87171; text-align:center;">
                    <h2>Kesalahan Koneksi Basis Data</h2>
                    <p>Sistem tidak dapat terhubung ke database. Pastikan layanan MySQL di Laragon aktif.</p>
                </div>
            ');
        }
    }

    return $pdo;
}
