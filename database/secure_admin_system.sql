-- ==========================================================
-- SECURE ADMIN SYSTEM - DATABASE SCHEMA
-- Mata Kuliah: Keamanan Data dan Sistem Informasi (UTS)
-- ==========================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS `secure_admin_system` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `secure_admin_system`;

-- ----------------------------------------------------------
-- 1. TABEL ADMINS
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `admins`;
CREATE TABLE `admins` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `rsa_public_key` TEXT NOT NULL,
    `rsa_fingerprint` VARCHAR(128) NOT NULL,
    `role` ENUM('superadmin', 'admin') DEFAULT 'admin',
    `status` ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 2. TABEL CATEGORIES
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `categories`;
CREATE TABLE `categories` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `slug` VARCHAR(100) NOT NULL UNIQUE,
    `description` TEXT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 3. TABEL CONTENTS ([TUGAS UTS - BUTIR 2]: ZERO-PLAINTEXT STORAGE)
-- Seluruh judul dan konten tersimpan 100% dalam format Ciphertext
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `contents`;
CREATE TABLE `contents` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `category_id` INT NOT NULL,
    `encrypted_title` TEXT NOT NULL,
    `encrypted_content` LONGTEXT NOT NULL,
    `encrypted_aes_key` TEXT NOT NULL,
    `nonce` VARCHAR(64) NOT NULL,
    `auth_tag` VARCHAR(64) NOT NULL,
    `status` ENUM('draft', 'published', 'archived') DEFAULT 'published',
    `created_by` INT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT `fk_contents_category` FOREIGN KEY (`category_id`) REFERENCES `categories`(`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_contents_admin` FOREIGN KEY (`created_by`) REFERENCES `admins`(`id`) ON DELETE SET NULL,
    INDEX `idx_content_status` (`status`),
    INDEX `idx_content_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 4. TABEL AUDIT_LOGS (Riwayat Aktivitas & Jejak Keamanan)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `audit_logs`;
CREATE TABLE `audit_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `admin_id` INT NULL,
    `admin_username` VARCHAR(50) NOT NULL,
    `action` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(255) NULL,
    `details` TEXT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_audit_admin` (`admin_id`),
    INDEX `idx_audit_action` (`action`),
    INDEX `idx_audit_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 5. TABEL LOGIN_ATTEMPTS (Perlindungan Brute-force & Rate Limit)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `login_attempts`;
CREATE TABLE `login_attempts` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `username` VARCHAR(50) NOT NULL,
    `success` TINYINT(1) DEFAULT 0,
    `attempted_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_attempt_ip` (`ip_address`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 6. TABEL AUTH_CHALLENGES (RSA-PSS Anti-Replay Challenge Store)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `auth_challenges`;
CREATE TABLE `auth_challenges` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `challenge` VARCHAR(64) NOT NULL UNIQUE,
    `username` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `is_used` TINYINT(1) DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_challenge_lookup` (`challenge`, `username`, `is_used`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 7. TABEL CRYPTO_LOGS (Audit Telemetri Operasi Kriptografi)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `crypto_logs`;
CREATE TABLE `crypto_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `admin_id` INT NULL,
    `algorithm` VARCHAR(50) NOT NULL,
    `operation_type` ENUM('encrypt', 'decrypt', 'sign', 'verify') NOT NULL,
    `status` ENUM('success', 'failed') NOT NULL,
    `execution_time_ms` DECIMAL(8, 4) NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_crypto_op` (`operation_type`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==========================================================
-- SEED DATA AWAL
-- ==========================================================

-- Admin Default (Username: admin | Password: AdminSecure2026!)
INSERT INTO `admins` (`id`, `username`, `email`, `password_hash`, `rsa_public_key`, `rsa_fingerprint`, `role`, `status`) VALUES
(1, 'admin', 'admin@secureadmin.local', '$2y$12$JNvp.LIWp.LWniFgDAWEIuZc7pVO7S7Pp8kkEe/o6GUTmURzLulcq', '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFmJTvtV+PtZe997UqKT\nP2N5+SIezb4USI7y3u5Thzv8w5ZU6MlkQWOGW5cd2B3h1Si7EGMSKQv5zNRzhjVc\nlOe59auzuzBH9qXii1sT5PchmBlNZZjbyeqAR+5YoJcdKwa/kbcvBWdKD0D/vfwj\nCMgyp9ZN3HlihYDiQmb3EvXxWHOCBKp0ipDFZ8a9PycTN5fpJjC+6Gp9nVOXUEpL\nKjlFhhi48buWHZG6h+EukgAibp9FILBp0vRyV0bPx2rVWfylwTo2UH7s5f1PpzFo\nnnd7w4mjgF0nQjg+Pn/890e85ZSWLgYl5VynLDDN84FALZNV/xVqrfKTFpW7R0C7\nXwIDAQAB\n-----END PUBLIC KEY-----', 'BF:52:BD:AE:6F:CD:1F:5D:A5:33:EE:5D:15:9C:AE:B6:71:25:49:FF:7C:D9:68:54:8C:5C:79:B9:47:14:25:F6', 'superadmin', 'active');

-- Kategori Default
INSERT INTO `categories` (`id`, `name`, `slug`, `description`) VALUES
(1, 'Keamanan Siber & Pertahanan', 'keamanan-siber', 'Dokumen strategis pertahanan dan analisis ancaman siber.'),
(2, 'Kriptografi & Perlindungan Data', 'kriptografi-data', 'Standar enkripsi, manajemen kunci, dan arsitektur zero-trust.'),
(3, 'Tata Kelola & Audit Sistem', 'audit-sistem', 'Laporan kepatuhan regulasi, audit trail, dan post-incident review.'),
(4, 'Pengumuman & Kebijakan Internal', 'kebijakan-internal', 'Standar operasional prosedur (SOP) dan arahan pimpinan sistem.');

-- Log Inisialisasi Sistem
INSERT INTO `audit_logs` (`admin_id`, `admin_username`, `action`, `ip_address`, `user_agent`, `details`) VALUES
(1, 'system', 'SYSTEM_INITIALIZATION', '127.0.0.1', 'System Provisioner', 'Inisialisasi skema database secure_admin_system dan kunci kriptografi RSA 2048-bit selesai.');

SET FOREIGN_KEY_CHECKS = 1;
