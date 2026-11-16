<?php
/**
 * ============================================================================
 * [TUGAS UTS - BUTIR 2]: DASHBOARD UTAMA HALAMAN ADMIN
 * File: dashboard.php
 * Fungsi: Menampilkan ringkasan telemetri sistem, status keamanan 100%
 *         konten terenkripsi, fingerprint RSA admin, dan riwayat audit.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';
require_once __DIR__ . '/crypto/rsa.php';

sendSecurityHeaders();
requireAuth();

$pdo = getDBConnection();
$admin = getCurrentAdmin();

// 1. Ambil Statistik
$totalContents = (int)$pdo->query('SELECT COUNT(*) FROM contents')->fetchColumn();
$totalCategories = (int)$pdo->query('SELECT COUNT(*) FROM categories')->fetchColumn();
$totalLogs = (int)$pdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
$totalCryptoOps = (int)$pdo->query('SELECT COUNT(*) FROM crypto_logs')->fetchColumn();

// 2. Ambil Recent Activity (5 log terakhir)
$stmtRecent = $pdo->query('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5');
$recentLogs = $stmtRecent->fetchAll();

// 3. Ambil Info Public Key Admin
$stmtAdm = $pdo->prepare('SELECT rsa_fingerprint, created_at FROM admins WHERE id = ?');
$stmtAdm->execute([$admin['id']]);
$admDetails = $stmtAdm->fetch();
$fingerprint = $admDetails['rsa_fingerprint'] ?? 'N/A';
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SECURE ADMIN SYSTEM</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Cyber CSS -->
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

<div class="admin-wrapper">
    <!-- SIDEBAR -->
    <aside class="admin-sidebar">
        <div class="sidebar-brand d-flex align-items-center gap-2">
            <div class="stat-icon badge-glow-cyan p-2 rounded-3" style="width:38px; height:38px;">
                <i class="fa-solid fa-shield-halved text-primary fs-5"></i>
            </div>
            <div>
                <span class="gradient-text fw-bold tracking-wide">SECURE ADMIN</span>
                <span class="d-block text-secondary small" style="font-size: 0.65rem;">CONTROL CENTER</span>
            </div>
        </div>

        <ul class="nav-list">
            <li class="nav-item">
                <a href="dashboard.php" class="nav-link active">
                    <i class="fa-solid fa-gauge-high"></i> Dashboard
                </a>
            </li>
            <li class="nav-item">
                <a href="contents.php" class="nav-link">
                    <i class="fa-solid fa-file-shield"></i> Manajemen Konten
                </a>
            </li>
            <li class="nav-item">
                <a href="categories.php" class="nav-link">
                    <i class="fa-solid fa-folder-tree"></i> Kategori
                </a>
            </li>
            <li class="nav-item">
                <a href="encryption.php" class="nav-link">
                    <i class="fa-solid fa-flask"></i> Enkripsi & Dekripsi
                </a>
            </li>
            <li class="nav-item">
                <a href="audit.php" class="nav-link">
                    <i class="fa-solid fa-clock-rotate-left"></i> Audit Log
                </a>
            </li>
            <li class="nav-item mt-4 pt-3 border-top border-secondary border-opacity-25">
                <a href="logout.php" class="nav-link text-danger">
                    <i class="fa-solid fa-arrow-right-from-bracket text-danger"></i> Logout
                </a>
            </li>
        </ul>

        <div class="p-3 border-top border-secondary border-opacity-25 mt-auto">
            <div class="d-flex align-items-center gap-2">
                <div class="rounded-circle p-2 bg-dark border border-secondary border-opacity-50 text-center" style="width:36px; height:36px;">
                    <i class="fa-solid fa-user-shield text-info small"></i>
                </div>
                <div class="overflow-hidden">
                    <div class="small fw-semibold text-white text-truncate"><?= e($admin['username']) ?></div>
                    <div class="text-secondary small text-truncate" style="font-size: 0.72rem;"><?= e($admin['role']) ?></div>
                </div>
            </div>
        </div>
    </aside>

    <!-- MAIN CONTENT -->
    <div class="admin-main">
        <!-- TOPBAR -->
        <header class="admin-topbar">
            <div class="d-flex align-items-center gap-3">
                <button class="btn btn-cyber-outline d-lg-none p-2" type="button" onclick="document.querySelector('.admin-sidebar').classList.toggle('show')">
                    <i class="fa-solid fa-bars"></i>
                </button>
                <h5 class="fw-bold mb-0 text-white">Sistem Ikhtisar & Telemetri Keamanan</h5>
            </div>
            <div class="d-flex align-items-center gap-3">
                <span class="badge badge-glow-emerald d-none d-md-inline-block">
                    <i class="fa-solid fa-circle me-1" style="font-size: 0.5rem;"></i> ZERO-TRUST MODE
                </span>
                <a href="logout.php" class="btn btn-cyber-outline btn-sm">
                    <i class="fa-solid fa-power-off me-1"></i> Keluar
                </a>
            </div>
        </header>

        <!-- DASHBOARD BODY -->
        <main class="admin-content">
            <!-- Welcome Alert Banner -->
            <div class="glass-panel p-4 mb-4 position-relative overflow-hidden">
                <div class="row align-items-center">
                    <div class="col-lg-8">
                        <span class="badge badge-glow-cyan mb-2">Autentikasi Terverifikasi</span>
                        <h3 class="fw-bold text-white mb-2">Selamat Datang, <?= e($admin['username']) ?>!</h3>
                        <p class="text-secondary mb-0">
                            Sistem berjalan dalam mode perlindungan enkripsi hibrida. Seluruh data sensitif otomatis diamankan dengan <strong>AES-256-GCM</strong> dan dikunci oleh <strong>RSA-OAEP 2048-bit</strong> sebelum disimpan ke basis data.
                        </p>
                    </div>
                    <div class="col-lg-4 text-lg-end mt-3 mt-lg-0">
                        <a href="contents.php?action=create" class="btn btn-cyber me-2">
                            <i class="fa-solid fa-plus me-1"></i> Konten Baru
                        </a>
                        <a href="encryption.php" class="btn btn-cyber-outline">
                            <i class="fa-solid fa-flask me-1"></i> Lab Crypto
                        </a>
                    </div>
                </div>
            </div>

            <!-- STATISTIC CARDS -->
            <div class="row g-4 mb-4">
                <div class="col-xl-3 col-sm-6">
                    <div class="stat-card">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <div class="text-secondary small fw-semibold">TOTAL KONTEN</div>
                                <h2 class="fw-bold text-white mb-0 mt-1"><?= $totalContents ?></h2>
                            </div>
                            <div class="stat-icon badge-glow-cyan">
                                <i class="fa-solid fa-file-shield text-info"></i>
                            </div>
                        </div>
                        <div class="d-flex align-items-center gap-1 text-success small">
                            <i class="fa-solid fa-lock"></i>
                            <span>100% Terenkripsi (Ciphertext)</span>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-sm-6">
                    <div class="stat-card">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <div class="text-secondary small fw-semibold">KATEGORI AKTIF</div>
                                <h2 class="fw-bold text-white mb-0 mt-1"><?= $totalCategories ?></h2>
                            </div>
                            <div class="stat-icon badge-glow-emerald">
                                <i class="fa-solid fa-folder-tree text-success"></i>
                            </div>
                        </div>
                        <div class="text-secondary small">
                            <span>Struktur pengelompokan rahasia</span>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-sm-6">
                    <div class="stat-card">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <div class="text-secondary small fw-semibold">JEJAK AUDIT LOG</div>
                                <h2 class="fw-bold text-white mb-0 mt-1"><?= $totalLogs ?></h2>
                            </div>
                            <div class="stat-icon badge-glow-cyan">
                                <i class="fa-solid fa-list-check text-primary"></i>
                            </div>
                        </div>
                        <div class="text-secondary small">
                            <span>Aktivitas tercatat permanen</span>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-sm-6">
                    <div class="stat-card">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <div>
                                <div class="text-secondary small fw-semibold">OPERASI KRIPTO</div>
                                <h2 class="fw-bold text-white mb-0 mt-1"><?= $totalCryptoOps ?></h2>
                            </div>
                            <div class="stat-icon badge-glow-rose">
                                <i class="fa-solid fa-microchip text-danger"></i>
                            </div>
                        </div>
                        <div class="d-flex align-items-center gap-1 text-info small">
                            <i class="fa-solid fa-bolt"></i>
                            <span>Enkripsi & Dekripsi Aktif</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- CRYPTO HEALTH & STATUS PANELS -->
            <div class="row g-4 mb-4">
                <!-- Panel Status Kriptografi -->
                <div class="col-lg-6">
                    <div class="glass-panel p-4 h-100">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <h5 class="fw-bold mb-0 text-white">
                                <i class="fa-solid fa-shield-virus text-info me-2"></i> Status Modul Kriptografi
                            </h5>
                            <span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-50">Active</span>
                        </div>

                        <ul class="list-group list-group-flush bg-transparent">
                            <li class="list-group-item bg-transparent text-light border-secondary border-opacity-25 px-0 py-2 d-flex justify-content-between align-items-center">
                                <div>
                                    <div class="fw-semibold">AES-256-GCM (Symmetric AEAD)</div>
                                    <small class="text-secondary">Enkripsi konten & validasi 128-bit integrity tag</small>
                                </div>
                                <span class="badge badge-glow-emerald">PROTECTED</span>
                            </li>
                            <li class="list-group-item bg-transparent text-light border-secondary border-opacity-25 px-0 py-2 d-flex justify-content-between align-items-center">
                                <div>
                                    <div class="fw-semibold">RSA-OAEP 2048-bit (Key Wrapping)</div>
                                    <small class="text-secondary">Pembungkusan ephemeral AES key dengan SHA-256</small>
                                </div>
                                <span class="badge badge-glow-emerald">ARMED</span>
                            </li>
                            <li class="list-group-item bg-transparent text-light border-secondary border-opacity-25 px-0 py-2 d-flex justify-content-between align-items-center">
                                <div>
                                    <div class="fw-semibold">RSA-PSS (Challenge-Response)</div>
                                    <small class="text-secondary">Autentikasi tanda tangan digital anti-replay</small>
                                </div>
                                <span class="badge badge-glow-emerald">VERIFIED</span>
                            </li>
                            <li class="list-group-item bg-transparent text-light border-secondary border-opacity-25 px-0 py-2 d-flex justify-content-between align-items-center">
                                <div>
                                    <div class="fw-semibold">OpenSSL Engine Engine</div>
                                    <small class="text-secondary"><?= OPENSSL_VERSION_TEXT ?></small>
                                </div>
                                <span class="badge bg-dark text-info border border-info border-opacity-50">PHP 8.4</span>
                            </li>
                        </ul>
                    </div>
                </div>

                <!-- Panel Kunci & Sidik Jari RSA Admin -->
                <div class="col-lg-6">
                    <div class="glass-panel p-4 h-100">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <h5 class="fw-bold mb-0 text-white">
                                <i class="fa-solid fa-key text-success me-2"></i> Identitas Kriptografi Admin
                            </h5>
                            <span class="badge badge-glow-cyan code-font">RSA-2048</span>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">SHA-256 Public Key Fingerprint:</label>
                            <div class="p-2 rounded-3 code-font small" style="background:#f8fafc; color:#0369a1; border:1px solid #cbd5e1; word-break:break-all;">
                                <?= e($fingerprint) ?>
                            </div>
                        </div>

                        <div class="p-3 rounded-3 mb-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                            <div class="d-flex justify-content-between text-secondary small mb-1">
                                <span>Role Akses:</span>
                                <span class="text-dark fw-semibold"><?= strtoupper(e($admin['role'])) ?></span>
                            </div>
                            <div class="d-flex justify-content-between text-secondary small mb-1">
                                <span>Session ID:</span>
                                <span class="code-font text-dark"><?= substr(session_id(), 0, 16) ?>...</span>
                            </div>
                            <div class="d-flex justify-content-between text-secondary small">
                                <span>Metode Autentikasi:</span>
                                <span class="text-primary fw-semibold"><?= e($_SESSION['auth_method'] ?? 'RSA-PSS-SHA256') ?></span>
                            </div>
                        </div>

                        <div class="d-flex gap-2">
                            <a href="encryption.php" class="btn btn-cyber-outline btn-sm w-100">
                                <i class="fa-solid fa-vial me-1"></i> Buka Laboratorium Kriptografi
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- RECENT AUDIT LOG TABLE -->
            <div class="glass-panel p-4">
                <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                    <h5 class="fw-bold mb-0 text-white">
                        <i class="fa-solid fa-clock-rotate-left text-info me-2"></i> Aktivitas Keamanan Terbaru
                    </h5>
                    <a href="audit.php" class="btn btn-cyber-outline btn-sm">
                        Lihat Seluruh Log <i class="fa-solid fa-arrow-right ms-1"></i>
                    </a>
                </div>

                <div class="table-responsive">
                    <table class="table-cyber">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Administrator</th>
                                <th>Aktivitas</th>
                                <th>IP Address</th>
                                <th>Rincian</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($recentLogs)): ?>
                                <tr>
                                    <td colspan="5" class="text-center py-4 text-secondary">Belum ada riwayat aktivitas.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($recentLogs as $log): ?>
                                    <tr>
                                        <td class="code-font small text-secondary"><?= e($log['created_at']) ?></td>
                                        <td>
                                            <span class="badge bg-dark border border-secondary border-opacity-50 text-light">
                                                <i class="fa-solid fa-user me-1 text-info"></i> <?= e($log['admin_username']) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge badge-glow-cyan"><?= e($log['action']) ?></span>
                                        </td>
                                        <td class="code-font small text-info"><?= e($log['ip_address']) ?></td>
                                        <td class="small text-secondary text-truncate" style="max-width: 250px;">
                                            <?= e($log['details']) ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>
</div>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/script.js"></script>
</body>
</html>
