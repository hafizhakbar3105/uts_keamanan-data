<?php
/**
 * ============================================================================
 * [TUGAS UTS]: AUDIT LOG & JEJAK REKAM KEAMANAN SISTEM
 * File: audit.php
 * Fungsi: Mencatat seluruh peristiwa login, enkripsi, dekripsi, dan manipulasi
 *         data secara permanen, serta menyediakan fitur ekspor laporan CSV.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

sendSecurityHeaders();
requireAuth();

$pdo = getDBConnection();
$admin = getCurrentAdmin();

// -------------------------------------------------------------
// EKSPOR AUDIT LOG KE CSV (UNTUK LAPORAN UTS)
// -------------------------------------------------------------
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=audit_logs_' . date('Ymd_His') . '.csv');

    $output = fopen('php://output', 'w');
    fputcsv($output, ['ID', 'Admin ID', 'Username', 'Action', 'IP Address', 'User Agent', 'Details', 'Timestamp']);

    $stmtExport = $pdo->query('SELECT * FROM audit_logs ORDER BY id DESC');
    while ($row = $stmtExport->fetch(PDO::FETCH_ASSOC)) {
        fputcsv($output, [
            $row['id'],
            $row['admin_id'] ?? 'N/A',
            $row['admin_username'],
            $row['action'],
            $row['ip_address'],
            $row['user_agent'],
            $row['details'],
            $row['created_at'],
        ]);
    }
    fclose($output);
    exit();
}

// -------------------------------------------------------------
// FILTER & PAGINATION
// -------------------------------------------------------------
$search = sanitizeInput($_GET['search'] ?? '');
$filterAction = sanitizeInput($_GET['action_filter'] ?? '');
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 15;
$offset = ($page - 1) * $perPage;

$whereClauses = ['1=1'];
$params = [];

if (!empty($search)) {
    $whereClauses[] = '(admin_username LIKE ? OR ip_address LIKE ? OR details LIKE ?)';
    $searchTerm = "%{$search}%";
    $params[] = $searchTerm;
    $params[] = $searchTerm;
    $params[] = $searchTerm;
}

if (!empty($filterAction)) {
    $whereClauses[] = 'action = ?';
    $params[] = $filterAction;
}

$whereSql = implode(' AND ', $whereClauses);

// Hitung total logs
$stmtCount = $pdo->prepare("SELECT COUNT(*) FROM audit_logs WHERE {$whereSql}");
$stmtCount->execute($params);
$totalRows = (int)$stmtCount->fetchColumn();
$totalPages = max(1, (int)ceil($totalRows / $perPage));

// Ambil data logs
$sql = "SELECT * FROM audit_logs WHERE {$whereSql} ORDER BY id DESC LIMIT {$perPage} OFFSET {$offset}";
$stmtLogs = $pdo->prepare($sql);
$stmtLogs->execute($params);
$logs = $stmtLogs->fetchAll();

// Ambil daftar aksi unik untuk dropdown filter
$distinctActions = $pdo->query('SELECT DISTINCT action FROM audit_logs ORDER BY action ASC')->fetchAll(PDO::FETCH_COLUMN);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Log - SECURE ADMIN SYSTEM</title>
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
                <a href="dashboard.php" class="nav-link">
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
                <a href="audit.php" class="nav-link active">
                    <i class="fa-solid fa-clock-rotate-left"></i> Audit Log
                </a>
            </li>
            <li class="nav-item mt-4 pt-3 border-top border-secondary border-opacity-25">
                <a href="logout.php" class="nav-link text-danger">
                    <i class="fa-solid fa-arrow-right-from-bracket text-danger"></i> Logout
                </a>
            </li>
        </ul>
    </aside>

    <!-- MAIN CONTENT -->
    <div class="admin-main">
        <header class="admin-topbar">
            <div class="d-flex align-items-center gap-3">
                <button class="btn btn-cyber-outline d-lg-none p-2" type="button" onclick="document.querySelector('.admin-sidebar').classList.toggle('show')">
                    <i class="fa-solid fa-bars"></i>
                </button>
                <h5 class="fw-bold mb-0 text-white">Jejak Audit & Log Keamanan Sistem</h5>
            </div>
            <div>
                <a href="audit.php?export=csv" class="btn btn-cyber-outline btn-sm">
                    <i class="fa-solid fa-file-csv me-1"></i> Ekspor CSV
                </a>
            </div>
        </header>

        <main class="admin-content">
            <div class="glass-panel p-4 mb-4">
                <!-- Filter Bar -->
                <form method="GET" action="audit.php" class="row g-3 align-items-end mb-4">
                    <div class="col-md-5">
                        <label class="form-label">Pencarian Keyword</label>
                        <div class="input-group">
                            <span class="input-group-text bg-dark border-secondary border-opacity-50 text-secondary">
                                <i class="fa-solid fa-magnifying-glass"></i>
                            </span>
                            <input type="text" name="search" class="form-control" placeholder="Cari username, IP, atau rincian..." value="<?= e($search) ?>">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Tipe Aktivitas (Action)</label>
                        <select name="action_filter" class="form-select">
                            <option value="">Semua Aktivitas</option>
                            <?php foreach ($distinctActions as $act): ?>
                                <option value="<?= e($act) ?>" <?= ($filterAction === $act) ? 'selected' : '' ?>>
                                    <?= e($act) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <button type="submit" class="btn btn-cyber w-100">
                            <i class="fa-solid fa-filter me-1"></i> Filter
                        </button>
                    </div>
                    <div class="col-md-2">
                        <a href="audit.php" class="btn btn-outline-secondary w-100">Reset</a>
                    </div>
                </form>

                <!-- Audit Log Table -->
                <div class="table-responsive">
                    <table class="table-cyber">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Administrator</th>
                                <th>Aktivitas</th>
                                <th>IP Address</th>
                                <th>Rincian Aktivitas</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($logs)): ?>
                                <tr>
                                    <td colspan="6" class="text-center py-4 text-secondary">
                                        Tidak ada catatan audit yang cocok dengan filter.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($logs as $l): ?>
                                    <?php
                                    // Beri warna badge sesuai severity aksi
                                    $badgeClass = 'badge-glow-cyan';
                                    if (str_contains($l['action'], 'FAILED') || str_contains($l['action'], 'PREVENTED') || str_contains($l['action'], 'DELETE')) {
                                        $badgeClass = 'badge-glow-rose';
                                    } elseif (str_contains($l['action'], 'SUCCESS') || str_contains($l['action'], 'CREATE')) {
                                        $badgeClass = 'badge-glow-emerald';
                                    }
                                    ?>
                                    <tr>
                                        <td class="code-font text-secondary">#<?= $l['id'] ?></td>
                                        <td class="code-font small text-secondary">
                                            <?= date('d M Y, H:i:s', strtotime($l['created_at'])) ?>
                                        </td>
                                        <td>
                                            <span class="badge bg-dark border border-secondary border-opacity-50 text-light">
                                                <i class="fa-solid fa-user-shield me-1 text-info"></i> <?= e($l['admin_username']) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge <?= $badgeClass ?>"><?= e($l['action']) ?></span>
                                        </td>
                                        <td class="code-font small text-info"><?= e($l['ip_address']) ?></td>
                                        <td class="small text-secondary" style="max-width: 380px;">
                                            <div class="text-truncate" title="<?= e($l['details']) ?>">
                                                <?= e($l['details']) ?>
                                            </div>
                                            <div class="text-secondary small opacity-50 text-truncate" style="font-size: 0.7rem;" title="<?= e($l['user_agent']) ?>">
                                                <?= e($l['user_agent']) ?>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                    <div class="d-flex justify-content-between align-items-center mt-4 pt-3 border-top border-secondary border-opacity-25">
                        <span class="text-secondary small">Menampilkan halaman <?= $page ?> dari <?= $totalPages ?> (Total <?= $totalRows ?> log)</span>
                        <ul class="pagination pagination-sm mb-0">
                            <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                                <li class="page-item <?= ($p === $page) ? 'active' : '' ?>">
                                    <a class="page-link bg-dark text-white border-secondary border-opacity-25" href="audit.php?page=<?= $p ?>&search=<?= urlencode($search) ?>&action_filter=<?= urlencode($filterAction) ?>">
                                        <?= $p ?>
                                    </a>
                                </li>
                            <?php endfor; ?>
                        </ul>
                    </div>
                <?php endif; ?>
            </div>
        </main>
    </div>
</div>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/script.js"></script>
</body>
</html>
