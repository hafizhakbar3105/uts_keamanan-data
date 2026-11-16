<?php
/**
 * ============================================================================
 * [TUGAS UTS - BUTIR 2]: HALAMAN ADMIN DENGAN KONTEN TERENKRIPSI
 * File: contents.php
 * Konsep:
 * 1. Simpan Konten: Teks dienkripsi dengan AES-256-GCM (Simetris) & kuncinya
 *    dibungkus dengan RSA-OAEP 2048-bit (Asimetris).
 * 2. Tampil di Admin: Tersimpan dan ditampilkan 100% dalam bentuk Ciphertext.
 * 3. Dekripsi: Membuka kembali konten menjadi teks asli menggunakan Private Key.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';
require_once __DIR__ . '/crypto/hybrid.php';

sendSecurityHeaders();
requireAuth(); // Wajib login untuk mengakses data admin

$pdo = getDBConnection();
$admin = getCurrentAdmin();
$message = null;
$messageType = null;
$decryptedView = null;

$action = $_GET['action'] ?? 'list';
$publicKeyPath = __DIR__ . '/storage/keys/public_key.pem';
$privateKeyPath = __DIR__ . '/storage/keys/private_key.pem';

// ----------------------------------------------------------------------------
// 1. PROSES POST: ENKRIPSI BARU, UPDATE, HAPUS, & DEKRIPSI KONTEN
// ----------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postAction = $_POST['action'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!validateCSRFToken($csrfToken)) {
        $message = 'Token CSRF tidak valid atau sesi telah berakhir.';
        $messageType = 'danger';
    } else {
        // [TUGAS UTS]: PROSES ENKRIPSI SAAT MENYIMPAN DATA BARU
        if ($postAction === 'create') {
            $categoryId = (int)($_POST['category_id'] ?? 0);
            $rawTitle = sanitizeInput($_POST['title'] ?? '');
            $rawContent = sanitizeInput($_POST['content'] ?? '');
            $status = in_array($_POST['status'] ?? '', ['draft', 'published', 'archived'], true) ? $_POST['status'] : 'published';

            if (empty($rawTitle) || empty($rawContent) || $categoryId <= 0) {
                $message = 'Judul, Isi Konten, dan Kategori wajib diisi.';
                $messageType = 'danger';
            } else {
                try {
                    // Ambil Public Key RSA untuk membungkus kunci AES
                    $pubKey = file_exists($publicKeyPath) ? file_get_contents($publicKeyPath) : '';
                    if (empty($pubKey)) {
                        throw new RuntimeException('Public Key RSA sistem tidak ditemukan di storage/keys/public_key.pem');
                    }

                    // Eksekusi Enkripsi Hibrida: AES-256-GCM (konten) + RSA-OAEP (kunci AES)
                    $enc = HybridCrypto::encryptRecord($rawTitle, $rawContent, $pubKey);

                    // [TUGAS UTS]: Simpan Ciphertext murni ke Database (TIDAK ADA PLAINTEXT)
                    $stmt = $pdo->prepare(
                        'INSERT INTO contents (category_id, encrypted_title, encrypted_content, encrypted_aes_key, nonce, auth_tag, status, created_by, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())'
                    );
                    $stmt->execute([
                        $categoryId,
                        $enc['encrypted_title'],
                        $enc['encrypted_content'],
                        $enc['encrypted_aes_key'],
                        $enc['nonce'],
                        $enc['auth_tag'],
                        $status,
                        $admin['id'],
                    ]);

                    $newId = (int)$pdo->lastInsertId();
                    logAudit('CONTENT_CREATE', "Menambahkan konten terenkripsi baru #{$newId} (AES-256-GCM + RSA-OAEP)");
                    header('Location: contents.php?msg=created');
                    exit();
                } catch (Exception $e) {
                    $message = 'Gagal menyimpan dan mengenkripsi konten: ' . $e->getMessage();
                    $messageType = 'danger';
                }
            }
        }

        // --- UPDATE KONTEN ---
        elseif ($postAction === 'update') {
            $id = (int)($_POST['id'] ?? 0);
            $categoryId = (int)($_POST['category_id'] ?? 0);
            $rawTitle = sanitizeInput($_POST['title'] ?? '');
            $rawContent = sanitizeInput($_POST['content'] ?? '');
            $status = in_array($_POST['status'] ?? '', ['draft', 'published', 'archived'], true) ? $_POST['status'] : 'published';

            if ($id <= 0 || empty($rawTitle) || empty($rawContent) || $categoryId <= 0) {
                $message = 'Seluruh kolom wajib diisi dengan benar.';
                $messageType = 'danger';
            } else {
                try {
                    $pubKey = file_exists($publicKeyPath) ? file_get_contents($publicKeyPath) : '';
                    // Enkripsi ulang dengan AES key & nonce baru
                    $enc = HybridCrypto::encryptRecord($rawTitle, $rawContent, $pubKey);

                    $stmt = $pdo->prepare(
                        'UPDATE contents SET category_id = ?, encrypted_title = ?, encrypted_content = ?, encrypted_aes_key = ?, nonce = ?, auth_tag = ?, status = ? WHERE id = ?'
                    );
                    $stmt->execute([
                        $categoryId,
                        $enc['encrypted_title'],
                        $enc['encrypted_content'],
                        $enc['encrypted_aes_key'],
                        $enc['nonce'],
                        $enc['auth_tag'],
                        $status,
                        $id,
                    ]);

                    logAudit('CONTENT_UPDATE', "Memperbarui dan mengenkripsi ulang konten #{$id}");
                    header('Location: contents.php?msg=updated');
                    exit();
                } catch (Exception $e) {
                    $message = 'Gagal memperbarui konten: ' . $e->getMessage();
                    $messageType = 'danger';
                }
            }
        }

        // --- HAPUS KONTEN (DELETE) ---
        elseif ($postAction === 'delete') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                $stmt = $pdo->prepare('DELETE FROM contents WHERE id = ?');
                $stmt->execute([$id]);
                logAudit('CONTENT_DELETE', "Menghapus konten terenkripsi #{$id}");
                header('Location: contents.php?msg=deleted');
                exit();
            }
        }

        // [TUGAS UTS]: PROSES DEKRIPSI KONTEN MENGGUNAKAN KUNCI ASIMETRIS (RSA)
        elseif ($postAction === 'decrypt_view') {
            $id = (int)($_POST['id'] ?? 0);
            $privKeyInput = trim($_POST['private_key'] ?? '');

            if (empty($privKeyInput)) {
                // Memuat kunci privat default sistem jika tidak diinput manual
                if (file_exists($privateKeyPath)) {
                    $privKeyInput = file_get_contents($privateKeyPath);
                } else {
                    $message = 'Private Key RSA wajib dimasukkan untuk mendekripsi konten.';
                    $messageType = 'danger';
                }
            }

            if (!empty($privKeyInput) && $id > 0) {
                $stmt = $pdo->prepare('SELECT c.*, cat.name as category_name FROM contents c JOIN categories cat ON c.category_id = cat.id WHERE c.id = ?');
                $stmt->execute([$id]);
                $item = $stmt->fetch();

                if ($item) {
                    try {
                        // 1. Dekripsi kunci AES dengan RSA-OAEP menggunakan Private Key
                        // 2. Dekripsi konten dengan AES-256-GCM dan verifikasi Authentication Tag
                        $decrypted = HybridCrypto::decryptRecord(
                            $item['encrypted_content'],
                            $item['encrypted_aes_key'],
                            $item['nonce'],
                            $item['auth_tag'],
                            $privKeyInput
                        );

                        $decryptedView = [
                            'id'            => $item['id'],
                            'category_name' => $item['category_name'],
                            'status'        => $item['status'],
                            'created_at'    => $item['created_at'],
                            'title'         => $decrypted['title'],
                            'content'       => $decrypted['content'],
                            'raw_aes_key'   => $decrypted['raw_aes_key_b64'],
                            'nonce'         => $item['nonce'],
                            'auth_tag'      => $item['auth_tag'],
                            'cipher_aes'    => $item['encrypted_aes_key'],
                            'cipher_body'   => $item['encrypted_content'],
                        ];

                        logAudit('CONTENT_DECRYPT', "Mendekripsi konten #{$id} menggunakan RSA Private Key");
                        $message = 'Data berhasil didekripsi! Integritas terverifikasi (Auth Tag Valid).';
                        $messageType = 'success';
                    } catch (Exception $e) {
                        logAudit('CONTENT_DECRYPT_FAILED', "Gagal mendekripsi konten #{$id}: " . $e->getMessage());
                        $message = 'DEKRIPSI GAGAL: ' . $e->getMessage();
                        $messageType = 'danger';
                    }
                }
            }
        }
    }
}

// Tangkap notifikasi URL
if (isset($_GET['msg'])) {
    if ($_GET['msg'] === 'created') {
        $message = 'Konten berhasil dienkripsi dengan AES-256-GCM + RSA-OAEP dan disimpan ke database!';
        $messageType = 'success';
    } elseif ($_GET['msg'] === 'updated') {
        $message = 'Konten berhasil diperbarui dan dienkripsi ulang!';
        $messageType = 'success';
    } elseif ($_GET['msg'] === 'deleted') {
        $message = 'Konten berhasil dihapus.';
        $messageType = 'success';
    }
}

// Ambil Kategori untuk dropdown
$categories = $pdo->query('SELECT id, name FROM categories ORDER BY name ASC')->fetchAll();

// -------------------------------------------------------------
// FILTER & PAGINATION KONTEN
// -------------------------------------------------------------
$filterCat = (int)($_GET['category'] ?? 0);
$filterStatus = sanitizeInput($_GET['status'] ?? '');
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 10;
$offset = ($page - 1) * $perPage;

$whereClauses = ['1=1'];
$params = [];

if ($filterCat > 0) {
    $whereClauses[] = 'c.category_id = ?';
    $params[] = $filterCat;
}
if (!empty($filterStatus) && in_array($filterStatus, ['draft', 'published', 'archived'], true)) {
    $whereClauses[] = 'c.status = ?';
    $params[] = $filterStatus;
}

$whereSql = implode(' AND ', $whereClauses);

// Count total
$stmtCount = $pdo->prepare("SELECT COUNT(*) FROM contents c WHERE {$whereSql}");
$stmtCount->execute($params);
$totalRows = (int)$stmtCount->fetchColumn();
$totalPages = max(1, (int)ceil($totalRows / $perPage));

// Fetch rows
$sql = "SELECT c.*, cat.name AS category_name, a.username AS author_name 
        FROM contents c 
        JOIN categories cat ON c.category_id = cat.id 
        LEFT JOIN admins a ON c.created_by = a.id 
        WHERE {$whereSql} 
        ORDER BY c.id DESC 
        LIMIT {$perPage} OFFSET {$offset}";
$stmtRows = $pdo->prepare($sql);
$stmtRows->execute($params);
$contents = $stmtRows->fetchAll();

$csrf = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manajemen Konten Terenkripsi - SECURE ADMIN SYSTEM</title>
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
                <a href="contents.php" class="nav-link active">
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
    </aside>

    <!-- MAIN CONTENT -->
    <div class="admin-main">
        <header class="admin-topbar">
            <div class="d-flex align-items-center gap-3">
                <button class="btn btn-cyber-outline d-lg-none p-2" type="button" onclick="document.querySelector('.admin-sidebar').classList.toggle('show')">
                    <i class="fa-solid fa-bars"></i>
                </button>
                <h5 class="fw-bold mb-0 text-white">Manajemen Konten Terenkripsi</h5>
            </div>
            <div>
                <a href="contents.php?action=create" class="btn btn-cyber btn-sm">
                    <i class="fa-solid fa-plus me-1"></i> Tambah Konten Rahasia
                </a>
            </div>
        </header>

        <main class="admin-content">
            <?php if ($message): ?>
                <div class="alert alert-<?= e($messageType) ?> alert-dismissible fade show rounded-3 mb-4" role="alert">
                    <i class="fa-solid <?= $messageType === 'success' ? 'fa-circle-check' : 'fa-triangle-exclamation' ?> me-2"></i>
                    <?= e($message) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <!-- KOTAK HASIL DEKRIPSI JIKA ADA -->
            <?php if ($decryptedView): ?>
                <div class="glass-panel p-4 mb-4 border border-info border-opacity-50">
                    <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                        <div class="d-flex align-items-center gap-2">
                            <i class="fa-solid fa-lock-open text-success fs-5"></i>
                            <h5 class="fw-bold mb-0 text-white">Hasil Dekripsi Dokumen Terverifikasi #<?= $decryptedView['id'] ?></h5>
                        </div>
                        <span class="badge badge-glow-emerald code-font">INTEGRITY VERIFIED (AEAD)</span>
                    </div>

                    <div class="row g-3 mb-3">
                        <div class="col-md-8">
                            <label class="form-label text-info">Judul Asli (Decrypted Plaintext):</label>
                            <div class="p-3 rounded-3 bg-dark text-white fw-bold fs-5 border border-secondary border-opacity-50">
                                <?= e($decryptedView['title']) ?>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label text-info">Metadata Kategori & Tanggal:</label>
                            <div class="p-3 rounded-3 bg-dark text-secondary small border border-secondary border-opacity-50">
                                <div><i class="fa-solid fa-folder me-1 text-info"></i> <?= e($decryptedView['category_name']) ?></div>
                                <div class="mt-1"><i class="fa-solid fa-calendar me-1"></i> <?= e($decryptedView['created_at']) ?></div>
                            </div>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label text-info">Isi Dokumen (Decrypted Plaintext):</label>
                        <div class="p-3 rounded-3 bg-dark text-light border border-secondary border-opacity-50" style="white-space: pre-wrap; font-size: 0.95rem;">
                            <?= e($decryptedView['content']) ?>
                        </div>
                    </div>

                    <!-- Telemetri Kriptografi Dokumen Ini -->
                    <div class="p-3 rounded-3" style="background:#f8fafc; border:1px solid #e2e8f0;">
                        <div class="text-secondary small fw-semibold mb-2">BUKTI KRIPTOGRAFIS (CIPHERTEXT & KEY WRAPPING):</div>
                        <div class="row g-2 code-font small text-secondary">
                            <div class="col-md-6">
                                <span class="text-info">Nonce (IV GCM 96-bit):</span> <?= e($decryptedView['nonce']) ?>
                            </div>
                            <div class="col-md-6">
                                <span class="text-success">Auth Tag (128-bit):</span> <?= e($decryptedView['auth_tag']) ?>
                            </div>
                            <div class="col-12 text-truncate">
                                <span class="text-warning">Encrypted AES Key (RSA-OAEP):</span> <?= e(substr($decryptedView['cipher_aes'], 0, 60)) ?>...
                            </div>
                        </div>
                    </div>

                    <div class="text-end mt-3">
                        <button type="button" class="btn btn-cyber-outline btn-sm" onclick="this.closest('.glass-panel').remove()">
                            <i class="fa-solid fa-eye-slash me-1"></i> Tutup Tampilan Plaintext
                        </button>
                    </div>
                </div>
            <?php endif; ?>

            <!-- JIKA AKSI CREATE ATAU EDIT -->
            <?php if ($action === 'create' || $action === 'edit'): ?>
                <?php
                $isEdit = ($action === 'edit');
                $editId = (int)($_GET['id'] ?? 0);
                $editData = null;
                if ($isEdit && $editId > 0) {
                    $stmtEdit = $pdo->prepare('SELECT * FROM contents WHERE id = ?');
                    $stmtEdit->execute([$editId]);
                    $editData = $stmtEdit->fetch();
                }
                ?>
                <div class="glass-panel p-4 col-lg-8 mx-auto">
                    <div class="d-flex justify-content-between align-items-center mb-4 pb-2 border-bottom border-secondary border-opacity-25">
                        <h5 class="fw-bold mb-0 text-white">
                            <i class="fa-solid <?= $isEdit ? 'fa-pen-to-square' : 'fa-plus' ?> text-info me-2"></i>
                            <?= $isEdit ? "Perbarui & Enkripsi Ulang Konten #{$editId}" : 'Tambah Konten Baru (Terenkripsi Penuh)' ?>
                        </h5>
                        <a href="contents.php" class="btn btn-cyber-outline btn-sm">
                            <i class="fa-solid fa-arrow-left me-1"></i> Batal
                        </a>
                    </div>

                    <form method="POST" action="contents.php">
                        <input type="hidden" name="action" value="<?= $isEdit ? 'update' : 'create' ?>">
                        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                        <?php if ($isEdit): ?>
                            <input type="hidden" name="id" value="<?= $editId ?>">
                        <?php endif; ?>

                        <div class="row g-3 mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Kategori Dokumen</label>
                                <select name="category_id" class="form-select" required>
                                    <option value="">-- Pilih Kategori --</option>
                                    <?php foreach ($categories as $cat): ?>
                                        <option value="<?= $cat['id'] ?>" <?= ($isEdit && $editData && (int)$editData['category_id'] === (int)$cat['id']) ? 'selected' : '' ?>>
                                            <?= e($cat['name']) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Status Publikasi</label>
                                <select name="status" class="form-select">
                                    <option value="published" <?= ($isEdit && $editData && $editData['status'] === 'published') ? 'selected' : '' ?>>Published</option>
                                    <option value="draft" <?= ($isEdit && $editData && $editData['status'] === 'draft') ? 'selected' : '' ?>>Draft</option>
                                    <option value="archived" <?= ($isEdit && $editData && $editData['status'] === 'archived') ? 'selected' : '' ?>>Archived</option>
                                </select>
                            </div>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">
                                <i class="fa-solid fa-heading text-info me-1"></i> Judul Konten (Akan Dienkripsi AES-256-GCM)
                            </label>
                            <input type="text" name="title" class="form-control" placeholder="Masukkan judul dokumen rahasia..." required>
                            <small class="text-secondary">Judul tidak akan disimpan dalam bentuk plaintext ke database.</small>
                        </div>

                        <div class="mb-4">
                            <label class="form-label">
                                <i class="fa-solid fa-align-left text-info me-1"></i> Isi Dokumen Sensitif (Akan Dienkripsi AES-256-GCM)
                            </label>
                            <textarea name="content" class="form-control" rows="8" placeholder="Ketik isi laporan atau informasi rahasia di sini..." required></textarea>
                            <small class="text-secondary">Data diproses melalui pembungkusan kunci hibrida (AES-256-GCM + RSA-OAEP 2048-bit).</small>
                        </div>

                        <div class="p-3 rounded-3 mb-4" style="background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2);">
                            <div class="d-flex align-items-center gap-2 text-info small fw-semibold mb-1">
                                <i class="fa-solid fa-shield-halved"></i> Garansi Keamanan Kriptografis
                            </div>
                            <div class="text-secondary small">
                                Saat tombol di bawah ditekan, sistem otomatis membuat kunci simetris 256-bit baru, membungkusnya dengan RSA Public Key, dan menyimpan ciphertext serta 128-bit integrity tag ke MySQL.
                            </div>
                        </div>

                        <button type="submit" class="btn btn-cyber py-2 px-4 w-100">
                            <i class="fa-solid fa-lock me-2"></i> <?= $isEdit ? 'Enkripsi Ulang & Simpan Perubahan' : 'Enkripsi & Simpan ke Basis Data' ?>
                        </button>
                    </form>
                </div>

            <!-- JIKA AKSI LIST (TABEL UTAMA) -->
            <?php else: ?>
                <div class="glass-panel p-4 mb-4">
                    <!-- Filter bar -->
                    <form method="GET" action="contents.php" class="row g-3 align-items-end mb-4">
                        <div class="col-md-4">
                            <label class="form-label">Filter Kategori</label>
                            <select name="category" class="form-select">
                                <option value="">Semua Kategori</option>
                                <?php foreach ($categories as $cat): ?>
                                    <option value="<?= $cat['id'] ?>" <?= ($filterCat === (int)$cat['id']) ? 'selected' : '' ?>>
                                        <?= e($cat['name']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">Status</label>
                            <select name="status" class="form-select">
                                <option value="">Semua Status</option>
                                <option value="published" <?= $filterStatus === 'published' ? 'selected' : '' ?>>Published</option>
                                <option value="draft" <?= $filterStatus === 'draft' ? 'selected' : '' ?>>Draft</option>
                                <option value="archived" <?= $filterStatus === 'archived' ? 'selected' : '' ?>>Archived</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <button type="submit" class="btn btn-cyber-outline w-100">
                                <i class="fa-solid fa-filter me-1"></i> Terapkan Filter
                            </button>
                        </div>
                        <div class="col-md-2 text-md-end">
                            <a href="contents.php" class="btn btn-outline-secondary w-100">Reset</a>
                        </div>
                    </form>

                    <!-- Security Note Notice -->
                    <div class="p-3 rounded-3 mb-4" style="background:#f8fafc; border:1px solid #e2e8f0;">
                        <div class="text-primary small fw-semibold mb-1">
                            <i class="fa-solid fa-circle-info me-1"></i> Catatan Arsitektur Zero-Knowledge:
                        </div>
                        <div class="text-secondary small">
                            Seluruh judul dan isi konten disimpan dalam bentuk <strong>Ciphertext AES-256-GCM</strong>. Tabel di bawah membuktikan bahwa data tersimpan tidak dapat dibaca (opaque) tanpa mendekripsinya menggunakan Private Key RSA.
                        </div>
                    </div>

                    <!-- Table of Encrypted Contents -->
                    <div class="table-responsive">
                        <table class="table-cyber">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Kategori</th>
                                    <th>Ciphertext Judul (Encrypted)</th>
                                    <th>Status</th>
                                    <th>Auth Tag (AEAD)</th>
                                    <th>Tanggal</th>
                                    <th class="text-end">Aksi Kriptografi</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($contents)): ?>
                                    <tr>
                                        <td colspan="7" class="text-center py-4 text-secondary">
                                            Belum ada dokumen terenkripsi. Silakan klik "Tambah Konten Rahasia".
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($contents as $row): ?>
                                        <tr>
                                            <td class="code-font text-secondary">#<?= $row['id'] ?></td>
                                            <td>
                                                <span class="badge bg-dark border border-secondary border-opacity-50 text-light">
                                                    <?= e($row['category_name']) ?>
                                                </span>
                                            </td>
                                            <td>
                                                <div class="cipher-preview" title="<?= e($row['encrypted_title']) ?>">
                                                    <i class="fa-solid fa-lock text-info me-1"></i> <?= e(substr($row['encrypted_title'], 0, 32)) ?>...
                                                </div>
                                            </td>
                                            <td>
                                                <?php if ($row['status'] === 'published'): ?>
                                                    <span class="badge badge-glow-emerald">Published</span>
                                                <?php elseif ($row['status'] === 'draft'): ?>
                                                    <span class="badge badge-glow-cyan">Draft</span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary">Archived</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="code-font small text-success">
                                                <?= e(substr($row['auth_tag'], 0, 12)) ?>...
                                            </td>
                                            <td class="small text-secondary"><?= date('d/m/Y H:i', strtotime($row['created_at'])) ?></td>
                                            <td class="text-end">
                                                <!-- Tombol Buka Modal Dekripsi -->
                                                <button class="btn btn-cyber-outline btn-sm py-1 px-2 me-1" 
                                                        title="Dekripsi Konten"
                                                        onclick="openDecryptModal(<?= $row['id'] ?>, '<?= e(addslashes($row['category_name'])) ?>')">
                                                    <i class="fa-solid fa-unlock-keyhole text-success"></i> Dekripsi
                                                </button>
                                                <!-- Tombol Edit -->
                                                <a href="contents.php?action=edit&id=<?= $row['id'] ?>" class="btn btn-cyber-outline btn-sm py-1 px-2 me-1" title="Edit">
                                                    <i class="fa-solid fa-pen-to-square"></i>
                                                </a>
                                                <!-- Tombol Hapus -->
                                                <button class="btn btn-outline-danger btn-sm py-1 px-2" 
                                                        title="Hapus"
                                                        onclick="confirmDeleteContent(<?= $row['id'] ?>)">
                                                    <i class="fa-solid fa-trash"></i>
                                                </button>
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
                            <span class="text-secondary small">Menampilkan halaman <?= $page ?> dari <?= $totalPages ?> (Total <?= $totalRows ?> konten)</span>
                            <ul class="pagination pagination-sm mb-0">
                                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                                    <li class="page-item <?= ($p === $page) ? 'active' : '' ?>">
                                        <a class="page-link bg-dark text-white border-secondary border-opacity-25" href="contents.php?page=<?= $p ?>&category=<?= $filterCat ?>&status=<?= e($filterStatus) ?>">
                                            <?= $p ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                            </ul>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </main>
    </div>
</div>

<!-- MODAL DEKRIPSI KONTEN -->
<div class="modal fade" id="modalDecrypt" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content cyber-modal">
            <div class="modal-header">
                <h5 class="modal-title fw-bold text-white">
                    <i class="fa-solid fa-key text-success me-2"></i> Dekripsi Dokumen Terproteksi
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="contents.php">
                <div class="modal-body">
                    <input type="hidden" name="action" value="decrypt_view">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <input type="hidden" name="id" id="decryptContentId">

                    <p class="text-secondary small mb-3">
                        Dokumen ini terenkripsi menggunakan <strong>AES-256-GCM</strong> dan kunci AES dibungkus dengan <strong>RSA-OAEP</strong>. Masukkan RSA Private Key Anda untuk membuka dokumen ini.
                    </p>

                    <div class="mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <label class="form-label mb-0">RSA Private Key (PEM):</label>
                            <button type="button" class="btn btn-link btn-sm text-info text-decoration-none p-0" onclick="loadTestKeyForDecrypt()">
                                <i class="fa-solid fa-wand-magic-sparkles me-1"></i> Gunakan Kunci Default
                            </button>
                        </div>
                        <textarea name="private_key" id="decryptPrivKeyInput" class="form-control code-font" rows="5" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----" required></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cyber-outline" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-cyber">
                        <i class="fa-solid fa-unlock me-1"></i> Verifikasi Tag & Dekripsi
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- MODAL DELETE CONTENT -->
<div class="modal fade" id="modalDeleteContent" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content cyber-modal">
            <div class="modal-header">
                <h5 class="modal-title fw-bold text-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i> Konfirmasi Penghapusan</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="contents.php">
                <div class="modal-body">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <input type="hidden" name="id" id="deleteContentId">
                    <p class="text-secondary mb-0">Apakah Anda yakin ingin menghapus konten terenkripsi ID <strong class="text-white" id="deleteContentLabel"></strong> secara permanen?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cyber-outline" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-danger">Hapus Permanen</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/script.js"></script>
<script>
function openDecryptModal(id, categoryName) {
    document.getElementById('decryptContentId').value = id;
    new bootstrap.Modal(document.getElementById('modalDecrypt')).show();
}

function confirmDeleteContent(id) {
    document.getElementById('deleteContentId').value = id;
    document.getElementById('deleteContentLabel').innerText = '#' + id;
    new bootstrap.Modal(document.getElementById('modalDeleteContent')).show();
}

async function loadTestKeyForDecrypt() {
    try {
        const res = await fetch('crypto/get_test_key.php');
        const data = await res.json();
        if (data.key) {
            document.getElementById('decryptPrivKeyInput').value = data.key;
            showCyberToast('Kunci RSA testing dimuat!', 'success');
        }
    } catch(e) {}
}
</script>
</body>
</html>
