<?php
/**
 * SECURE ADMIN SYSTEM - CATEGORIES MANAGEMENT
 * File: categories.php
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';

sendSecurityHeaders();
requireAuth();

$pdo = getDBConnection();
$admin = getCurrentAdmin();
$message = null;
$messageType = null;

// PROSES POST: TAMBAH, EDIT, HAPUS KATEGORI
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!validateCSRFToken($csrfToken)) {
        $message = 'Token CSRF tidak valid atau sesi berakhir.';
        $messageType = 'danger';
    } else {
        if ($action === 'create') {
            $name = sanitizeInput($_POST['name'] ?? '');
            $description = sanitizeInput($_POST['description'] ?? '');
            $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $name), '-'));

            if (empty($name)) {
                $message = 'Nama kategori wajib diisi.';
                $messageType = 'danger';
            } else {
                try {
                    $stmt = $pdo->prepare('INSERT INTO categories (name, slug, description, created_at) VALUES (?, ?, ?, NOW())');
                    $stmt->execute([$name, $slug, $description]);
                    logAudit('CATEGORY_CREATE', 'Menambahkan kategori: ' . $name);
                    $message = 'Kategori baru berhasil ditambahkan!';
                    $messageType = 'success';
                } catch (PDOException $e) {
                    $message = 'Gagal menambahkan kategori. Nama atau slug mungkin sudah digunakan.';
                    $messageType = 'danger';
                }
            }
        } elseif ($action === 'update') {
            $id = (int)($_POST['id'] ?? 0);
            $name = sanitizeInput($_POST['name'] ?? '');
            $description = sanitizeInput($_POST['description'] ?? '');
            $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $name), '-'));

            if ($id <= 0 || empty($name)) {
                $message = 'Data kategori tidak valid.';
                $messageType = 'danger';
            } else {
                try {
                    $stmt = $pdo->prepare('UPDATE categories SET name = ?, slug = ?, description = ? WHERE id = ?');
                    $stmt->execute([$name, $slug, $description, $id]);
                    logAudit('CATEGORY_UPDATE', 'Memperbarui kategori ID: ' . $id . ' (' . $name . ')');
                    $message = 'Kategori berhasil diperbarui!';
                    $messageType = 'success';
                } catch (PDOException $e) {
                    $message = 'Gagal memperbarui kategori.';
                    $messageType = 'danger';
                }
            }
        } elseif ($action === 'delete') {
            $id = (int)($_POST['id'] ?? 0);

            // Cek apakah ada konten terasosiasi
            $stmtCheck = $pdo->prepare('SELECT COUNT(*) FROM contents WHERE category_id = ?');
            $stmtCheck->execute([$id]);
            $count = (int)$stmtCheck->fetchColumn();

            if ($count > 0) {
                $message = "Kategori tidak dapat dihapus karena masih digunakan oleh {$count} konten terenkripsi.";
                $messageType = 'warning';
            } else {
                $stmt = $pdo->prepare('DELETE FROM categories WHERE id = ?');
                $stmt->execute([$id]);
                logAudit('CATEGORY_DELETE', 'Menghapus kategori ID: ' . $id);
                $message = 'Kategori berhasil dihapus!';
                $messageType = 'success';
            }
        }
    }
}

// Ambil Semua Kategori dengan Jumlah Konten
$stmtCats = $pdo->query('
    SELECT c.*, COUNT(cnt.id) AS total_contents 
    FROM categories c 
    LEFT JOIN contents cnt ON c.id = cnt.category_id 
    GROUP BY c.id 
    ORDER BY c.name ASC
');
$categories = $stmtCats->fetchAll();
$csrf = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manajemen Kategori - SECURE ADMIN SYSTEM</title>
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
                <a href="categories.php" class="nav-link active">
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
                <h5 class="fw-bold mb-0 text-white">Manajemen Kategori Konten</h5>
            </div>
            <div>
                <button class="btn btn-cyber btn-sm" data-bs-toggle="modal" data-bs-target="#modalCreateCategory">
                    <i class="fa-solid fa-plus me-1"></i> Tambah Kategori
                </button>
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

            <div class="glass-panel p-4">
                <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                    <div>
                        <h5 class="fw-bold mb-0 text-white">Daftar Kategori Konten</h5>
                        <small class="text-secondary">Pengelompokan dokumen dan informasi terenkripsi.</small>
                    </div>
                    <span class="badge badge-glow-cyan"><?= count($categories) ?> Kategori Terdaftar</span>
                </div>

                <div class="table-responsive">
                    <table class="table-cyber">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Nama Kategori</th>
                                <th>Slug</th>
                                <th>Deskripsi</th>
                                <th>Total Konten</th>
                                <th class="text-end">Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($categories)): ?>
                                <tr>
                                    <td colspan="6" class="text-center py-4 text-secondary">Belum ada kategori yang dibuat.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($categories as $cat): ?>
                                    <tr>
                                        <td class="code-font text-secondary">#<?= $cat['id'] ?></td>
                                        <td class="fw-semibold text-white">
                                            <i class="fa-solid fa-folder me-2 text-info"></i><?= e($cat['name']) ?>
                                        </td>
                                        <td class="code-font small text-info"><?= e($cat['slug']) ?></td>
                                        <td class="small text-secondary"><?= e($cat['description'] ?: '-') ?></td>
                                        <td>
                                            <span class="badge bg-dark border border-secondary border-opacity-50 text-light">
                                                <?= (int)$cat['total_contents'] ?> Konten
                                            </span>
                                        </td>
                                        <td class="text-end">
                                            <button class="btn btn-cyber-outline btn-sm py-1 px-2 me-1" 
                                                    onclick="editCategory(<?= htmlspecialchars(json_encode($cat), ENT_QUOTES, 'UTF-8') ?>)">
                                                <i class="fa-solid fa-pen-to-square"></i>
                                            </button>
                                            <button class="btn btn-outline-danger btn-sm py-1 px-2"
                                                    onclick="deleteCategory(<?= $cat['id'] ?>, '<?= e($cat['name']) ?>')">
                                                <i class="fa-solid fa-trash"></i>
                                            </button>
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

<!-- MODAL CREATE CATEGORY -->
<div class="modal fade" id="modalCreateCategory" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content cyber-modal">
            <div class="modal-header">
                <h5 class="modal-title fw-bold text-white"><i class="fa-solid fa-folder-plus text-info me-2"></i> Tambah Kategori Baru</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="categories.php">
                <div class="modal-body">
                    <input type="hidden" name="action" value="create">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">

                    <div class="mb-3">
                        <label class="form-label">Nama Kategori</label>
                        <input type="text" name="name" class="form-control" placeholder="Contoh: Operasi Keamanan Khusus" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Deskripsi (Opsional)</label>
                        <textarea name="description" class="form-control" rows="3" placeholder="Penjelasan singkat tujuan kategori..."></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cyber-outline" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-cyber">Simpan Kategori</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- MODAL EDIT CATEGORY -->
<div class="modal fade" id="modalEditCategory" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content cyber-modal">
            <div class="modal-header">
                <h5 class="modal-title fw-bold text-white"><i class="fa-solid fa-pen-to-square text-info me-2"></i> Perbarui Kategori</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="categories.php">
                <div class="modal-body">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <input type="hidden" name="id" id="editCatId">

                    <div class="mb-3">
                        <label class="form-label">Nama Kategori</label>
                        <input type="text" name="name" id="editCatName" class="form-control" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Deskripsi</label>
                        <textarea name="description" id="editCatDescription" class="form-control" rows="3"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cyber-outline" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-cyber">Simpan Perubahan</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- MODAL DELETE CONFIRMATION -->
<div class="modal fade" id="modalDeleteCategory" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content cyber-modal">
            <div class="modal-header">
                <h5 class="modal-title fw-bold text-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i> Konfirmasi Hapus</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="categories.php">
                <div class="modal-body">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <input type="hidden" name="id" id="deleteCatId">
                    <p class="text-secondary mb-0">Apakah Anda yakin ingin menghapus kategori <strong class="text-white" id="deleteCatName"></strong>?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cyber-outline" data-bs-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-danger">Hapus Kategori</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/script.js"></script>
<script>
function editCategory(cat) {
    document.getElementById('editCatId').value = cat.id;
    document.getElementById('editCatName').value = cat.name;
    document.getElementById('editCatDescription').value = cat.description || '';
    new bootstrap.Modal(document.getElementById('modalEditCategory')).show();
}

function deleteCategory(id, name) {
    document.getElementById('deleteCatId').value = id;
    document.getElementById('deleteCatName').innerText = name;
    new bootstrap.Modal(document.getElementById('modalDeleteCategory')).show();
}
</script>
</body>
</html>
