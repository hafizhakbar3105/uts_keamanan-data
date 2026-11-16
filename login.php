<?php
/**
 * ============================================================================
 * [TUGAS UTS - BUTIR 1]: PARADIGMA LOGIN KUNCI SIMETRIS & ASIMETRIS
 * File: login.php
 * Konsep:
 * 1. Kunci Simetris: Master secret passphrase untuk verifikasi akun.
 * 2. Kunci Asimetris: RSA Private Key untuk menandatangani challenge acak server.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';
require_once __DIR__ . '/crypto/rsa.php';

sendSecurityHeaders();
startSecureSession();

// Jika sudah terautentikasi, langsung arahkan ke halaman admin
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

$clientIp = getClientIP();
$pdo = getDBConnection();

// ----------------------------------------------------------------------------
// TAHAP 1: VALIDASI KUNCI SIMETRIS & PEMBUATAN RSA CHALLENGE ACAK
// ----------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'request_challenge') {
    header('Content-Type: application/json');

    // Proteksi brute-force: batasi maksimal 5 percobaan per 10 menit
    if (isRateLimited($clientIp, 5, 10)) {
        echo json_encode([
            'success' => false,
            'message' => 'Terlalu banyak percobaan gagal. Akses IP Anda ditangguhkan selama 10 menit demi keamanan sistem.',
        ]);
        exit();
    }

    $rawInput = file_get_contents('php://input');
    $data = json_decode($rawInput, true) ?? [];

    $username  = trim((string)($data['username'] ?? ''));
    $password  = (string)($data['password'] ?? ''); // Kunci Simetris
    $csrfToken = (string)($data['csrf_token'] ?? '');

    if (!validateCSRFToken($csrfToken)) {
        echo json_encode(['success' => false, 'message' => 'Token CSRF tidak valid atau sesi kedaluwarsa. Silakan refresh halaman.']);
        exit();
    }

    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Identitas dan Kunci Simetris wajib diisi.']);
        exit();
    }

    // Ambil data admin & verifikasi Kunci Simetris via hash
    $stmt = $pdo->prepare('SELECT id, username, email, password_hash, rsa_public_key, rsa_fingerprint, role, status FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $admin = $stmt->fetch();

    if (!$admin || !password_verify($password, $admin['password_hash'])) {
        recordLoginAttempt($clientIp, $username, false);
        logAudit('LOGIN_FAILED_CREDENTIALS', 'Kunci Simetris atau Username salah untuk: ' . $username, null, $username);
        echo json_encode(['success' => false, 'message' => 'Verifikasi Kunci Simetris Gagal: Kunci Simetris tidak cocok dengan brankas sistem.']);
        exit();
    }

    if ($admin['status'] !== 'active') {
        recordLoginAttempt($clientIp, $username, false);
        logAudit('LOGIN_FAILED_INACTIVE', 'Upaya login ke akun non-aktif: ' . $username, (int)$admin['id'], $username);
        echo json_encode(['success' => false, 'message' => 'Akun administrator ini berstatus non-aktif atau ditangguhkan.']);
        exit();
    }

    // Bangkitkan string acak (Challenge) 32-byte untuk ditandatangani Kunci Asimetris
    $challenge = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', time() + 120); // Kedaluwarsa dalam 2 menit (Anti-Replay)

    $stmtChallenge = $pdo->prepare(
        'INSERT INTO auth_challenges (challenge, username, ip_address, expires_at, is_used, created_at)
         VALUES (?, ?, ?, ?, 0, NOW())'
    );
    $stmtChallenge->execute([$challenge, $username, $clientIp, $expiresAt]);

    echo json_encode([
        'success'           => true,
        'challenge'         => $challenge,
        'expires_in_second' => 120,
        'fingerprint'       => $admin['rsa_fingerprint'],
    ]);
    exit();
}

// ----------------------------------------------------------------------------
// TAHAP 2: VERIFIKASI TANDA TANGAN KUNCI ASIMETRIS & PEMBUATAN SESI
// ----------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'verify_signature') {
    header('Content-Type: application/json');

    if (isRateLimited($clientIp, 5, 10)) {
        echo json_encode(['success' => false, 'message' => 'Akses ditangguhkan karena pelanggaran batas percobaan.']);
        exit();
    }

    $rawInput = file_get_contents('php://input');
    $data = json_decode($rawInput, true) ?? [];

    $username  = trim((string)($data['username'] ?? ''));
    $challenge = trim((string)($data['challenge'] ?? ''));
    $signature = trim((string)($data['signature'] ?? ''));
    $csrfToken = (string)($data['csrf_token'] ?? '');

    if (!validateCSRFToken($csrfToken)) {
        echo json_encode(['success' => false, 'message' => 'Validasi CSRF gagal.']);
        exit();
    }

    // Ambil record challenge yang masih aktif dan belum terpakai
    $stmtCh = $pdo->prepare(
        'SELECT id, username, expires_at, is_used FROM auth_challenges WHERE challenge = ? AND username = ?'
    );
    $stmtCh->execute([$challenge, $username]);
    $chRecord = $stmtCh->fetch();

    if (!$chRecord) {
        recordLoginAttempt($clientIp, $username, false);
        echo json_encode(['success' => false, 'message' => 'Challenge tidak ditemukan atau tidak sesuai.']);
        exit();
    }

    if ((int)$chRecord['is_used'] === 1) {
        recordLoginAttempt($clientIp, $username, false);
        logAudit('REPLAY_ATTACK_PREVENTED', 'Upaya penggunaan ulang challenge token (Replay Attack): ' . $challenge, null, $username);
        echo json_encode(['success' => false, 'message' => 'Peringatan Keamanan: Token challenge sudah digunakan sebelumnya (Replay Attack dicegah).']);
        exit();
    }

    if (strtotime($chRecord['expires_at']) < time()) {
        recordLoginAttempt($clientIp, $username, false);
        echo json_encode(['success' => false, 'message' => 'Token challenge telah kedaluwarsa. Silakan coba kembali.']);
        exit();
    }

    // Ambil data admin & Public Key
    $stmtAdmin = $pdo->prepare('SELECT id, username, email, rsa_public_key, role, status FROM admins WHERE username = ?');
    $stmtAdmin->execute([$username]);
    $admin = $stmtAdmin->fetch();

    if (!$admin || $admin['status'] !== 'active') {
        echo json_encode(['success' => false, 'message' => 'Akun tidak sah.']);
        exit();
    }

    // Verifikasi Digital Signature RSA (RSA-PSS / RSASSA SHA-256) menggunakan Public Key
    $isValid = RSACrypto::verifySignature($challenge, $signature, $admin['rsa_public_key']);

    if (!$isValid) {
        recordLoginAttempt($clientIp, $username, false);
        logAudit('LOGIN_FAILED_SIGNATURE', 'Digital signature tidak valid untuk challenge: ' . $challenge, (int)$admin['id'], $username);
        echo json_encode([
            'success' => false,
            'message' => 'Verifikasi Tanda Tangan Digital Gagal! Private Key yang Anda gunakan tidak cocok dengan Public Key yang terdaftar.',
        ]);
        exit();
    }

    // TANDAI CHALLENGE DIGUNAKAN (Anti-Replay Attack)
    $stmtUse = $pdo->prepare('UPDATE auth_challenges SET is_used = 1 WHERE id = ?');
    $stmtUse->execute([$chRecord['id']]);

    // Hapus sesi lama & regenerasi session ID baru untuk mencegah Session Fixation
    session_regenerate_id(true);

    $_SESSION['admin_id']         = (int)$admin['id'];
    $_SESSION['admin_username']   = $admin['username'];
    $_SESSION['admin_email']      = $admin['email'];
    $_SESSION['admin_role']       = $admin['role'];
    $_SESSION['is_authenticated'] = true;
    $_SESSION['login_time']       = time();
    $_SESSION['auth_method']      = 'RSA-PSS-SHA256';

    recordLoginAttempt($clientIp, $username, true);
    logAudit('LOGIN_SUCCESS_CRYPTO', 'Login berhasil menggunakan autentikasi RSA Digital Signature', (int)$admin['id'], $username);

    echo json_encode([
        'success'  => true,
        'message'  => 'Autentikasi Kriptografis Berhasil!',
        'redirect' => 'dashboard.php',
    ]);
    exit();
}

$csrf = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - SECURE ADMIN SYSTEM</title>
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
<body class="d-flex align-items-center justify-content-center py-5">

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-6 col-md-8">
                
                <div class="text-center mb-4">
                    <a href="index.php" class="text-decoration-none d-inline-flex align-items-center gap-2 mb-2">
                        <div class="stat-icon badge-glow-cyan p-2 rounded-3">
                            <i class="fa-solid fa-shield-halved text-primary fs-3"></i>
                        </div>
                        <span class="gradient-text fs-3 fw-bold">SECURE ADMIN SYSTEM</span>
                    </a>
                    <p class="text-secondary small">Paradigma Login Kriptografis: Autentikasi Kunci Simetris & Kunci Asimetris</p>
                </div>

                <div class="glass-panel p-4 p-md-5">
                    
                    <div class="d-flex justify-content-between align-items-center mb-4 pb-2 border-bottom border-secondary border-opacity-25">
                        <div>
                            <h4 class="fw-bold mb-0 text-white"><i class="fa-solid fa-fingerprint text-info me-2"></i> Administrator Gateway</h4>
                            <small class="text-secondary" style="font-size: 0.78rem;">Sesuai Soal UTS: Login via Input Kunci Simetris & Asimetris</small>
                        </div>
                        <span class="badge badge-glow-cyan code-font">CHALLENGE-RESPONSE</span>
                    </div>

                    <!-- Kotak Status Tahapan Autentikasi -->
                    <div id="loginStatusBox" class="alert d-none mb-4 p-3 rounded-3" style="background: #eff6ff; border: 1px solid #bfdbfe;">
                        <div id="loginStatusText" class="small text-dark"></div>
                    </div>

                    <form id="formSecureLogin" onsubmit="submitSecureLogin(event, this)">
                        <input type="hidden" id="loginCsrf" value="<?= e($csrf) ?>">

                        <!-- Identitas Admin -->
                        <div class="mb-3">
                            <label class="form-label" for="loginUsername">
                                <i class="fa-solid fa-user-shield me-1 text-info"></i> Identitas Administrator (Username)
                            </label>
                            <input type="text" id="loginUsername" class="form-control" placeholder="Masukkan username (default: admin)" value="admin" required autocomplete="username">
                        </div>

                        <!-- 1. Kunci Simetris -->
                        <div class="mb-3">
                            <label class="form-label" for="loginPassword">
                                <i class="fa-solid fa-key me-1 text-warning"></i> 1. Kunci Simetris (Symmetric Secret Key / Master Key)
                            </label>
                            <input type="password" id="loginPassword" class="form-control code-font" placeholder="Masukkan Kunci Simetris Rahasia" value="AdminSecure2026!" required autocomplete="current-password">
                            <small class="text-secondary" style="font-size: 0.75rem;">
                                <i class="fa-solid fa-shield-halved text-warning me-1"></i> Kunci rahasia bersama (Shared Secret) untuk verifikasi akses sistem.
                            </small>
                        </div>

                        <!-- 2. Kunci Asimetris -->
                        <div class="mb-4">
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <label class="form-label mb-0" for="loginPrivateKey">
                                    <i class="fa-solid fa-file-shield me-1 text-success"></i> 2. Kunci Asimetris (RSA Private Key 2048-bit)
                                </label>
                                <button type="button" class="btn btn-link btn-sm text-info text-decoration-none p-0" onclick="loadDefaultTestingKey()">
                                    <i class="fa-solid fa-wand-magic-sparkles me-1"></i> Muat Kunci Pengujian Otomatis
                                </button>
                            </div>
                            <textarea id="loginPrivateKey" class="form-control code-font" rows="5" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----" required></textarea>
                            <div class="d-flex justify-content-between align-items-center mt-2">
                                <small class="text-secondary" style="font-size: 0.75rem;">
                                    <i class="fa-solid fa-lock text-success me-1"></i> Kunci privat menandatangani challenge di sisi klien (Client-Side). Tidak pernah dikirim ke server.
                                </small>
                            </div>
                        </div>

                        <!-- Submit Button -->
                        <button type="submit" id="btnLoginSubmit" class="btn btn-cyber w-100 py-3 mb-3">
                            <i class="fa-solid fa-unlock-keyhole me-2"></i> Verifikasi Kunci Simetris & Asimetris
                        </button>
                    </form>

                    <div class="text-center pt-3 border-top border-secondary border-opacity-25">
                        <a href="index.php" class="text-secondary small text-decoration-none hover-white">
                            <i class="fa-solid fa-arrow-left me-1"></i> Kembali ke Beranda
                        </a>
                    </div>
                </div>

                <!-- Info Box Bantuan Dosen & Penguji -->
                <div class="glass-panel p-3 mt-4 text-secondary small">
                    <div class="text-info fw-semibold mb-1">
                        <i class="fa-solid fa-circle-info me-1"></i> Pembuktian Soal UTS (Kunci Simetris & Asimetris):
                    </div>
                    <div><strong>Username:</strong> <code>admin</code></div>
                    <div><strong>Kunci Simetris:</strong> <code>AdminSecure2026!</code></div>
                    <div><strong>Kunci Asimetris:</strong> Tersimpan di <code>storage/keys/private_key.pem</code></div>
                    <div class="mt-2 text-white-50">
                        Klik tombol <strong>"Muat Kunci Pengujian Otomatis"</strong> di atas untuk langsung mengisi kedua kunci pengujian secara instan.
                    </div>
                </div>

            </div>
        </div>
    </div>

    <!-- Bootstrap 5 JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/script.js"></script>
    <script>
        // Helper untuk memuat kunci testing secara otomatis dari file server tanpa mengeksposnya secara publik
        async function loadDefaultTestingKey() {
            try {
                const res = await fetch('crypto/get_test_key.php');
                const data = await res.json();
                if (data.key) {
                    document.getElementById('loginPrivateKey').value = data.key;
                    showCyberToast('Kunci RSA testing berhasil dimuat!', 'success');
                } else {
                    showCyberToast('Gagal memuat kunci testing.', 'danger');
                }
            } catch (e) {
                showCyberToast('Silakan salin kunci dari storage/keys/private_key.pem.', 'info');
            }
        }
    </script>
</body>
</html>
