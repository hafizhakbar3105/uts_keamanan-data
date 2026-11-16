<?php
/**
 * ============================================================================
 * [TUGAS UTS]: LABORATORIUM DEMONSTRASI KRIPTOGRAFI INTERAKTIF
 * File: encryption.php
 * Demonstrasi Langsung:
 * 1. AES-256-GCM (Simetris): Enkripsi, Nonce, Auth Tag, & Uji Coba Tamper Attack.
 * 2. RSA-PSS (Asimetris): Digital Signature & Verifikasi Tanda Tangan.
 * 3. Hybrid Encryption: Alur gabungan enkripsi konten dan pembungkusan kunci.
 * 4. Key Generator: Pembangkitan pasangan kunci RSA 2048-bit secara instan.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';
require_once __DIR__ . '/crypto/aes.php';
require_once __DIR__ . '/crypto/rsa.php';
require_once __DIR__ . '/crypto/hybrid.php';

sendSecurityHeaders();
requireAuth();

$admin = getCurrentAdmin();
$csrf = generateCSRFToken();

// Load default keys jika ada
$publicKeyPath = __DIR__ . '/storage/keys/public_key.pem';
$privateKeyPath = __DIR__ . '/storage/keys/private_key.pem';
$defaultPubKey = file_exists($publicKeyPath) ? file_get_contents($publicKeyPath) : '';
$defaultPrivKey = file_exists($privateKeyPath) ? file_get_contents($privateKeyPath) : '';
$defaultFingerprint = !empty($defaultPubKey) ? RSACrypto::getFingerprint($defaultPubKey) : 'N/A';

// -------------------------------------------------------------
// AJAX API HANDLER UNTUK DEMONSTRASI REAL-TIME
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['demo'])) {
    header('Content-Type: application/json');
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true) ?? [];
    $csrfToken = (string)($data['csrf_token'] ?? '');

    if (!validateCSRFToken($csrfToken)) {
        echo json_encode(['success' => false, 'message' => 'Token CSRF tidak valid.']);
        exit();
    }

    $demoType = $_GET['demo'];

    try {
        // --- 1. DEMO AES-256-GCM ---
        if ($demoType === 'aes_encrypt') {
            $plain = (string)($data['plaintext'] ?? '');
            if (empty($plain)) {
                throw new InvalidArgumentException('Plaintext tidak boleh kosong.');
            }
            $result = AESCrypto::encrypt($plain);
            logAudit('CRYPTO_DEMO_AES_ENC', 'Demonstrasi AES-256-GCM Encrypt');
            echo json_encode([
                'success'        => true,
                'ciphertext_b64' => $result['ciphertext_b64'],
                'nonce_b64'      => $result['nonce_b64'],
                'tag_b64'        => $result['tag_b64'],
                'key_b64'        => $result['key_b64'],
                'algorithm'      => $result['algorithm'],
            ]);
            exit();
        }

        if ($demoType === 'aes_decrypt') {
            $cipher = (string)($data['ciphertext_b64'] ?? '');
            $nonce  = (string)($data['nonce_b64'] ?? '');
            $tag    = (string)($data['tag_b64'] ?? '');
            $key    = (string)($data['key_b64'] ?? '');

            $decrypted = AESCrypto::decrypt($cipher, $nonce, $tag, $key);
            logAudit('CRYPTO_DEMO_AES_DEC', 'Demonstrasi AES-256-GCM Decrypt Berhasil');
            echo json_encode(['success' => true, 'plaintext' => $decrypted]);
            exit();
        }

        // --- 2. DEMO RSA SIGN & VERIFY ---
        if ($demoType === 'rsa_sign') {
            $challenge = (string)($data['challenge'] ?? '');
            $privKey   = (string)($data['private_key'] ?? $defaultPrivKey);

            if (empty($challenge)) {
                throw new InvalidArgumentException('Challenge string wajib diisi.');
            }
            $sig = RSACrypto::sign($challenge, $privKey);
            logAudit('CRYPTO_DEMO_RSA_SIGN', 'Demonstrasi RSA Digital Signature');
            echo json_encode(['success' => true, 'signature_b64' => $sig]);
            exit();
        }

        if ($demoType === 'rsa_verify') {
            $challenge = (string)($data['challenge'] ?? '');
            $signature = (string)($data['signature_b64'] ?? '');
            $pubKey    = (string)($data['public_key'] ?? $defaultPubKey);

            $isValid = RSACrypto::verifySignature($challenge, $signature, $pubKey);
            logAudit('CRYPTO_DEMO_RSA_VERIFY', 'Demonstrasi Verifikasi Signature: ' . ($isValid ? 'VALID' : 'INVALID'));
            echo json_encode(['success' => true, 'is_valid' => $isValid]);
            exit();
        }

        // --- 3. DEMO HYBRID PIPELINE ---
        if ($demoType === 'hybrid_encrypt') {
            $title   = (string)($data['title'] ?? '');
            $content = (string)($data['content'] ?? '');
            $pubKey  = (string)($data['public_key'] ?? $defaultPubKey);

            if (empty($title) || empty($content)) {
                throw new InvalidArgumentException('Judul dan isi konten harus diisi.');
            }

            $enc = HybridCrypto::encryptRecord($title, $content, $pubKey);
            logAudit('CRYPTO_DEMO_HYBRID_ENC', 'Demonstrasi Hybrid Encryption Pipeline');
            echo json_encode([
                'success'           => true,
                'encrypted_title'   => $enc['encrypted_title'],
                'encrypted_content' => $enc['encrypted_content'],
                'encrypted_aes_key' => $enc['encrypted_aes_key'],
                'nonce'             => $enc['nonce'],
                'auth_tag'          => $enc['auth_tag'],
                'raw_aes_key_b64'   => $enc['raw_aes_key_b64'],
            ]);
            exit();
        }

        if ($demoType === 'hybrid_decrypt') {
            $cipherContent = (string)($data['encrypted_content'] ?? '');
            $cipherKey     = (string)($data['encrypted_aes_key'] ?? '');
            $nonce         = (string)($data['nonce'] ?? '');
            $tag           = (string)($data['auth_tag'] ?? '');
            $privKey       = (string)($data['private_key'] ?? $defaultPrivKey);

            $dec = HybridCrypto::decryptRecord($cipherContent, $cipherKey, $nonce, $tag, $privKey);
            logAudit('CRYPTO_DEMO_HYBRID_DEC', 'Demonstrasi Hybrid Decryption Berhasil');
            echo json_encode([
                'success'         => true,
                'title'           => $dec['title'],
                'content'         => $dec['content'],
                'raw_aes_key_b64' => $dec['raw_aes_key_b64'],
            ]);
            exit();
        }

        // --- 4. DEMO KEYGEN ON THE FLY ---
        if ($demoType === 'generate_keypair') {
            $bits = (int)($data['bits'] ?? 2048);
            $keypair = RSACrypto::generateKeyPair($bits);
            logAudit('CRYPTO_DEMO_KEYGEN', "Membangkitkan pasangan kunci RSA {$bits}-bit baru");
            echo json_encode([
                'success'     => true,
                'public_key'  => $keypair['public_key'],
                'private_key' => $keypair['private_key'],
                'fingerprint' => $keypair['fingerprint'],
                'bits'        => $keypair['bits'],
            ]);
            exit();
        }

        throw new InvalidArgumentException('Tipe demonstrasi tidak dikenali.');
    } catch (Throwable $e) {
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laboratorium Kriptografi - SECURE ADMIN SYSTEM</title>
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
                <a href="encryption.php" class="nav-link active">
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
                <h5 class="fw-bold mb-0 text-white">Laboratorium & Demonstrasi Kriptografi UTS</h5>
            </div>
            <span class="badge badge-glow-cyan code-font">PHP 8.4 OpenSSL ENGINE</span>
        </header>

        <main class="admin-content">
            <input type="hidden" id="demoCsrf" value="<?= e($csrf) ?>">

            <!-- NAV TABS DEMONSTRASI -->
            <ul class="nav nav-pills mb-4 gap-2" id="cryptoTabs">
                <li class="nav-item">
                    <button class="nav-link active btn-cyber-outline" data-bs-toggle="pill" data-bs-target="#tab-hybrid">
                        <i class="fa-solid fa-layer-group me-1"></i> 1. Hybrid Encryption (Utama)
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link btn-cyber-outline" data-bs-toggle="pill" data-bs-target="#tab-aes">
                        <i class="fa-solid fa-lock me-1"></i> 2. AES-256-GCM & Tamper Test
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link btn-cyber-outline" data-bs-toggle="pill" data-bs-target="#tab-rsa">
                        <i class="fa-solid fa-signature me-1"></i> 3. RSA-PSS & Digital Signature
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link btn-cyber-outline" data-bs-toggle="pill" data-bs-target="#tab-keygen">
                        <i class="fa-solid fa-key me-1"></i> 4. Key Generator RSA
                    </button>
                </li>
            </ul>

            <div class="tab-content">
                <!-- ======================================================= -->
                <!-- TAB 1: DEMO HYBRID ENCRYPTION -->
                <!-- ======================================================= -->
                <div class="tab-pane fade show active" id="tab-hybrid">
                    <div class="glass-panel p-4 mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <div>
                                <h5 class="fw-bold mb-0 text-white">Demonstrasi Hybrid Encryption (AES-256-GCM + RSA-OAEP 2048-bit)</h5>
                                <small class="text-secondary">Alur gabungan: Enkripsi konten dengan AES simetris dan pembungkusan kunci AES dengan RSA asimetris.</small>
                            </div>
                            <span class="badge badge-glow-emerald">STANDAR UTS</span>
                        </div>

                        <!-- Visual Workflow Diagram -->
                        <div class="row g-2 mb-4 text-center code-font small">
                            <div class="col-md-3">
                                <div class="p-2 rounded-3 bg-dark border border-info border-opacity-50">
                                    <div class="text-info fw-bold mb-1">1. Ephemeral Key</div>
                                    <div class="text-secondary" style="font-size: 0.75rem;">random_bytes(32) [256-bit]</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="p-2 rounded-3 bg-dark border border-primary border-opacity-50">
                                    <div class="text-primary fw-bold mb-1">2. AES-256-GCM</div>
                                    <div class="text-secondary" style="font-size: 0.75rem;">Ciphertext + 16B Tag</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="p-2 rounded-3 bg-dark border border-warning border-opacity-50">
                                    <div class="text-warning fw-bold mb-1">3. RSA-OAEP Wrap</div>
                                    <div class="text-secondary" style="font-size: 0.75rem;">Public Key Enkripsi AES Key</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="p-2 rounded-3 bg-dark border border-success border-opacity-50">
                                    <div class="text-success fw-bold mb-1">4. Secure Storage</div>
                                    <div class="text-secondary" style="font-size: 0.75rem;">Simpan ke MySQL (0 Plaintext)</div>
                                </div>
                            </div>
                        </div>

                        <div class="row g-4">
                            <!-- Input -->
                            <div class="col-lg-6">
                                <div class="mb-3">
                                    <label class="form-label">Judul Dokumen Rahasia:</label>
                                    <input type="text" id="hybridTitle" class="form-control" value="Strategi Penanggulangan Serangan Siber 2026">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Isi Dokumen Sensitif:</label>
                                    <textarea id="hybridContent" class="form-control" rows="5">Dokumen ini berisi protokol penanganan insiden keamanan siber nasional level kritis, daftar aset server cadangan, serta sertifikat kunci otentikasi pusat komando.</textarea>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Public Key RSA (Untuk Enkripsi Kunci AES):</label>
                                    <textarea id="hybridPubKey" class="form-control code-font" rows="4"><?= e($defaultPubKey) ?></textarea>
                                </div>
                                <button type="button" class="btn btn-cyber w-100 py-2" onclick="runHybridEncrypt()">
                                    <i class="fa-solid fa-lock me-2"></i> Jalankan Enkripsi Hibrida
                                </button>
                            </div>

                            <!-- Hasil Enkripsi & Form Dekripsi -->
                            <div class="col-lg-6">
                                <div id="hybridResultBox" class="p-3 rounded-3 mb-3 d-none" style="background:#f8fafc; border:1px solid #bfdbfe;">
                                    <div class="text-primary fw-bold small mb-2"><i class="fa-solid fa-shield-halved me-1"></i> HASIL ENKRIPSI HIBRIDA:</div>
                                    <div class="mb-2">
                                        <label class="form-label text-warning small mb-0">Encrypted AES Key (RSA-OAEP Base64):</label>
                                        <textarea id="resHybridEncKey" class="form-control code-font small" rows="2" readonly></textarea>
                                    </div>
                                    <div class="row g-2 mb-2">
                                        <div class="col-6">
                                            <label class="form-label text-primary small mb-0">Nonce (96-bit):</label>
                                            <input type="text" id="resHybridNonce" class="form-control code-font small" readonly>
                                        </div>
                                        <div class="col-6">
                                            <label class="form-label text-success small mb-0">Auth Tag (128-bit):</label>
                                            <input type="text" id="resHybridTag" class="form-control code-font small" readonly>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-dark small mb-0">Ciphertext Konten (AES-256-GCM Base64):</label>
                                        <textarea id="resHybridCipher" class="form-control code-font small" rows="3" readonly></textarea>
                                    </div>

                                    <!-- Bagian Dekripsi -->
                                    <div class="pt-2 border-top border-secondary border-opacity-25">
                                        <label class="form-label text-success small mb-1">RSA Private Key untuk Dekripsi:</label>
                                        <textarea id="hybridPrivKey" class="form-control code-font small mb-2" rows="3"><?= e($defaultPrivKey) ?></textarea>
                                        <button type="button" class="btn btn-cyber-outline btn-sm w-100 py-2" onclick="runHybridDecrypt()">
                                            <i class="fa-solid fa-unlock-keyhole me-1"></i> Buka / Dekripsi Kembali Dokumen
                                        </button>
                                    </div>
                                </div>

                                <!-- Box Hasil Dekripsi -->
                                <div id="hybridDecryptedBox" class="p-3 rounded-3 d-none" style="background:#f0fdf4; border:1px solid #bbf7d0;">
                                    <div class="text-success fw-bold small mb-2"><i class="fa-solid fa-circle-check me-1"></i> DOKUMEN BERHASIL DIDEKRIPSI:</div>
                                    <div class="mb-2">
                                        <span class="text-secondary small">Judul Plaintext:</span>
                                        <div id="resDecTitle" class="fw-bold text-dark fs-6"></div>
                                    </div>
                                    <div class="mb-2">
                                        <span class="text-secondary small">Isi Plaintext:</span>
                                        <div id="resDecContent" class="text-dark small p-2 rounded-2 bg-white border border-light"></div>
                                    </div>
                                    <div>
                                        <span class="text-secondary small">Kunci Simetris yang Berhasil Dibuka:</span>
                                        <div id="resDecRawKey" class="code-font text-warning small text-truncate"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ======================================================= -->
                <!-- TAB 2: DEMO AES-256-GCM & TAMPER TEST -->
                <!-- ======================================================= -->
                <div class="tab-pane fade" id="tab-aes">
                    <div class="glass-panel p-4 mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <div>
                                <h5 class="fw-bold mb-0 text-white">Demonstrasi AES-256-GCM & Uji Integritas (Anti-Tampering)</h5>
                                <small class="text-secondary">Uji langsung bahwa modifikasi sekecil 1 bit pada ciphertext atau tag akan menyebabkan dekripsi ditolak secara mutlak.</small>
                            </div>
                            <span class="badge badge-glow-cyan">AEAD GCM</span>
                        </div>

                        <div class="row g-4">
                            <div class="col-lg-6">
                                <div class="mb-3">
                                    <label class="form-label">Plaintext Uji Coba:</label>
                                    <textarea id="aesPlainInput" class="form-control" rows="4">Kerahasiaan Negara: Koordinat Bunker Alpha 106.8456, -6.2088. Kode Otorisasi: 984712-XZ.</textarea>
                                </div>
                                <button type="button" class="btn btn-cyber w-100 py-2 mb-3" onclick="runAESEncrypt()">
                                    <i class="fa-solid fa-lock me-1"></i> Enkripsi dengan AES-256-GCM
                                </button>

                                <div class="p-3 rounded-3" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255,255,255,0.06);">
                                    <div class="text-info fw-semibold small mb-2"><i class="fa-solid fa-microscope me-1"></i> Simulasi Serangan Manipulasi (Tamper Attack):</div>
                                    <p class="text-secondary small mb-2">
                                        Klik tombol di bawah untuk merusak 1 karakter ciphertext sebelum didekripsi. Ini membuktikan bahwa sistem AEAD tidak akan memproses data yang rusak atau disusupi.
                                    </p>
                                    <button type="button" class="btn btn-outline-danger btn-sm w-100" onclick="tamperCiphertext()">
                                        <i class="fa-solid fa-bug me-1"></i> Rusak Ciphertext (Simulasi Manipulasi Hacker)
                                    </button>
                                </div>
                            </div>

                            <div class="col-lg-6">
                                <div class="mb-2">
                                    <label class="form-label text-warning small mb-0">AES Key (256-bit Base64):</label>
                                    <input type="text" id="aesKeyOutput" class="form-control code-font small" readonly>
                                </div>
                                <div class="row g-2 mb-2">
                                    <div class="col-6">
                                        <label class="form-label text-info small mb-0">Nonce (96-bit Base64):</label>
                                        <input type="text" id="aesNonceOutput" class="form-control code-font small" readonly>
                                    </div>
                                    <div class="col-6">
                                        <label class="form-label text-success small mb-0">Auth Tag (128-bit Base64):</label>
                                        <input type="text" id="aesTagOutput" class="form-control code-font small" readonly>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label text-light small mb-0">Ciphertext (Base64):</label>
                                    <textarea id="aesCipherOutput" class="form-control code-font small" rows="3"></textarea>
                                </div>

                                <button type="button" class="btn btn-cyber-outline w-100 py-2 mb-3" onclick="runAESDecrypt()">
                                    <i class="fa-solid fa-unlock-keyhole me-1"></i> Uji Dekripsi & Verifikasi Tag
                                </button>

                                <div id="aesDecryptedResult" class="p-3 rounded-3 d-none">
                                    <div id="aesDecryptedStatus" class="fw-bold small mb-1"></div>
                                    <div id="aesDecryptedText" class="code-font small"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ======================================================= -->
                <!-- TAB 3: DEMO RSA DIGITAL SIGNATURE -->
                <!-- ======================================================= -->
                <div class="tab-pane fade" id="tab-rsa">
                    <div class="glass-panel p-4 mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <div>
                                <h5 class="fw-bold mb-0 text-white">Demonstrasi RSA-PSS Digital Signature & Challenge-Response</h5>
                                <small class="text-secondary">Simulasi autentikasi kriptografis: Server memberikan random token dan ditandatangani secara digital.</small>
                            </div>
                            <span class="badge badge-glow-rose">RSA-PSS SHA-256</span>
                        </div>

                        <div class="row g-4">
                            <div class="col-lg-6">
                                <div class="mb-3">
                                    <div class="d-flex justify-content-between align-items-center mb-1">
                                        <label class="form-label mb-0">Random Server Challenge:</label>
                                        <button type="button" class="btn btn-link btn-sm text-info text-decoration-none p-0" onclick="generateNewChallenge()">
                                            <i class="fa-solid fa-arrows-rotate me-1"></i> Generate Acak Baru
                                        </button>
                                    </div>
                                    <input type="text" id="rsaChallenge" class="form-control code-font" value="<?= bin2hex(random_bytes(32)) ?>">
                                </div>

                                <div class="mb-3">
                                    <label class="form-label">RSA Private Key Penandatangan (Signer):</label>
                                    <textarea id="rsaPrivKeySign" class="form-control code-font small" rows="5"><?= e($defaultPrivKey) ?></textarea>
                                </div>

                                <button type="button" class="btn btn-cyber w-100 py-2 mb-3" onclick="runRSASign()">
                                    <i class="fa-solid fa-signature me-1"></i> Tandatangani Challenge (Sign Data)
                                </button>
                            </div>

                            <div class="col-lg-6">
                                <div class="mb-3">
                                    <label class="form-label text-warning small mb-0">Digital Signature (Base64):</label>
                                    <textarea id="rsaSignatureOutput" class="form-control code-font small" rows="4"></textarea>
                                </div>

                                <div class="mb-3">
                                    <label class="form-label text-info small mb-0">RSA Public Key Verifier:</label>
                                    <textarea id="rsaPubKeyVerify" class="form-control code-font small" rows="4"><?= e($defaultPubKey) ?></textarea>
                                </div>

                                <button type="button" class="btn btn-cyber-outline w-100 py-2 mb-3" onclick="runRSAVerify()">
                                    <i class="fa-solid fa-certificate me-1"></i> Verifikasi Signature dengan Public Key
                                </button>

                                <div id="rsaVerifyResult" class="p-3 rounded-3 d-none">
                                    <div id="rsaVerifyStatus" class="fw-bold"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ======================================================= -->
                <!-- TAB 4: DEMO KEY GENERATOR RSA -->
                <!-- ======================================================= -->
                <div class="tab-pane fade" id="tab-keygen">
                    <div class="glass-panel p-4 mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <div>
                                <h5 class="fw-bold mb-0 text-white">Generator Pasangan Kunci RSA (Keypair Generator)</h5>
                                <small class="text-secondary">Pembangkitan pasangan kunci RSA 2048-bit atau 4096-bit secara real-time via PHP OpenSSL.</small>
                            </div>
                            <span class="badge badge-glow-cyan">OPENSSL KEYGEN</span>
                        </div>

                        <div class="row g-4 align-items-center mb-4">
                            <div class="col-md-4">
                                <label class="form-label">Panjang Bit Kunci:</label>
                                <select id="keygenBits" class="form-select">
                                    <option value="2048" selected>2048-bit (Standar Standar Industri & UTS)</option>
                                    <option value="4096">4096-bit (Ultra Secure High Entropy)</option>
                                </select>
                            </div>
                            <div class="col-md-4 pt-md-4">
                                <button type="button" id="btnRunKeygen" class="btn btn-cyber w-100" onclick="runKeyGenerator()">
                                    <i class="fa-solid fa-wand-magic-sparkles me-1"></i> Generate Kunci Baru Sekarang
                                </button>
                            </div>
                            <div class="col-md-4 pt-md-4 text-secondary small">
                                <i class="fa-solid fa-circle-info text-info me-1"></i> Kunci dihasilkan menggunakan entropi sistem operasi dan diekspor dalam format PEM PKCS#8.
                            </div>
                        </div>

                        <div class="row g-4">
                            <div class="col-lg-6">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <label class="form-label mb-0 text-success"><i class="fa-solid fa-key me-1"></i> RSA Public Key:</label>
                                    <button class="btn btn-link btn-sm text-info p-0 text-decoration-none" onclick="copyToClipboard(document.getElementById('resKeygenPub').value, this)">
                                        <i class="fa-solid fa-copy me-1"></i> Salin
                                    </button>
                                </div>
                                <textarea id="resKeygenPub" class="form-control code-font small" rows="9" readonly><?= e($defaultPubKey) ?></textarea>
                                <div class="mt-2 text-secondary small">
                                    Fingerprint (SHA-256): <span id="resKeygenFingerprint" class="code-font text-info"><?= e($defaultFingerprint) ?></span>
                                </div>
                            </div>

                            <div class="col-lg-6">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <label class="form-label mb-0 text-warning"><i class="fa-solid fa-file-shield me-1"></i> RSA Private Key (Sensitif):</label>
                                    <button class="btn btn-link btn-sm text-info p-0 text-decoration-none" onclick="copyToClipboard(document.getElementById('resKeygenPriv').value, this)">
                                        <i class="fa-solid fa-copy me-1"></i> Salin
                                    </button>
                                </div>
                                <textarea id="resKeygenPriv" class="form-control code-font small" rows="9" readonly><?= e($defaultPrivKey) ?></textarea>
                                <div class="mt-2 text-danger small">
                                    <i class="fa-solid fa-triangle-exclamation me-1"></i> Jangan bagikan Private Key kepada pihak lain.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </main>
    </div>
</div>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/script.js"></script>
<script>
const csrf = document.getElementById('demoCsrf').value;

// 1. DEMO HYBRID
async function runHybridEncrypt() {
    const title = document.getElementById('hybridTitle').value;
    const content = document.getElementById('hybridContent').value;
    const pubKey = document.getElementById('hybridPubKey').value;

    try {
        const res = await fetch('encryption.php?demo=hybrid_encrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ title, content, public_key: pubKey, csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        document.getElementById('resHybridEncKey').value = data.encrypted_aes_key;
        document.getElementById('resHybridNonce').value = data.nonce;
        document.getElementById('resHybridTag').value = data.auth_tag;
        document.getElementById('resHybridCipher').value = data.encrypted_content;
        document.getElementById('hybridResultBox').classList.remove('d-none');
        document.getElementById('hybridDecryptedBox').classList.add('d-none');
        showCyberToast('Enkripsi Hibrida Berhasil!', 'success');
    } catch (e) {
        showCyberToast(e.message, 'danger');
    }
}

async function runHybridDecrypt() {
    const encryptedContent = document.getElementById('resHybridCipher').value;
    const encryptedAesKey = document.getElementById('resHybridEncKey').value;
    const nonce = document.getElementById('resHybridNonce').value;
    const authTag = document.getElementById('resHybridTag').value;
    const privKey = document.getElementById('hybridPrivKey').value;

    try {
        const res = await fetch('encryption.php?demo=hybrid_decrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                encrypted_content: encryptedContent,
                encrypted_aes_key: encryptedAesKey,
                nonce: nonce,
                auth_tag: authTag,
                private_key: privKey,
                csrf_token: csrf
            })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        document.getElementById('resDecTitle').innerText = data.title;
        document.getElementById('resDecContent').innerText = data.content;
        document.getElementById('resDecRawKey').innerText = data.raw_aes_key_b64;
        document.getElementById('hybridDecryptedBox').classList.remove('d-none');
        showCyberToast('Dekripsi Berhasil & Integritas Terverifikasi!', 'success');
    } catch (e) {
        showCyberToast(e.message, 'danger');
    }
}

// 2. DEMO AES
async function runAESEncrypt() {
    const plain = document.getElementById('aesPlainInput').value;
    try {
        const res = await fetch('encryption.php?demo=aes_encrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ plaintext: plain, csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        document.getElementById('aesKeyOutput').value = data.key_b64;
        document.getElementById('aesNonceOutput').value = data.nonce_b64;
        document.getElementById('aesTagOutput').value = data.tag_b64;
        document.getElementById('aesCipherOutput').value = data.ciphertext_b64;
        document.getElementById('aesDecryptedResult').classList.add('d-none');
        showCyberToast('AES-256-GCM Enkripsi Berhasil!', 'success');
    } catch(e) {
        showCyberToast(e.message, 'danger');
    }
}

async function runAESDecrypt() {
    const cipher = document.getElementById('aesCipherOutput').value;
    const nonce = document.getElementById('aesNonceOutput').value;
    const tag = document.getElementById('aesTagOutput').value;
    const key = document.getElementById('aesKeyOutput').value;
    const box = document.getElementById('aesDecryptedResult');
    const status = document.getElementById('aesDecryptedStatus');
    const text = document.getElementById('aesDecryptedText');

    box.classList.remove('d-none');

    try {
        const res = await fetch('encryption.php?demo=aes_decrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ciphertext_b64: cipher, nonce_b64: nonce, tag_b64: tag, key_b64: key, csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        box.className = 'p-3 rounded-3 bg-dark border border-success';
        status.className = 'text-success fw-bold small mb-1';
        status.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> DEKRIPSI SUKSES & INTEGRITAS DATA TERJAMIN';
        text.innerText = data.plaintext;
        showCyberToast('Data asli berhasil dibuka!', 'success');
    } catch(e) {
        box.className = 'p-3 rounded-3 bg-dark border border-danger';
        status.className = 'text-danger fw-bold small mb-1';
        status.innerHTML = '<i class="fa-solid fa-circle-xmark me-1"></i> DEKRIPSI DITOLAK (INTEGRITAS RUSAK / TAMPERED)';
        text.innerText = e.message;
        showCyberToast('Integritas data rusak! Dekripsi ditolak.', 'danger');
    }
}

function tamperCiphertext() {
    const cipherEl = document.getElementById('aesCipherOutput');
    if (!cipherEl.value) {
        showCyberToast('Silakan enkripsi teks terlebih dahulu sebelum merusaknya.', 'warning');
        return;
    }
    let val = cipherEl.value;
    val = val.substring(0, 4) + (val[4] === 'X' ? 'Y' : 'X') + val.substring(5);
    cipherEl.value = val;
    showCyberToast('Ciphertext berhasil dirusak (1 karakter diubah). Coba klik Dekripsi!', 'warning');
}

// 3. DEMO RSA SIGN & VERIFY
function generateNewChallenge() {
    const hex = [...Array(64)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    document.getElementById('rsaChallenge').value = hex;
}

async function runRSASign() {
    const challenge = document.getElementById('rsaChallenge').value;
    const privKey = document.getElementById('rsaPrivKeySign').value;

    try {
        const res = await fetch('encryption.php?demo=rsa_sign', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ challenge, private_key: privKey, csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        document.getElementById('rsaSignatureOutput').value = data.signature_b64;
        showCyberToast('Tanda Tangan Digital Berhasil Dibuat!', 'success');
    } catch(e) {
        showCyberToast(e.message, 'danger');
    }
}

async function runRSAVerify() {
    const challenge = document.getElementById('rsaChallenge').value;
    const sig = document.getElementById('rsaSignatureOutput').value;
    const pubKey = document.getElementById('rsaPubKeyVerify').value;
    const box = document.getElementById('rsaVerifyResult');
    const status = document.getElementById('rsaVerifyStatus');

    box.classList.remove('d-none');

    try {
        const res = await fetch('encryption.php?demo=rsa_verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ challenge, signature_b64: sig, public_key: pubKey, csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        if (data.is_valid) {
            box.className = 'p-3 rounded-3 bg-dark border border-success';
            status.className = 'text-success';
            status.innerHTML = '<i class="fa-solid fa-circle-check me-2"></i> DIGITAL SIGNATURE VALID & SAH (VERIFIED)';
        } else {
            box.className = 'p-3 rounded-3 bg-dark border border-danger';
            status.className = 'text-danger';
            status.innerHTML = '<i class="fa-solid fa-circle-xmark me-2"></i> SIGNATURE TIDAK VALID (Tanda tangan palsu atau Public Key tidak cocok)';
        }
    } catch(e) {
        box.className = 'p-3 rounded-3 bg-dark border border-danger';
        status.className = 'text-danger';
        status.innerText = e.message;
    }
}

// 4. DEMO KEYGEN
async function runKeyGenerator() {
    const bits = document.getElementById('keygenBits').value;
    const btn = document.getElementById('btnRunKeygen');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Membangkitkan...';

    try {
        const res = await fetch('encryption.php?demo=generate_keypair', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ bits: parseInt(bits), csrf_token: csrf })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        document.getElementById('resKeygenPub').value = data.public_key;
        document.getElementById('resKeygenPriv').value = data.private_key;
        document.getElementById('resKeygenFingerprint').innerText = data.fingerprint;
        showCyberToast(`Kunci RSA ${bits}-bit baru berhasil dibuat!`, 'success');
    } catch(e) {
        showCyberToast(e.message, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles me-1"></i> Generate Kunci Baru Sekarang';
    }
}
</script>
</body>
</html>
