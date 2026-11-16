<?php
/**
 * ============================================================================
 * [TUGAS UTS - BUTIR 1]: LANDING PAGE UNTUK MASUK KE HALAMAN ADMIN
 * File: index.php
 * Fungsi: Halaman utama publik yang memperkenalkan sistem dan menyediakan
 *         gerbang tombol masuk menuju halaman login administrator.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/security.php';
sendSecurityHeaders(); // Mengirim header pengaman (X-Frame-Options, CSP, XSS protection)
startSecureSession();  // Memulai session aman berbasis HttpOnly & SameSite=Strict
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SECURE ADMIN SYSTEM - Protecting Data, Empowering Trust</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Google Fonts (Inter & JetBrains Mono) -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <!-- Font Awesome 6 Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Custom Cyber CSS -->
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg cyber-navbar">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <div class="stat-icon badge-glow-cyan p-2 rounded-3 me-2">
                    <i class="fa-solid fa-shield-halved text-primary fs-4"></i>
                </div>
                <div>
                    <span class="gradient-text tracking-wide">SECURE ADMIN</span>
                    <span class="d-block text-secondary small fw-normal" style="font-size: 0.68rem; letter-spacing: 1px;">SYSTEM 2026</span>
                </div>
            </a>
            
            <button class="navbar-toggler border-0 text-white" type="button" data-bs-toggle="collapse" data-bs-target="#navContent">
                <i class="fa-solid fa-bars fs-4"></i>
            </button>

            <div class="collapse navbar-collapse" id="navContent">
                <ul class="navbar-nav ms-auto align-items-lg-center gap-3">
                    <li class="nav-item">
                        <a class="nav-link text-light opacity-75" href="#features">Keamanan</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-light opacity-75" href="#cryptography">Kriptografi</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-light opacity-75" href="#architecture">Arsitektur</a>
                    </li>
                    <li class="nav-item ms-lg-2">
                        <?php if (isLoggedIn()): ?>
                            <a href="dashboard.php" class="btn btn-cyber">
                                <i class="fa-solid fa-gauge-high"></i> Buka Dashboard
                            </a>
                        <?php else: ?>
                            <a href="login.php" class="btn btn-cyber">
                                <i class="fa-solid fa-lock"></i> Access Admin Panel
                            </a>
                        <?php endif; ?>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- HERO SECTION -->
    <header class="py-5 my-lg-4">
        <div class="container py-4">
            <div class="row align-items-center gy-5">
                <div class="col-lg-7">
                    <div class="d-inline-flex align-items-center gap-2 px-3 py-1 rounded-pill badge-glow-cyan mb-4">
                        <i class="fa-solid fa-fingerprint text-primary"></i>
                        <span class="small fw-semibold">UTS Keamanan Data & Sistem Informasi</span>
                    </div>

                    <h1 class="display-4 fw-bold mb-3">
                        Secure Information <br>
                        <span class="gradient-text">Management System</span>
                    </h1>

                    <p class="fs-5 text-secondary mb-4 col-lg-11">
                        Sistem informasi manajemen konten enterprise yang mengintegrasikan kriptografi simetris <strong>AES-256-GCM</strong>, proteksi kunci <strong>RSA-OAEP 2048-bit</strong>, dan autentikasi berbasis digital signature <strong>RSA-PSS</strong> untuk menjamin kerahasiaan, integritas, dan non-repudiation.
                    </p>

                    <div class="d-flex flex-wrap gap-3 pt-2">
                        <a href="login.php" class="btn btn-cyber px-4 py-3">
                            <i class="fa-solid fa-arrow-right-to-bracket"></i> Access Admin Panel
                        </a>
                        <a href="#cryptography" class="btn btn-cyber-outline px-4 py-3">
                            <i class="fa-solid fa-microchip"></i> Pelajari Kriptografi
                        </a>
                    </div>

                    <div class="row g-4 mt-4 pt-3 border-top border-secondary border-opacity-25 col-lg-11">
                        <div class="col-4">
                            <div class="text-white fw-bold fs-4">256-bit</div>
                            <div class="text-secondary small">AES-GCM Encryption</div>
                        </div>
                        <div class="col-4">
                            <div class="text-white fw-bold fs-4">2048-bit</div>
                            <div class="text-secondary small">RSA Key Security</div>
                        </div>
                        <div class="col-4">
                            <div class="text-white fw-bold fs-4">Zero-Raw</div>
                            <div class="text-secondary small">Plaintext in Database</div>
                        </div>
                    </div>
                </div>

                <div class="col-lg-5">
                    <div class="glass-panel p-4 position-relative">
                        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
                            <div class="d-flex align-items-center gap-2">
                                <span class="spinner-grow spinner-grow-sm text-info"></span>
                                <span class="code-font small text-info">SYSTEM STATUS: ARMED</span>
                            </div>
                            <span class="badge bg-dark text-secondary border border-secondary border-opacity-25 code-font">PHP 8.4 OpenSSL</span>
                        </div>

                        <!-- Visual Security Monitor Mockup -->
                        <div class="p-3 rounded-3 mb-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                            <div class="d-flex justify-content-between text-secondary small mb-1">
                                <span>Algoritma Simetris:</span>
                                <span class="text-dark fw-semibold">AES-256-GCM (AEAD)</span>
                            </div>
                            <div class="d-flex justify-content-between text-secondary small mb-1">
                                <span>Algoritma Asimetris:</span>
                                <span class="text-dark fw-semibold">RSA-OAEP (SHA-256)</span>
                            </div>
                            <div class="d-flex justify-content-between text-secondary small mb-1">
                                <span>Autentikasi Signer:</span>
                                <span class="text-dark fw-semibold">RSA-PSS Challenge-Response</span>
                            </div>
                            <div class="d-flex justify-content-between text-secondary small">
                                <span>Anti-Tampering:</span>
                                <span class="text-success fw-semibold"><i class="fa-solid fa-check-circle"></i> 128-bit Auth Tag</span>
                            </div>
                        </div>

                        <!-- Interactive Terminal Snippet Preview -->
                        <div class="code-font small p-3 rounded-3" style="background: #0f172a; color: #38bdf8; border: 1px solid #1e293b;">
                            <div class="text-secondary mb-1">// Zero-Knowledge Cryptographic Pipeline</div>
                            <div>$key = random_bytes(32); <span class="text-secondary">// 256-bit</span></div>
                            <div>$cipher = openssl_encrypt($data, 'aes-256-gcm', ...);</div>
                            <div>$encKey = openssl_public_encrypt($key, ..., RSA_OAEP);</div>
                            <div class="text-success mt-2"><i class="fa-solid fa-shield"></i> Database Payload: 100% Encrypted</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <!-- SECTION KRIPTOGRAFI TIGA PILAR -->
    <section id="cryptography" class="py-5">
        <div class="container py-4">
            <div class="text-center mb-5">
                <span class="badge badge-glow-cyan px-3 py-1 rounded-pill mb-2">Defense in Depth</span>
                <h2 class="display-6 fw-bold">Tiga Pilar Kriptografi Aplikasi</h2>
                <p class="text-secondary col-md-7 mx-auto">
                    Kombinasi standar internasional yang dirancang untuk mencegah eksfiltrasi data, tampering, dan serangan replay.
                </p>
            </div>

            <div class="row g-4">
                <!-- CARD 1: AES-256-GCM -->
                <div class="col-lg-4">
                    <div class="glass-panel p-4 h-100 d-flex flex-column">
                        <div class="stat-icon badge-glow-cyan p-3 rounded-4 mb-4">
                            <i class="fa-solid fa-lock text-primary fs-3"></i>
                        </div>
                        <h4 class="fw-bold mb-2">AES-256-GCM</h4>
                        <div class="text-info small fw-semibold mb-3">Enkripsi Simetris Berotentikasi (AEAD)</div>
                        <p class="text-secondary small mb-4 flex-grow-1">
                            Galois/Counter Mode (GCM) menghasilkan ciphertext berkecepatan tinggi sekaligus memproduksi <strong>16-byte Authentication Tag</strong>. Tag ini memverifikasi bahwa data tidak pernah diubah atau dimanipulasi selama penyimpanan di database.
                        </p>
                        <ul class="list-unstyled small text-light mb-0 pt-3 border-top border-secondary border-opacity-25">
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-info me-2"></i> Kunci Simetris 256-bit acak per-konten</li>
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-info me-2"></i> Nonce unik 96-bit (Anti-Replay)</li>
                            <li><i class="fa-solid fa-circle-check text-info me-2"></i> Perlindungan integritas data otomatis</li>
                        </ul>
                    </div>
                </div>

                <!-- CARD 2: RSA-OAEP -->
                <div class="col-lg-4">
                    <div class="glass-panel p-4 h-100 d-flex flex-column">
                        <div class="stat-icon badge-glow-emerald p-3 rounded-4 mb-4">
                            <i class="fa-solid fa-key text-success fs-3"></i>
                        </div>
                        <h4 class="fw-bold mb-2">RSA-OAEP</h4>
                        <div class="text-success small fw-semibold mb-3">Key Wrapping Asimetris 2048-bit</div>
                        <p class="text-secondary small mb-4 flex-grow-1">
                            Optimal Asymmetric Encryption Padding (OAEP) dengan fungsi hash SHA-256 digunakan untuk membungkus kunci AES simetris. Kunci AES tidak disimpan mentah, melainkan hanya dapat didekripsi menggunakan <strong>Private Key RSA</strong> yang sah.
                        </p>
                        <ul class="list-unstyled small text-light mb-0 pt-3 border-top border-secondary border-opacity-25">
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-success me-2"></i> Kekuatan kunci minimal 2048-bit</li>
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-success me-2"></i> Kebal serangan Chosen-Ciphertext (IND-CCA2)</li>
                            <li><i class="fa-solid fa-circle-check text-success me-2"></i> Public Key untuk kunci, Private Key untuk buka</li>
                        </ul>
                    </div>
                </div>

                <!-- CARD 3: RSA-PSS -->
                <div class="col-lg-4">
                    <div class="glass-panel p-4 h-100 d-flex flex-column">
                        <div class="stat-icon badge-glow-rose p-3 rounded-4 mb-4">
                            <i class="fa-solid fa-signature text-danger fs-3"></i>
                        </div>
                        <h4 class="fw-bold mb-2">RSA-PSS</h4>
                        <div class="text-danger small fw-semibold mb-3">Tanda Tangan Digital & Login Challenge</div>
                        <p class="text-secondary small mb-4 flex-grow-1">
                            Probabilistic Signature Scheme (PSS) dengan SHA-256 menyediakan mekanisme pembuktian identitas admin. Browser menandatangani <strong>time-limited challenge</strong> dari server menggunakan Web Crypto API tanpa mengirimkan Private Key ke internet.
                        </p>
                        <ul class="list-unstyled small text-light mb-0 pt-3 border-top border-secondary border-opacity-25">
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-danger me-2"></i> Autentikasi Zero-Knowledge (Client-side)</li>
                            <li class="mb-2"><i class="fa-solid fa-circle-check text-danger me-2"></i> Single-use nonce & expiration time</li>
                            <li><i class="fa-solid fa-circle-check text-danger me-2"></i> Verifikasi kriptografis via PHP OpenSSL</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION ARSITEKTUR HYBRID & KEAMANAN -->
    <section id="architecture" class="py-5" style="background: #f1f5f9;">
        <div class="container py-4">
            <div class="row align-items-center gy-5">
                <div class="col-lg-6">
                    <span class="badge badge-glow-cyan px-3 py-1 rounded-pill mb-2">Sistem End-to-End</span>
                    <h3 class="h2 fw-bold mb-3">Bagaimana Data Anda Dilindungi?</h3>
                    <p class="text-secondary mb-4">
                        Setiap konten yang dibuat di Admin Panel diproses melalui pipeline kriptografi bertingkat sebelum menyentuh media penyimpanan:
                    </p>

                    <div class="d-flex gap-3 mb-3">
                        <div class="stat-icon badge-glow-cyan rounded-3 p-3 flex-shrink-0" style="width:44px; height:44px;">
                            <span class="fw-bold text-primary">1</span>
                        </div>
                        <div>
                            <h6 class="text-dark fw-semibold mb-1">Generate Kunci Ephemeral</h6>
                            <p class="text-secondary small mb-0">Sistem menghasilkan AES key 256-bit dan Nonce acak baru menggunakan generator entropi sistem operasi (<code>random_bytes</code>).</p>
                        </div>
                    </div>

                    <div class="d-flex gap-3 mb-3">
                        <div class="stat-icon badge-glow-cyan rounded-3 p-3 flex-shrink-0" style="width:44px; height:44px;">
                            <span class="fw-bold text-primary">2</span>
                        </div>
                        <div>
                            <h6 class="text-dark fw-semibold mb-1">Enkripsi Data dengan AES-256-GCM</h6>
                            <p class="text-secondary small mb-0">Judul dan isi konten dienkripsi menjadi ciphertext tidak terbaca dan menghasilkan Authentication Tag integritas 128-bit.</p>
                        </div>
                    </div>

                    <div class="d-flex gap-3 mb-3">
                        <div class="stat-icon badge-glow-cyan rounded-3 p-3 flex-shrink-0" style="width:44px; height:44px;">
                            <span class="fw-bold text-primary">3</span>
                        </div>
                        <div>
                            <h6 class="text-dark fw-semibold mb-1">Pembungkusan Kunci dengan RSA-OAEP</h6>
                            <p class="text-secondary small mb-0">Kunci AES dibungkus secara asimetris menggunakan Public Key. Kunci AES mentah segera dihapus dari memori volatil.</p>
                        </div>
                    </div>

                    <div class="d-flex gap-3">
                        <div class="stat-icon badge-glow-cyan rounded-3 p-3 flex-shrink-0" style="width:44px; height:44px;">
                            <span class="fw-bold text-primary">4</span>
                        </div>
                        <div>
                            <h6 class="text-dark fw-semibold mb-1">Penyimpanan Ciphertext & Audit Trail</h6>
                            <p class="text-secondary small mb-0">Hanya ciphertext, nonce, dan tag yang tersimpan di MySQL. Seluruh aktivitas tercatat di tabel audit log yang tidak dapat dihapus.</p>
                        </div>
                    </div>
                </div>

                <div class="col-lg-6">
                    <div class="glass-panel p-4">
                        <div class="d-flex align-items-center justify-content-between mb-4 pb-2 border-bottom border-secondary border-opacity-25">
                            <h5 class="fw-bold mb-0 text-dark"><i class="fa-solid fa-list-check text-info me-2"></i> Standar Keamanan Sistem</h5>
                            <span class="badge bg-success bg-opacity-10 text-success border border-success border-opacity-50">Compliant</span>
                        </div>

                        <div class="row g-3">
                            <div class="col-sm-6">
                                <div class="p-3 rounded-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                                    <div class="text-primary fw-semibold small mb-1"><i class="fa-solid fa-database me-1"></i> PDO Prepared Stmt</div>
                                    <div class="text-secondary small">Perlindungan 100% dari SQL Injection pada seluruh query.</div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="p-3 rounded-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                                    <div class="text-primary fw-semibold small mb-1"><i class="fa-solid fa-shield-virus me-1"></i> CSRF & XSS Filter</div>
                                    <div class="text-secondary small">Validasi token cryptographically secure dan output escaping.</div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="p-3 rounded-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                                    <div class="text-primary fw-semibold small mb-1"><i class="fa-solid fa-clock-rotate-left me-1"></i> Rate Limiting</div>
                                    <div class="text-secondary small">Pencegahan serangan brute-force login berbasis IP address.</div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="p-3 rounded-3" style="background: #f8fafc; border: 1px solid #e2e8f0;">
                                    <div class="text-primary fw-semibold small mb-1"><i class="fa-solid fa-cookie-bite me-1"></i> Secure Session</div>
                                    <div class="text-secondary small">Cookie HttpOnly, SameSite=Strict, anti-hijacking tracking.</div>
                                </div>
                            </div>
                        </div>

                        <div class="mt-4 p-3 rounded-3 text-center" style="background: #eff6ff; border: 1px dashed #bfdbfe;">
                            <span class="text-secondary small">Siap menguji sistem keamanan?</span>
                            <div class="mt-2">
                                <a href="login.php" class="btn btn-cyber btn-sm">
                                    <i class="fa-solid fa-right-to-bracket me-1"></i> Masuk ke Panel Administrator
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- FOOTER -->
    <footer class="py-4 border-top border-secondary border-opacity-25 mt-5">
        <div class="container d-flex flex-column flex-md-row justify-content-between align-items-center gap-3">
            <div class="text-secondary small">
                &copy; <?= date('Y') ?> <strong>SECURE ADMIN SYSTEM</strong> &bull; UTS Keamanan Data dan Sistem Informasi.
            </div>
            <div class="d-flex align-items-center gap-3 text-secondary small">
                <span><i class="fa-solid fa-shield-halved text-info"></i> AES-256-GCM</span>
                <span>&bull;</span>
                <span><i class="fa-solid fa-key text-success"></i> RSA-OAEP</span>
                <span>&bull;</span>
                <span><i class="fa-solid fa-signature text-danger"></i> RSA-PSS</span>
            </div>
        </div>
    </footer>

    <!-- Bootstrap 5 JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/script.js"></script>
</body>
</html>
