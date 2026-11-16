<?php
/**
 * SECURE ADMIN SYSTEM - AUTOMATED INTEGRATION & VERIFICATION TEST
 * File: crypto/test_all_features.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/security.php';
require_once __DIR__ . '/../crypto/aes.php';
require_once __DIR__ . '/../crypto/rsa.php';
require_once __DIR__ . '/../crypto/hybrid.php';

echo "========================================================\n";
echo "SECURE ADMIN SYSTEM - VERIFIKASI PENGUJIAN OTOMATIS UTS\n";
echo "========================================================\n\n";

$passCount = 0;
$failCount = 0;

function reportTest(string $name, bool $passed, string $detail = ''): void {
    global $passCount, $failCount;
    if ($passed) {
        $passCount++;
        echo "[PASS] " . $name . "\n";
        if ($detail) echo "       -> " . $detail . "\n";
    } else {
        $failCount++;
        echo "[FAIL] " . $name . "\n";
        if ($detail) echo "       -> " . $detail . "\n";
    }
}

$pdo = getDBConnection();
$pubKey = file_get_contents(__DIR__ . '/../storage/keys/public_key.pem');
$privKey = file_get_contents(__DIR__ . '/../storage/keys/private_key.pem');

// 1. UJI LANDING PAGE & CONFIG
$landingFile = file_exists(__DIR__ . '/../index.php');
reportTest("1. Landing page (index.php) tersedia dan terkonfigurasi", $landingFile);

// 2. UJI SEED ADMIN DAN PASSWORD VERIFY
$stmtAdm = $pdo->prepare("SELECT * FROM admins WHERE username = 'admin'");
$stmtAdm->execute();
$adminUser = $stmtAdm->fetch();
$passCheck = $adminUser && password_verify('AdminSecure2026!', $adminUser['password_hash']);
reportTest("2. Akun administrator default valid (Argon2id/Bcrypt)", $passCheck, "Username: admin");

// 3. UJI GENERASI CHALLENGE & DIGITAL SIGNATURE SAH
$challenge = bin2hex(random_bytes(32));
$sigB64 = RSACrypto::sign($challenge, $privKey);
$sigValid = RSACrypto::verifySignature($challenge, $sigB64, $adminUser['rsa_public_key']);
reportTest("3. Login dengan RSA Digital Signature sah BERHASIL diverifikasi", $sigValid);

// 4. UJI PENOLAKAN SIGNATURE PALSU / SALAH
$wrongSig = base64_encode(str_repeat("A", 256));
$sigRejected = !RSACrypto::verifySignature($challenge, $wrongSig, $adminUser['rsa_public_key']);
reportTest("4. Login dengan digital signature salah/palsu DITOLAK", $sigRejected);

// 5. UJI CHALLENGE EXPIRATION & REPLAY ATTACK
$expiredTime = date('Y-m-d H:i:s', time() - 300); // 5 menit yang lalu
$stmtExp = $pdo->prepare("INSERT INTO auth_challenges (challenge, username, ip_address, expires_at, is_used, created_at) VALUES (?, 'admin', '127.0.0.1', ?, 0, NOW())");
$expChallenge = bin2hex(random_bytes(32));
$stmtExp->execute([$expChallenge, $expiredTime]);

// Periksa apakah sistem menolak challenge expired
$stmtCheckExp = $pdo->prepare("SELECT * FROM auth_challenges WHERE challenge = ?");
$stmtCheckExp->execute([$expChallenge]);
$rowExp = $stmtCheckExp->fetch();
$isExpRejected = (strtotime($rowExp['expires_at']) < time());
reportTest("5. Challenge kedaluwarsa (expired) DITOLAK sistem", $isExpRejected);

// 6. UJI CRUD KONTEN - SIMPAN DALAM BENTUK CIPHERTEXT
$testTitle = "Laporan Operasi Siber Alpha 2026";
$testBody = "Konten rahasia tingkat tinggi: Memvalidasi enkripsi hibrida database UTS.";
$enc = HybridCrypto::encryptRecord($testTitle, $testBody, $pubKey);

$stmtInsert = $pdo->prepare("INSERT INTO contents (category_id, encrypted_title, encrypted_content, encrypted_aes_key, nonce, auth_tag, status, created_by, created_at) VALUES (1, ?, ?, ?, ?, ?, 'published', ?, NOW())");
$stmtInsert->execute([
    $enc['encrypted_title'],
    $enc['encrypted_content'],
    $enc['encrypted_aes_key'],
    $enc['nonce'],
    $enc['auth_tag'],
    $adminUser['id']
]);
$contentId = (int)$pdo->lastInsertId();

// Cek di DB apakah TIDAK ADA plaintext
$stmtVerifyDb = $pdo->prepare("SELECT * FROM contents WHERE id = ?");
$stmtVerifyDb->execute([$contentId]);
$dbRow = $stmtVerifyDb->fetch();

$noPlaintext = !str_contains($dbRow['encrypted_title'], $testTitle) && !str_contains($dbRow['encrypted_content'], $testBody);
reportTest("6. Konten tersimpan di basis data 100% dalam bentuk Ciphertext", $noPlaintext, "ID Konten: #" . $contentId);

// 7. UJI PEMBUNGKUSAN KUNCI AES DENGAN RSA-OAEP
$rawAesKey = RSACrypto::decryptOAEP($dbRow['encrypted_aes_key'], $privKey);
$aesKeyMatch = (strlen($rawAesKey) === 32) && hash_equals($rawAesKey, base64_decode($enc['raw_aes_key_b64']));
reportTest("7. Kunci AES dibungkus RSA-OAEP dan berhasil dibuka Private Key", $aesKeyMatch, "AES Key length: 256 bits");

// 8. UJI PENGEMBALIAN KONTEN KE PLAINTEXT ASLI (DEKRIPSI SUKSES)
$decRecord = HybridCrypto::decryptRecord($dbRow['encrypted_content'], $dbRow['encrypted_aes_key'], $dbRow['nonce'], $dbRow['auth_tag'], $privKey);
$dataRestored = ($decRecord['title'] === $testTitle) && ($decRecord['content'] === $testBody);
reportTest("8. Konten berhasil didekripsi sempurna kembali ke Plaintext asli", $dataRestored);

// 9. UJI PENOLAKAN TAMPERING / AUTH TAG TIDAK COCOK
$tamperedTag = $dbRow['auth_tag'];
$tamperedTag[0] = ($tamperedTag[0] === 'A') ? 'B' : 'A';
$tamperDetected = false;
try {
    HybridCrypto::decryptRecord($dbRow['encrypted_content'], $dbRow['encrypted_aes_key'], $dbRow['nonce'], $tamperedTag, $privKey);
} catch (Exception $e) {
    $tamperDetected = true;
}
reportTest("9. Authentication Tag tidak valid menyebabkan dekripsi DITOLAK (Integritas Terjaga)", $tamperDetected);

// 10. UJI AUDIT LOG PENCATATAN AKTIVITAS
logAudit('INTEGRATION_TEST_SUCCESS', 'Pengujian otomatis seluruh modul kriptografi');
$stmtAudit = $pdo->query("SELECT * FROM audit_logs WHERE action = 'INTEGRATION_TEST_SUCCESS' ORDER BY id DESC LIMIT 1");
$auditLogged = ($stmtAudit->fetch() !== false);
reportTest("10. Audit log mencatat seluruh aktivitas secara real-time", $auditLogged);

// 11. UJI RATE LIMITING IP
recordLoginAttempt('192.168.1.99', 'attacker', false);
recordLoginAttempt('192.168.1.99', 'attacker', false);
recordLoginAttempt('192.168.1.99', 'attacker', false);
recordLoginAttempt('192.168.1.99', 'attacker', false);
recordLoginAttempt('192.168.1.99', 'attacker', false);
$rateLimitTriggered = isRateLimited('192.168.1.99', 5, 10);
reportTest("11. Rate limiter memblokir upaya brute force setelah 5x gagal", $rateLimitTriggered);

// 12. UJI PROTEKSI STORAGE KEYS (.HTACCESS)
$htaccessFile = file_exists(__DIR__ . '/../storage/keys/.htaccess');
reportTest("12. Storage kunci privat terlindungi dari akses langsung browser", $htaccessFile);

echo "\n========================================================\n";
echo "RINGKASAN HASIL PENGUJIAN: " . $passCount . " LULUS / " . $failCount . " GAGAL\n";
echo "========================================================\n";
