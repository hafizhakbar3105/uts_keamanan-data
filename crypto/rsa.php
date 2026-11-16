<?php
/**
 * ============================================================================
 * [TUGAS UTS]: MODUL KRIPTOGRAFI ASIMETRIS (RSA-OAEP & RSA-PSS)
 * File: crypto/rsa.php
 * Standar: RSA 2048-bit dengan SHA-256
 * Karakteristik:
 * 1. RSA-OAEP: Enkripsi asimetris untuk membungkus (wrap) ephemeral AES key.
 * 2. RSA-PSS / RSASSA: Pembuatan & verifikasi tanda tangan digital untuk login.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/security.php';

class RSACrypto
{
    public const DEFAULT_KEY_BITS = 2048;
    public const HASH_ALGO         = 'sha256';

    /**
     * Membangkitkan pasangan kunci RSA baru (minimal 2048-bit).
     *
     * @param int $keyBits Panjang bit kunci (default 2048)
     * @param string|null $passphrase Passphrase pelindung private key (opsional)
     * @return array [private_key, public_key, fingerprint, bits]
     * @throws Exception
     */
    public static function generateKeyPair(int $keyBits = self::DEFAULT_KEY_BITS, ?string $passphrase = null): array
    {
        $startTime = microtime(true);

        if ($keyBits < 2048) {
            throw new InvalidArgumentException('Standar keamanan mewajibkan ukuran RSA minimal 2048-bit.');
        }

        $config = [
            'digest_alg'       => self::HASH_ALGO,
            'private_key_bits' => $keyBits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $cnf = getenv('OPENSSL_CONF');
        if ($cnf && file_exists($cnf)) {
            $config['config'] = $cnf;
        }

        $res = openssl_pkey_new($config);
        if (!$res) {
            $err = openssl_error_string() ?: 'Gagal membuat pasangan kunci RSA';
            throw new RuntimeException($err);
        }

        $privKey = '';
        if (!empty($passphrase)) {
            openssl_pkey_export($res, $privKey, $passphrase, $config);
        } else {
            openssl_pkey_export($res, $privKey, null, $config);
        }

        $details = openssl_pkey_get_details($res);
        $pubKey  = $details['key'];

        $privKey = str_replace("\r\n", "\n", trim($privKey));
        $pubKey  = str_replace("\r\n", "\n", trim($pubKey));

        $fingerprint = self::getFingerprint($pubKey);

        logCrypto('RSA-' . $keyBits, 'sign', 'success', (microtime(true) - $startTime) * 1000);

        return [
            'private_key' => $privKey,
            'public_key'  => $pubKey,
            'fingerprint' => $fingerprint,
            'bits'        => $keyBits,
        ];
    }

    /**
     * Menghitung SHA-256 fingerprint dari sebuah Public Key PEM.
     */
    public static function getFingerprint(string $publicKeyPem): string
    {
        $clean = trim(preg_replace('/-----(BEGIN|END) (RSA )?PUBLIC KEY-----/', '', $publicKeyPem));
        $clean = str_replace(["\r", "\n", " "], '', $clean);
        $der   = base64_decode($clean, true);

        if ($der === false) {
            return 'INVALID_KEY_FORMAT';
        }

        $hash = hash('sha256', $der);
        return strtoupper(implode(':', str_split($hash, 2)));
    }

    /**
     * Mengenkripsi data (misalnya ephemeral AES key) dengan RSA-OAEP menggunakan Public Key.
     *
     * @param string $data Plaintext/Secret yang akan dibungkus
     * @param string $publicKeyPem Public Key dalam format PEM
     * @return string Ciphertext dalam format Base64
     * @throws Exception
     */
    public static function encryptOAEP(string $data, string $publicKeyPem): string
    {
        $startTime = microtime(true);
        $pubKeyRes = openssl_pkey_get_public($publicKeyPem);

        if (!$pubKeyRes) {
            throw new InvalidArgumentException('Public Key RSA tidak valid atau korup.');
        }

        $encrypted = '';
        $success = openssl_public_encrypt($data, $encrypted, $pubKeyRes, OPENSSL_PKCS1_OAEP_PADDING);

        if (!$success) {
            $err = openssl_error_string() ?: 'Enkripsi RSA-OAEP gagal.';
            logCrypto('RSA-OAEP', 'encrypt', 'failed', (microtime(true) - $startTime) * 1000);
            throw new RuntimeException($err);
        }

        logCrypto('RSA-OAEP', 'encrypt', 'success', (microtime(true) - $startTime) * 1000);
        return base64_encode($encrypted);
    }

    /**
     * Mendekripsi data yang dibungkus RSA-OAEP menggunakan Private Key.
     *
     * @param string $encryptedB64 Ciphertext Base64
     * @param string $privateKeyPem Private Key dalam format PEM
     * @param string|null $passphrase Passphrase jika private key diproteksi
     * @return string Data hasil dekripsi (misal: raw AES Key)
     * @throws Exception
     */
    public static function decryptOAEP(string $encryptedB64, string $privateKeyPem, ?string $passphrase = null): string
    {
        $startTime = microtime(true);
        $privKeyRes = openssl_pkey_get_private($privateKeyPem, $passphrase ?? '');

        if (!$privKeyRes) {
            throw new InvalidArgumentException('Private Key RSA tidak valid atau passphrase salah.');
        }

        $ciphertext = base64_decode($encryptedB64, true);
        if ($ciphertext === false) {
            throw new InvalidArgumentException('Data terenkripsi RSA Base64 tidak valid.');
        }

        $decrypted = '';
        $success = openssl_private_decrypt($ciphertext, $decrypted, $privKeyRes, OPENSSL_PKCS1_OAEP_PADDING);

        if (!$success) {
            $err = openssl_error_string() ?: 'Dekripsi RSA-OAEP gagal. Pastikan Private Key cocok dengan Public Key yang digunakan untuk mengenkripsi.';
            logCrypto('RSA-OAEP', 'decrypt', 'failed', (microtime(true) - $startTime) * 1000);
            throw new RuntimeException($err);
        }

        logCrypto('RSA-OAEP', 'decrypt', 'success', (microtime(true) - $startTime) * 1000);
        return $decrypted;
    }

    /**
     * Menandatangani pesan/challenge secara digital menggunakan Private Key.
     */
    public static function sign(string $data, string $privateKeyPem, ?string $passphrase = null): string
    {
        $startTime = microtime(true);
        $privKeyRes = openssl_pkey_get_private($privateKeyPem, $passphrase ?? '');

        if (!$privKeyRes) {
            throw new InvalidArgumentException('Private Key tidak valid untuk penandatanganan.');
        }

        $signature = '';
        $ok = openssl_sign($data, $signature, $privKeyRes, OPENSSL_ALGO_SHA256);

        if (!$ok) {
            logCrypto('RSA-SIGN', 'sign', 'failed', (microtime(true) - $startTime) * 1000);
            throw new RuntimeException('Pembuatan digital signature gagal.');
        }

        logCrypto('RSA-SIGN', 'sign', 'success', (microtime(true) - $startTime) * 1000);
        return base64_encode($signature);
    }

    /**
     * Memverifikasi digital signature (mendukung interoperabilitas Web Crypto API & PHP OpenSSL).
     *
     * @param string $data Data/challenge yang diverifikasi
     * @param string $signatureB64 Signature dalam format Base64
     * @param string $publicKeyPem Public Key dalam format PEM
     * @return bool True jika tanda tangan digital valid dan sah
     */
    public static function verifySignature(string $data, string $signatureB64, string $publicKeyPem): bool
    {
        $startTime = microtime(true);
        $sigBinary = base64_decode($signatureB64, true);

        if ($sigBinary === false) {
            return false;
        }

        $pubKeyRes = openssl_pkey_get_public($publicKeyPem);
        if (!$pubKeyRes) {
            return false;
        }

        // 1. Uji verifikasi native PHP OpenSSL (RSASSA-PKCS1-v1_5 SHA-256)
        $nativeResult = openssl_verify($data, $sigBinary, $pubKeyRes, OPENSSL_ALGO_SHA256);
        if ($nativeResult === 1) {
            logCrypto('RSA-VERIFY', 'verify', 'success', (microtime(true) - $startTime) * 1000);
            return true;
        }

        // 2. Uji verifikasi RSA-PSS via OpenSSL CLI jika signature dibuat dengan mode PSS murni
        $pssValid = self::verifyViaOpenSSLCLI($data, $sigBinary, $publicKeyPem);
        if ($pssValid) {
            logCrypto('RSA-PSS', 'verify', 'success', (microtime(true) - $startTime) * 1000);
            return true;
        }

        logCrypto('RSA-VERIFY', 'verify', 'failed', (microtime(true) - $startTime) * 1000);
        return false;
    }

    /**
     * Verifikasi signature RSA-PSS SHA-256 menggunakan CLI OpenSSL untuk kompatibilitas WebCrypto PSS murni.
     */
    private static function verifyViaOpenSSLCLI(string $data, string $sigBinary, string $publicKeyPem): bool
    {
        $tempDir = sys_get_temp_dir();
        $keyFile = tempnam($tempDir, 'pub_');
        $dataFile = tempnam($tempDir, 'dat_');
        $sigFile = tempnam($tempDir, 'sig_');

        if (!$keyFile || !$dataFile || !$sigFile) {
            return false;
        }

        try {
            file_put_contents($keyFile, $publicKeyPem);
            file_put_contents($dataFile, $data);
            file_put_contents($sigFile, $sigBinary);

            // Perintah OpenSSL verifikasi PSS dengan SHA-256 dan salt length 32
            $cmd = sprintf(
                'openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -verify %s -signature %s %s 2>&1',
                escapeshellarg($keyFile),
                escapeshellarg($sigFile),
                escapeshellarg($dataFile)
            );

            $output = shell_exec($cmd);
            $isValid = ($output !== null && stripos($output, 'Verified OK') !== false);

            return $isValid;
        } catch (Throwable $t) {
            return false;
        } finally {
            @unlink($keyFile);
            @unlink($dataFile);
            @unlink($sigFile);
        }
    }
}
