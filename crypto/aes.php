<?php
/**
 * ============================================================================
 * [TUGAS UTS]: MODUL KRIPTOGRAFI SIMETRIS (AES-256-GCM)
 * File: crypto/aes.php
 * Standar: AEAD (Authenticated Encryption with Associated Data)
 * Karakteristik:
 * - Kunci simetris 256-bit acak per-konten via random_bytes(32)
 * - Nonce/IV acak 96-bit (Anti-Replay)
 * - Authentication Tag 128-bit untuk verifikasi integritas data anti-tampering
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/security.php';

class AESCrypto
{
    public const CIPHER_METHOD = 'aes-256-gcm';
    public const KEY_BYTES     = 32; // 256 bits
    public const NONCE_BYTES   = 12; // 96 bits (rekomendasi NIST untuk GCM)
    public const TAG_BYTES     = 16; // 128 bits auth tag

    /**
     * Menghasilkan kunci simetris 256-bit secara aman secara kriptografis.
     */
    public static function generateKey(): string
    {
        return random_bytes(self::KEY_BYTES);
    }

    /**
     * Menghasilkan Nonce/IV 96-bit secara acak untuk setiap proses enkripsi.
     */
    public static function generateNonce(): string
    {
        return random_bytes(self::NONCE_BYTES);
    }

    /**
     * Melakukan enkripsi teks menggunakan AES-256-GCM.
     *
     * @param string $plaintext Data yang akan dienkripsi.
     * @param string|null $key Kunci 32-byte (jika null, akan digenerate otomatis).
     * @param string|null $aad Additional Authenticated Data (opsional).
     * @return array [ciphertext_b64, nonce_b64, tag_b64, key_raw, key_b64, algorithm]
     * @throws Exception
     */
    public static function encrypt(string $plaintext, ?string $key = null, ?string $aad = null): array
    {
        $startTime = microtime(true);

        if ($key === null) {
            $key = self::generateKey();
        } elseif (strlen($key) !== self::KEY_BYTES) {
            // Coba periksa apakah key dikirim dalam format Base64
            $decodedKey = base64_decode($key, true);
            if ($decodedKey !== false && strlen($decodedKey) === self::KEY_BYTES) {
                $key = $decodedKey;
            } else {
                throw new InvalidArgumentException('Panjang kunci AES harus tepat 256-bit (32 bytes).');
            }
        }

        $nonce = self::generateNonce();
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad ?? '',
            self::TAG_BYTES
        );

        if ($ciphertext === false) {
            $errorMsg = openssl_error_string() ?: 'Unknown OpenSSL error';
            logCrypto(self::CIPHER_METHOD, 'encrypt', 'failed', (microtime(true) - $startTime) * 1000);
            throw new RuntimeException('Gagal mengenkripsi data dengan AES-256-GCM: ' . $errorMsg);
        }

        $execTime = (microtime(true) - $startTime) * 1000;
        logCrypto(self::CIPHER_METHOD, 'encrypt', 'success', $execTime);

        return [
            'ciphertext_b64' => base64_encode($ciphertext),
            'nonce_b64'      => base64_encode($nonce),
            'tag_b64'        => base64_encode($tag),
            'key_raw'        => $key,
            'key_b64'        => base64_encode($key),
            'algorithm'      => strtoupper(self::CIPHER_METHOD),
            'tag_length'     => strlen($tag),
            'nonce_length'   => strlen($nonce),
        ];
    }

    /**
     * Melakukan dekripsi dan verifikasi integritas data menggunakan AES-256-GCM.
     *
     * @param string $ciphertextB64 Ciphertext dalam format Base64.
     * @param string $nonceB64 Nonce/IV dalam format Base64.
     * @param string $tagB64 Authentication Tag dalam format Base64.
     * @param string $key Kunci 32-byte (raw atau Base64).
     * @param string|null $aad Additional Authenticated Data (opsional).
     * @return string Plaintext yang berhasil didekripsi.
     * @throws SecurityException Jika tag tidak valid atau integritas data telah rusak.
     */
    public static function decrypt(
        string $ciphertextB64,
        string $nonceB64,
        string $tagB64,
        string $key,
        ?string $aad = null
    ): string {
        $startTime = microtime(true);

        if (strlen($key) !== self::KEY_BYTES) {
            $decodedKey = base64_decode($key, true);
            if ($decodedKey !== false && strlen($decodedKey) === self::KEY_BYTES) {
                $key = $decodedKey;
            } else {
                throw new InvalidArgumentException('Kunci AES tidak valid (harus 32 bytes).');
            }
        }

        $ciphertext = base64_decode($ciphertextB64, true);
        $nonce      = base64_decode($nonceB64, true);
        $tag        = base64_decode($tagB64, true);

        if ($ciphertext === false || $nonce === false || $tag === false) {
            throw new InvalidArgumentException('Data masukan dekripsi Base64 tidak valid.');
        }

        if (strlen($tag) !== self::TAG_BYTES) {
            throw new InvalidArgumentException('Panjang Authentication Tag harus 16 bytes.');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad ?? ''
        );

        if ($plaintext === false) {
            logCrypto(self::CIPHER_METHOD, 'decrypt', 'failed', (microtime(true) - $startTime) * 1000);
            throw new RuntimeException(
                'Dekripsi Gagal: Integritas data tidak valid atau kunci salah. ' .
                'Authentication Tag tidak cocok dengan ciphertext (indikasi manipulasi/tampering).'
            );
        }

        $execTime = (microtime(true) - $startTime) * 1000;
        logCrypto(self::CIPHER_METHOD, 'decrypt', 'success', $execTime);

        return $plaintext;
    }
}
