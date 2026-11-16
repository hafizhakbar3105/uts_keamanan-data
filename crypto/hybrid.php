<?php
/**
 * ============================================================================
 * [TUGAS UTS]: MESIN KRIPTOGRAFI HIBRIDA (HYBRID CRYPTOSYSTEM)
 * File: crypto/hybrid.php
 * Sinergi Dua Kriptografi:
 * 1. AES-256-GCM (Simetris): Mengenkripsi data payload judul dan isi konten.
 * 2. RSA-OAEP (Asimetris): Mengenkripsi ephemeral AES key menggunakan Public Key.
 * Hasil: Tidak ada satupun plaintext maupun kunci mentah yang masuk ke database.
 * ============================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/aes.php';
require_once __DIR__ . '/rsa.php';

class HybridCrypto
{
    /**
     * Mengenkripsi konten dan membungkus AES key dengan Public Key RSA.
     *
     * @param string $title Judul konten yang sensitif
     * @param string $content Isi konten yang sensitif
     * @param string $publicKeyPem Public Key RSA dalam format PEM
     * @return array [encrypted_title, encrypted_content, encrypted_aes_key, nonce, auth_tag, raw_aes_key_b64]
     * @throws Exception
     */
    public static function encryptRecord(string $title, string $content, string $publicKeyPem): array
    {
        // 1. Bangkitkan satu Ephemeral AES Key 256-bit
        $aesKey = AESCrypto::generateKey();

        // 2. Gabungkan Judul & Isi ke dalam payload JSON terstruktur
        $payload = json_encode([
            'title'   => $title,
            'content' => $content,
            'time'    => time(),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // 3. Enkripsi payload dengan AES-256-GCM (menghasilkan ciphertext, nonce 96-bit, auth tag 128-bit)
        $aesResult = AESCrypto::encrypt($payload, $aesKey);

        // Enkripsi judul tersendiri untuk kebutuhan display ciphertext di tabel
        $titleResult = AESCrypto::encrypt($title, $aesKey);

        // 4. Bungkus (wrap) AES Key menggunakan RSA-OAEP dengan Public Key
        $encryptedAesKeyB64 = RSACrypto::encryptOAEP($aesKey, $publicKeyPem);

        return [
            'encrypted_title'    => $titleResult['ciphertext_b64'] . ':' . $titleResult['nonce_b64'] . ':' . $titleResult['tag_b64'],
            'encrypted_content'  => $aesResult['ciphertext_b64'],
            'encrypted_aes_key'  => $encryptedAesKeyB64,
            'nonce'              => $aesResult['nonce_b64'],
            'auth_tag'           => $aesResult['tag_b64'],
            'raw_aes_key_b64'    => base64_encode($aesKey),
        ];
    }

    /**
     * Mendekripsi konten terenkripsi menggunakan Private Key RSA.
     *
     * @param string $encryptedContentB64 Ciphertext payload (Base64)
     * @param string $encryptedAesKeyB64 Kunci AES terbungkus RSA (Base64)
     * @param string $nonceB64 Nonce GCM (Base64)
     * @param string $tagB64 Authentication Tag GCM (Base64)
     * @param string $privateKeyPem Private Key RSA dalam format PEM
     * @param string|null $passphrase Passphrase pelindung private key (jika ada)
     * @return array [title, content, raw_aes_key_b64]
     * @throws Exception Jika Private key tidak cocok, atau ciphertext mengalami manipulasi/tampering
     */
    public static function decryptRecord(
        string $encryptedContentB64,
        string $encryptedAesKeyB64,
        string $nonceB64,
        string $tagB64,
        string $privateKeyPem,
        ?string $passphrase = null
    ): array {
        // 1. Dekripsi AES Key menggunakan RSA-OAEP dengan Private Key
        $rawAesKey = RSACrypto::decryptOAEP($encryptedAesKeyB64, $privateKeyPem, $passphrase);

        if (strlen($rawAesKey) !== 32) {
            throw new RuntimeException('Ukuran kunci AES yang didekripsi tidak valid.');
        }

        // 2. Dekripsi payload konten dan verifikasi Authentication Tag dengan AES-256-GCM
        $decryptedJson = AESCrypto::decrypt(
            $encryptedContentB64,
            $nonceB64,
            $tagB64,
            $rawAesKey
        );

        $data = json_decode($decryptedJson, true);
        if (!is_array($data) || !isset($data['title']) || !isset($data['content'])) {
            throw new RuntimeException('Struktur payload hasil dekripsi tidak sesuai.');
        }

        return [
            'title'           => (string)$data['title'],
            'content'         => (string)$data['content'],
            'raw_aes_key_b64' => base64_encode($rawAesKey),
        ];
    }

    /**
     * Helper untuk mendekripsi judul secara individual jika diperlukan
     */
    public static function decryptTitle(string $encryptedTitleComposite, string $rawAesKey): string
    {
        $parts = explode(':', $encryptedTitleComposite);
        if (count($parts) !== 3) {
            return '[Ciphertext Judul]';
        }

        [$cipherB64, $nonceB64, $tagB64] = $parts;
        try {
            return AESCrypto::decrypt($cipherB64, $nonceB64, $tagB64, $rawAesKey);
        } catch (Throwable $e) {
            return '[Dekripsi Gagal]';
        }
    }
}
