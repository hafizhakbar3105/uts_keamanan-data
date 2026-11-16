<?php
/**
 * Helper Endpoint untuk Pengujian UTS: Memuat Private Key default dari storage/keys/private_key.pem
 * File: crypto/get_test_key.php
 */

declare(strict_types=1);

header('Content-Type: application/json');

$keyPath = __DIR__ . '/../storage/keys/private_key.pem';

if (file_exists($keyPath)) {
    $keyContent = file_get_contents($keyPath);
    echo json_encode([
        'success' => true,
        'key'     => $keyContent,
    ]);
} else {
    echo json_encode([
        'success' => false,
        'message' => 'File kunci pengujian belum dibuat di storage/keys/private_key.pem',
    ]);
}
