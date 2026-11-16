<?php
/**
 * Script Inisialisasi Kunci RSA 2048-bit untuk Secure Admin System
 */

// Cari lokasi openssl.cnf di Laragon/PHP
$php_dir = dirname(php_ini_loaded_file() ?: 'C:/laragon/bin/php/php-8.4.27-1-nts-Win32-vs17-x64');
$possible_paths = [
    $php_dir . '/extras/ssl/openssl.cnf',
    'C:/laragon/usr/ssl/openssl.cnf',
    'C:/laragon/etc/ssl/openssl.cnf',
    'C:/laragon/bin/apache/httpd-2.4.54-win64-VS16/conf/openssl.cnf'
];

$valid_config = null;
foreach ($possible_paths as $path) {
    if (file_exists($path)) {
        $valid_config = $path;
        break;
    }
}

if ($valid_config) {
    putenv("OPENSSL_CONF=" . $valid_config);
    $_ENV['OPENSSL_CONF'] = $valid_config;
}

$config = [
    "digest_alg" => "sha256",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];
if ($valid_config) {
    $config["config"] = $valid_config;
}

$res = openssl_pkey_new($config);
if (!$res) {
    die("Error generating RSA key: " . openssl_error_string() . "\n");
}

// Export Private Key
$privKey = '';
openssl_pkey_export($res, $privKey, null, $config);

// Export Public Key
$details = openssl_pkey_get_details($res);
$pubKey = $details["key"];

// Normalisasi baris
$privKey = str_replace("\r\n", "\n", trim($privKey));
$pubKey = str_replace("\r\n", "\n", trim($pubKey));

$keyDir = __DIR__;
file_put_contents($keyDir . '/private_key.pem', $privKey);
file_put_contents($keyDir . '/public_key.pem', $pubKey);

// Hitung SHA-256 fingerprint dari public key
$pubKeyClean = trim(preg_replace('/-----(BEGIN|END) PUBLIC KEY-----/', '', $pubKey));
$pubKeyClean = str_replace(["\r", "\n", " "], '', $pubKeyClean);
$fingerprint = strtoupper(implode(':', str_split(hash('sha256', base64_decode($pubKeyClean)), 2)));

// Password hash admin default: AdminSecure2026!
$defaultPass = 'AdminSecure2026!';
$passHash = password_hash($defaultPass, PASSWORD_BCRYPT, ['cost' => 12]);

echo "RSA 2048-bit Keypair Berhasil Dibuat!\n";
echo "Private Key Path: " . $keyDir . "/private_key.pem\n";
echo "Public Key Path: " . $keyDir . "/public_key.pem\n";
echo "Fingerprint (SHA-256): " . $fingerprint . "\n";
echo "Default Admin: admin\n";
echo "Default Pass: " . $defaultPass . "\n";
echo "Password Hash: " . $passHash . "\n";
