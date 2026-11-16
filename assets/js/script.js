/**
 * ============================================================================
 * [TUGAS UTS - BUTIR 1]: CLIENT-SIDE SIGNER (WEB CRYPTO API & BIGINT)
 * File: assets/js/script.js
 * Fungsi: Menandatangani challenge acak dari server menggunakan Kunci Asimetris
 *         (RSA Private Key) di browser tanpa pernah mengirimkan kunci ke server.
 * ============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    initTooltips();
});

// -------------------------------------------------------------
// 1. PURE JAVASCRIPT CRYPTOGRAPHIC FALLBACK ENGINE (BigInt RSA)
// Digunakan saat browser mengakses via HTTP non-localhost (*.test)
// di mana Chrome menonaktifkan window.crypto.subtle demi W3C Secure Context.
// Private Key TETAP 100% diproses di browser dan tidak pernah dikirim ke server.
// -------------------------------------------------------------

function pureJsSha256(ascii) {
    function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), lengthProperty = 'length';
    var i, j, words = [], asciiBitLength = ascii[lengthProperty] * 8;
    var hash = [], k = [], primeCounter = 0, isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
            hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }
    ascii += '\x80';
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j >> 8) return '';
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
    words[words[lengthProperty]] = (asciiBitLength);
    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16), oldHash = hash;
        hash = hash.slice(0, 8);
        for (i = 0; i < 64; i++) {
            var i2 = i + j, w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
            var temp1 = hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                + ((e & hash[5]) ^ ((~e) & hash[6])) + k[i]
                + (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) | 0);
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
        }
        for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    var hex = '';
    for (i = 0; i < 8; i++) {
        for (j = 3; j >= 0; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            hex += (b < 16 ? '0' : '') + b.toString(16);
        }
    }
    return hex;
}

function parseDerKeys(der) {
    let p = 0;
    function readLen() {
        let b = der[p++];
        if ((b & 0x80) === 0) return b;
        let count = b & 0x7f, val = 0;
        for (let i = 0; i < count; i++) val = (val << 8) | der[p++];
        return val;
    }
    function readInteger() {
        if (der[p++] !== 0x02) throw new Error('Format ASN.1 INTEGER tidak valid.');
        let len = readLen(), slice = der.slice(p, p + len);
        p += len;
        let hex = '';
        for (let i = 0; i < slice.length; i++) {
            let h = slice[i].toString(16);
            hex += (h.length < 2 ? '0' : '') + h;
        }
        return BigInt('0x' + (hex || '0'));
    }
    function parsePkcs1Structure(subDer) {
        let sp = 0;
        function sReadLen() {
            let b = subDer[sp++];
            if ((b & 0x80) === 0) return b;
            let count = b & 0x7f, val = 0;
            for (let i = 0; i < count; i++) val = (val << 8) | subDer[sp++];
            return val;
        }
        function sReadInteger() {
            if (subDer[sp++] !== 0x02) throw new Error('Expected INTEGER');
            let len = sReadLen(), slice = subDer.slice(sp, sp + len);
            sp += len;
            let hex = '';
            for (let i = 0; i < slice.length; i++) {
                let h = slice[i].toString(16);
                hex += (h.length < 2 ? '0' : '') + h;
            }
            return BigInt('0x' + (hex || '0'));
        }
        sp++; sReadLen(); // SEQUENCE
        let version = sReadInteger(), n = sReadInteger(), e = sReadInteger(), d = sReadInteger();
        return { n, e, d };
    }

    // Cek apakah PKCS#8 atau PKCS#1
    let tag = der[0];
    p++; readLen(); // SEQUENCE
    let firstInt = der[p++];
    let fLen = readLen();
    p += fLen;

    if (der[p] === 0x30) {
        // PKCS#8: AlgorithmIdentifier SEQUENCE
        p++; let aLen = readLen(); p += aLen;
        // OCTET STRING
        p++; let oLen = readLen();
        return parsePkcs1Structure(der.slice(p, p + oLen));
    } else {
        // PKCS#1 langsung
        return parsePkcs1Structure(der);
    }
}

function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}

function signWithPureJsBigInt(challenge, privateKeyPem) {
    const cleanPem = privateKeyPem
        .replace(/-----BEGIN[A-Z0-9_-|\s]+-----/g, '')
        .replace(/-----END[A-Z0-9_-|\s]+-----/g, '')
        .replace(/\s+/g, '');
    const binary = window.atob(cleanPem);
    const der = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);

    const keys = parseDerKeys(der);
    const hashHex = pureJsSha256(challenge);
    const digestInfoPrefix = '3031300d060960864801650304020105000420';
    const tHex = digestInfoPrefix + hashHex;
    const emLen = 256; // 2048-bit RSA = 256 bytes
    const psLen = emLen - (tHex.length / 2) - 3;
    let emHex = '0001';
    for (let i = 0; i < psLen; i++) emHex += 'ff';
    emHex += '00' + tHex;

    const m = BigInt('0x' + emHex);
    const s = modPow(m, keys.d, keys.n);
    let sHex = s.toString(16);
    if (sHex.length % 2 !== 0) sHex = '0' + sHex;
    while (sHex.length < 512) sHex = '0' + sHex;

    // Convert sHex to Base64
    let sigBinary = '';
    for (let i = 0; i < sHex.length; i += 2) {
        sigBinary += String.fromCharCode(parseInt(sHex.substr(i, 2), 16));
    }
    return window.btoa(sigBinary);
}

// -------------------------------------------------------------
// 2. WEB CRYPTO API / FALLBACK ARRAY BUFFER CONVERTERS
// -------------------------------------------------------------

function pemToArrayBuffer(pem) {
    const cleanPem = pem
        .replace(/-----BEGIN[A-Z0-9_-|\s]+-----/g, '')
        .replace(/-----END[A-Z0-9_-|\s]+-----/g, '')
        .replace(/\s+/g, '');
    
    const binaryString = window.atob(cleanPem);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// -------------------------------------------------------------
// 3. DIGITAL SIGNATURE SIGNER (Web Crypto API + BigInt Fallback)
// -------------------------------------------------------------

/**
 * Menandatangani data/challenge di browser.
 * Menggunakan Web Crypto API jika Secure Context aktif (localhost/https),
 * atau BigInt pure JS engine jika browser memblokir Web Crypto karena HTTP non-localhost.
 * Private Key TIDAK PERNAH dikirim ke server.
 */
async function signChallengeWithWebCrypto(challenge, privateKeyPem) {
    // 1. Jika Web Crypto API didukung (Secure Context: localhost / https)
    if (window.crypto && window.crypto.subtle) {
        try {
            const keyBuffer = pemToArrayBuffer(privateKeyPem);
            const encoder = new TextEncoder();
            const dataBytes = encoder.encode(challenge);

            let cryptoKey = null;
            let usedAlgorithm = null;

            try {
                cryptoKey = await window.crypto.subtle.importKey(
                    'pkcs8',
                    keyBuffer,
                    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
                    false,
                    ['sign']
                );
                usedAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
            } catch (e1) {
                cryptoKey = await window.crypto.subtle.importKey(
                    'pkcs8',
                    keyBuffer,
                    { name: 'RSA-PSS', hash: { name: 'SHA-256' } },
                    false,
                    ['sign']
                );
                usedAlgorithm = { name: 'RSA-PSS', saltLength: 32 };
            }

            const signatureBuffer = await window.crypto.subtle.sign(
                usedAlgorithm,
                cryptoKey,
                dataBytes
            );

            return arrayBufferToBase64(signatureBuffer);
        } catch (webCryptoErr) {
            console.warn('Web Crypto Subtle gagal, beralih ke Client-Side BigInt Signer:', webCryptoErr);
        }
    }

    // 2. Fallback: Eksekusi penandatanganan via Client-Side BigInt Signer
    return signWithPureJsBigInt(challenge, privateKeyPem);
}

// -------------------------------------------------------------
// 4. CHALLENGE-RESPONSE RSA-PSS LOGIN PROCESSOR
// -------------------------------------------------------------

async function submitSecureLogin(event, formElement) {
    event.preventDefault();

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const privateKeyPem = document.getElementById('loginPrivateKey').value.trim();
    const csrfToken = document.getElementById('loginCsrf').value;

    const statusBox = document.getElementById('loginStatusBox');
    const statusText = document.getElementById('loginStatusText');
    const submitBtn = document.getElementById('btnLoginSubmit');

    if (!username || !password || !privateKeyPem) {
        showCyberToast('Harap lengkapi Username, Password, dan Private Key RSA Anda.', 'danger');
        return;
    }

    // UI Loading state
    statusBox.classList.remove('d-none');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Memverifikasi...';

    const updateStatus = (text, icon = 'fa-spinner fa-spin') => {
        statusText.innerHTML = `<i class="fa-solid ${icon} me-2 text-cyan"></i>${text}`;
    };

    try {
        // TAHAP 1: Request Challenge dari Server & Verifikasi Akun
        updateStatus('Tahap 1/3: Memverifikasi akun dan meminta RSA Challenge...');
        const resStep1 = await fetch('login.php?action=request_challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, csrf_token: csrfToken }),
        });

        const dataStep1 = await resStep1.json();
        if (!dataStep1.success) {
            throw new Error(dataStep1.message || 'Verifikasi akun gagal.');
        }

        const challenge = dataStep1.challenge;

        // TAHAP 2: Penandatanganan Digital Signature di Browser (Client-Side)
        const engineLabel = (window.crypto && window.crypto.subtle) ? 'Web Crypto API' : 'Client-Side BigInt Engine';
        updateStatus(`Tahap 2/3: Menandatangani challenge via ${engineLabel} (Private Key tetap di browser)...`, 'fa-key');
        
        const signatureB64 = await signChallengeWithWebCrypto(challenge, privateKeyPem);

        // TAHAP 3: Kirim Signature ke Server untuk Verifikasi Public Key
        updateStatus('Tahap 3/3: Memverifikasi tanda tangan digital & anti-replay di server...', 'fa-shield-halved');
        const resStep2 = await fetch('login.php?action=verify_signature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                challenge,
                signature: signatureB64,
                csrf_token: csrfToken,
            }),
        });

        const dataStep2 = await resStep2.json();
        if (!dataStep2.success) {
            throw new Error(dataStep2.message || 'Verifikasi digital signature gagal.');
        }

        // BERHASIL: Redirect ke dashboard
        updateStatus('Autentikasi Kriptografis Berhasil! Mengalihkan ke Dashboard...', 'fa-circle-check text-success');
        showCyberToast('Login Sukses: Digital Signature Sah!', 'success');
        setTimeout(() => {
            window.location.href = dataStep2.redirect || 'dashboard.php';
        }, 800);

    } catch (err) {
        updateStatus(err.message, 'fa-circle-xmark text-danger');
        showCyberToast(err.message, 'danger');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-unlock-keyhole me-2"></i>Verifikasi & Masuk';
    }
}

// -------------------------------------------------------------
// 5. UI HELPERS: CLIPBOARD & TOAST NOTIFICATION
// -------------------------------------------------------------

function copyToClipboard(text, btnElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalHtml = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="fa-solid fa-check text-success"></i> Tersalin!';
        showCyberToast('Kunci berhasil disalin ke clipboard.', 'success');
        setTimeout(() => {
            btnElement.innerHTML = originalHtml;
        }, 2000);
    }).catch(() => {
        showCyberToast('Gagal menyalin. Silakan salin manual.', 'danger');
    });
}

function showCyberToast(message, type = 'info') {
    let container = document.getElementById('cyberToastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'cyberToastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'cyber-toast mb-2 d-flex align-items-center justify-content-between';
    
    let icon = 'fa-circle-info text-primary';
    if (type === 'success') icon = 'fa-circle-check text-success';
    if (type === 'danger') icon = 'fa-triangle-exclamation text-danger';
    if (type === 'warning') icon = 'fa-circle-exclamation text-warning';

    toast.innerHTML = `
        <div class="d-flex align-items-center gap-3">
            <i class="fa-solid ${icon} fs-5"></i>
            <span class="small">${message}</span>
        </div>
        <button type="button" class="btn-close btn-close-white ms-3" onclick="this.parentElement.remove()"></button>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.transition = 'opacity 0.4s ease';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

function initTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (window.bootstrap && bootstrap.Tooltip) {
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    }
}
