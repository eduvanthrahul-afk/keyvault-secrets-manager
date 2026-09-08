const crypto = require('crypto').webcrypto;

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 256;
const ALGO = 'AES-GCM';

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
}

async function deriveKey(password, saltHex) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const salt = hexToBuffer(saltHex);

    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        baseKey,
        { name: ALGO, length: KEY_LENGTH },
        false,
        ['encrypt', 'decrypt']
    );
}

async function decryptAndImportPrivateKey(encryptedHex, sessionKey) {
    const parts = encryptedHex.split(':');
    if (parts.length !== 2) throw new Error("Invalid private key format");
    const iv = hexToBuffer(parts[0]);
    const ciphertext = hexToBuffer(parts[1]);
    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: ALGO, iv: iv },
        sessionKey,
        ciphertext
    );
    return await crypto.subtle.importKey(
        "pkcs8",
        decryptedBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["unwrapKey", "decrypt"]
    );
}

async function unwrapProjectKey(wrappedHex, rsaPrivateKey) {
    const wrappedBuffer = hexToBuffer(wrappedHex);
    return await crypto.subtle.unwrapKey(
        "raw",
        wrappedBuffer,
        rsaPrivateKey,
        "RSA-OAEP",
        { name: ALGO, length: KEY_LENGTH },
    );
}

async function unwrapProjectKeyWithToken(wrappedWithSalt, tokenSecret) {
    const encoder = new TextEncoder();
    const parts = wrappedWithSalt.split(':');
    if (parts.length !== 3) throw new Error("Invalid token-encrypted key format");

    const salt = hexToBuffer(parts[0]);
    const iv = hexToBuffer(parts[1]);
    const ciphertext = hexToBuffer(parts[2]);

    // Derive the key from the token secret
    const baseKey = await crypto.subtle.importKey('raw', encoder.encode(tokenSecret), 'PBKDF2', false, ['deriveKey']);
    const encKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['unwrapKey']
    );

    return await crypto.subtle.unwrapKey(
        "raw",
        ciphertext,
        encKey,
        { name: 'AES-GCM', iv: iv },
        { name: ALGO, length: KEY_LENGTH },
        true,
        ['encrypt', 'decrypt']
    );
}

async function decrypt(ciphertextHex, ivHex, key) {
    const decoder = new TextDecoder();
    const ciphertext = hexToBuffer(ciphertextHex);
    const iv = hexToBuffer(ivHex);

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: ALGO, iv: iv },
        key,
        ciphertext
    );
    return decoder.decode(decryptedBuffer);
}

// Fallback logic
async function getLegacyProjectKey(projectId) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(projectId),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const salt = hexToBuffer("abcdef1234567890abcdef1234567890");

    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 50000,
            hash: 'SHA-256'
        },
        baseKey,
        { name: ALGO, length: KEY_LENGTH },
        false,
        ['encrypt', 'decrypt']
    );
}

module.exports = {
    deriveKey,
    decryptAndImportPrivateKey,
    unwrapProjectKey,
    unwrapProjectKeyWithToken,
    decrypt,
    getLegacyProjectKey
};
