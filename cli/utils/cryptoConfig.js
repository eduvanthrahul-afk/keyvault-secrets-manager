const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');

// Derive a 256‑bit key from the OS username + static salt.
const SALT = Buffer.from('c1f2e3d4b5a69788', 'hex'); // static, not secret

function _deriveKey() {
    const username = os.userInfo().username;
    return crypto.pbkdf2Sync(username, SALT, 100_000, 32, 'sha256');
}

/**
 * Encrypt a JSON‑serialisable object and write it to the given file.
 * The file is stored as Base64‑encoded ciphertext (IV|TAG|CIPHERTEXT).
 */
async function writeEncrypted(filePath, obj) {
    const key = _deriveKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([iv, tag, ciphertext]).toString('base64');
    await fs.promises.writeFile(filePath, payload, { mode: 0o600 });
}

/**
 * Read the encrypted file, decrypt it and return the parsed JSON object.
 */
async function readEncrypted(filePath) {
    const data = await fs.promises.readFile(filePath, 'utf8');
    const buf = Buffer.from(data, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ciphertext = buf.slice(28);
    const key = _deriveKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
}

module.exports = { writeEncrypted, readEncrypted };
