/**
 * Cryptography Module for Zero-Knowledge API Key Management
 * Uses Web Crypto API (PBKDF2 + AES-GCM)
 */
const CryptoModule = {
    // Configuration
    PBKDF2_ITERATIONS: 100000,
    KEY_LENGTH: 256,
    ALGO: 'AES-GCM',

    /**
     * Derives an encryption key from a master password and salt.
     * @param {string} password - The master password
     * @param {string} saltHex - The hex-encoded salt
     * @returns {Promise<CryptoKey>}
     */
    async deriveKey(password, saltHex) {
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const salt = this.hexToBuffer(saltHex);

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            baseKey,
            { name: this.ALGO, length: this.KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Encrypts plaintext using AES-GCM.
     * @param {string} plaintext - The text to encrypt
     * @param {CryptoKey} key - The derived encryption key
     * @returns {Promise<{ciphertext: string, iv: string}>}
     */
    async encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const ciphertextBuffer = await crypto.subtle.encrypt(
            { name: this.ALGO, iv: iv },
            key,
            encoder.encode(plaintext)
        );

        return {
            ciphertext: this.bufferToHex(ciphertextBuffer),
            iv: this.bufferToHex(iv)
        };
    },

    /**
     * Decrypts ciphertext using AES-GCM.
     * @param {string} ciphertextHex - The hex-encoded ciphertext
     * @param {string} ivHex - The hex-encoded IV
     * @param {CryptoKey} key - The derived encryption key
     * @returns {Promise<string>}
     */
    async decrypt(ciphertextHex, ivHex, key) {
        const decoder = new TextDecoder();
        const ciphertext = this.hexToBuffer(ciphertextHex);
        const iv = this.hexToBuffer(ivHex);

        try {
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: this.ALGO, iv: iv },
                key,
                ciphertext
            );
            return decoder.decode(decryptedBuffer);
        } catch (e) {
            console.error("Decryption failed", e);
            throw new Error("Failed to decrypt. Possible wrong password or corrupted data.");
        }
    },

    // Utilities
    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    hexToBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes.buffer;
    },

    generateSalt() {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        return this.bufferToHex(salt);
    }
};
