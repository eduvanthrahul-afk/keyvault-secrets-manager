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

    /**
     * Stores a derived key in IndexedDB (extractable: false) for secure session management.
     * @param {CryptoKey} key 
     */
    async saveSessionKey(key) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('KeyVaultSession', 1);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('session')) {
                    db.createObjectStore('session');
                }
            };
            request.onsuccess = (e) => {
                const db = e.target.result;
                const tx = db.transaction('session', 'readwrite');
                tx.objectStore('session').put(key, 'current_key');
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(new Error("Failed to save session key"));
            };
            request.onerror = () => reject(new Error("IndexedDB access denied"));
        });
    },

    /**
     * Retrieves the non-extractable key from IndexedDB.
     * @returns {Promise<CryptoKey|null>}
     */
    async getSessionKey() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('KeyVaultSession', 1);
            request.onsuccess = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('session')) return resolve(null);
                const tx = db.transaction('session', 'readonly');
                const getReq = tx.objectStore('session').get('current_key');
                getReq.onsuccess = () => resolve(getReq.result || null);
                getReq.onerror = () => reject(new Error("Failed to get session key"));
            };
            request.onerror = () => resolve(null); // Silent fail if DB blocked
        });
    },

    async clearSessionVault() {
        return new Promise((resolve) => {
            const request = indexedDB.deleteDatabase('KeyVaultSession');
            request.onsuccess = () => resolve();
            request.onerror = () => resolve();
        });
    },

    // --- True Zero-Knowledge Operations ---

    async generateRSAKeyPair() {
        return await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );
    },

    async exportPublicKey(keyPair) {
        const exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        return this.bufferToHex(exported);
    },

    async importPublicKey(hexString) {
        const buffer = this.hexToBuffer(hexString);
        return await crypto.subtle.importKey(
            "spki",
            buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["wrapKey", "encrypt"]
        );
    },

    async exportAndEncryptPrivateKey(keyPair, sessionKey) {
        const exported = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertextBuffer = await crypto.subtle.encrypt(
            { name: this.ALGO, iv: iv },
            sessionKey,
            exported
        );
        return this.bufferToHex(iv) + ":" + this.bufferToHex(ciphertextBuffer);
    },

    async decryptAndImportPrivateKey(encryptedHex, sessionKey) {
        const parts = encryptedHex.split(':');
        if (parts.length !== 2) throw new Error("Invalid private key format");
        const iv = this.hexToBuffer(parts[0]);
        const ciphertext = this.hexToBuffer(parts[1]);
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: this.ALGO, iv: iv },
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
    },

    async generateProjectKey() {
        return await crypto.subtle.generateKey(
            { name: this.ALGO, length: this.KEY_LENGTH },
            true,
            ["encrypt", "decrypt"]
        );
    },

    async wrapProjectKey(projectKey, rsaPublicKey) {
        const wrapped = await crypto.subtle.wrapKey(
            "raw",
            projectKey,
            rsaPublicKey,
            "RSA-OAEP"
        );
        return this.bufferToHex(wrapped);
    },

    async unwrapProjectKey(wrappedHex, rsaPrivateKey) {
        const wrappedBuffer = this.hexToBuffer(wrappedHex);
        return await crypto.subtle.unwrapKey(
            "raw",
            wrappedBuffer,
            rsaPrivateKey,
            "RSA-OAEP",
            { name: this.ALGO, length: this.KEY_LENGTH },
            true,
            ["encrypt", "decrypt", "wrapKey"]
        );
    },

    /**
     * Helper to get project key from current user's session state.
     */
    async getProjectKey(projectId, overrideEncPk = null) {
        let encProjectKey = overrideEncPk;

        if (!encProjectKey) {
            const currentProject = JSON.parse(sessionStorage.getItem('current_project'));
            if (!currentProject || currentProject.id !== projectId) {
                throw new Error("Missing encrypted project context.");
            }
            encProjectKey = currentProject.encryptedProjectKey;
        }

        // --- LEGACY BACKWARD COMPATIBILITY ---
        // If this project was created BEFORE Zero-Knowledge identities,
        // or the user hasn't migrated, use the deterministic fallback algorithm.
        if (!encProjectKey) {
            return await this.getLegacyProjectKey(projectId);
        }

        const sessionKey = await this.getSessionKey();
        if (!sessionKey) throw new Error("Missing session key. Please login again.");

        const encPrivKey = localStorage.getItem('encrypted_private_key');
        if (!encPrivKey) throw new Error("Missing private key. Please re-register or login again.");

        const rsaPrivateKey = await this.decryptAndImportPrivateKey(encPrivKey, sessionKey);
        return await this.unwrapProjectKey(encProjectKey, rsaPrivateKey);
    },

    /**
     * Legacy deterministic project master key generator (symmetric).
     */
    async getLegacyProjectKey(projectId) {
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(projectId),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const salt = this.hexToBuffer("abcdef1234567890abcdef1234567890");

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 50000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: this.ALGO, length: this.KEY_LENGTH },
            true, // Extractable for token generation
            ['encrypt', 'decrypt', 'wrapKey']
        );
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
