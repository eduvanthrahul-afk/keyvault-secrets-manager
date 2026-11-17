package dev.keyvault.common;

import dev.keyvault.config.KeyVaultProperties;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Server-side cryptography for the few values the server legitimately must read
 * (TOTP seeds). User secrets are NEVER handled here; they are end-to-end encrypted.
 */
@Component
public class ServerCrypto {
    private static final String PREFIX = "sv1.";
    private final SecretKeySpec encKey;
    private final SecretKeySpec macKey;

    public ServerCrypto(KeyVaultProperties props) {
        byte[] master;
        try {
            master = Base64.getDecoder().decode(props.serverKey().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("KEYVAULT_SERVER_KEY must be base64");
        }
        if (master.length < 32) {
            throw new IllegalStateException("KEYVAULT_SERVER_KEY must be at least 32 random bytes (openssl rand -base64 32)");
        }
        this.encKey = new SecretKeySpec(hmac(master, "keyvault/server/enc"), "AES");
        this.macKey = new SecretKeySpec(hmac(master, "keyvault/server/mac"), "HmacSHA256");
        Arrays.fill(master, (byte) 0);
    }

    public String encrypt(byte[] plaintext, String context) {
        try {
            byte[] iv = Codec.randomBytes(12);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, encKey, new GCMParameterSpec(128, iv));
            c.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plaintext);
            return PREFIX + Codec.b64u(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] decrypt(String envelope, String context) {
        if (envelope == null || !envelope.startsWith(PREFIX)) throw new IllegalStateException("Bad server ciphertext");
        byte[] raw = Codec.fromB64u(envelope.substring(PREFIX.length()));
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, encKey, new GCMParameterSpec(128, raw, 0, 12));
            c.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(raw, 12, raw.length - 12);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Server ciphertext failed authentication", e);
        }
    }

    public byte[] mac(String data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(macKey);
            return m.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, String label) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(label.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
