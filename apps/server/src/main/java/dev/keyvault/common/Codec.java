package dev.keyvault.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Pattern;

/** Small, dependency-free encoding and hashing helpers. Base64url without padding everywhere. */
public final class Codec {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
    public static final Pattern B64U_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+$");

    private Codec() {}

    public static String b64u(byte[] bytes) { return B64U.encodeToString(bytes); }

    public static byte[] fromB64u(String s) {
        if (s == null || !B64U_PATTERN.matcher(s).matches()) throw ApiException.badRequest("Malformed base64url value");
        try {
            return B64U_DEC.decode(s);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("Malformed base64url value");
        }
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String randomToken(int bytes) { return b64u(randomBytes(bytes)); }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(String s) { return hex(sha256(s.getBytes(StandardCharsets.UTF_8))); }

    public static String sha256B64u(byte[] data) { return b64u(sha256(data)); }

    public static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Constant-time comparison so verifiers cannot be probed byte-by-byte via timing. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public static UUID parseUuid(String s) {
        try {
            return UUID.fromString(s);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest("Malformed id");
        }
    }
}
