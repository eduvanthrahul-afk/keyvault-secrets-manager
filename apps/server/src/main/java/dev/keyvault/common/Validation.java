package dev.keyvault.common;

/** Shared limits for client-supplied crypto material. Keeps storage and parsing bounded. */
public final class Validation {
    private Validation() {}

    /** base64url, no padding. */
    public static final String B64U = "^[A-Za-z0-9_-]+$";
    /** "kv1." AEAD envelope produced by @keyvault/crypto. */
    public static final String ENVELOPE = "^kv1\\.[A-Za-z0-9_-]+$";
    /** "kv1s." sealed box produced by @keyvault/crypto. */
    public static final String SEALED = "^kv1s\\.[A-Za-z0-9_-]+$";
    /** 32 bytes as base64url = 43 chars. */
    public static final String KEY_32 = "^[A-Za-z0-9_-]{43}$";
    public static final String UUID = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$";
    public static final String SLUG = "^[a-z0-9][a-z0-9-]{0,39}$";

    /** 64 KiB plaintext → ~87.5 KiB base64 + nonce/tag overhead. */
    public static final int MAX_VALUE_CT = 90_000;
    public static final int MAX_SMALL_CT = 2_000;
}
