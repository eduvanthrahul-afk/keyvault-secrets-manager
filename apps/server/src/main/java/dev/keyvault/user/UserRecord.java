package dev.keyvault.user;

import java.time.Instant;
import java.util.UUID;

public record UserRecord(
        UUID id,
        String email,
        String displayName,
        String authHash,
        Kdf kdf,
        String salt,
        String protectedAccountKey,
        String publicKey,
        String protectedPrivateKey,
        String recoveryVerifierHash,
        String recoveryProtectedAccountKey,
        String totpSecretEnc,
        boolean totpEnabled,
        long totpLastStep,
        Instant createdAt) {

    public record Kdf(String algorithm, int memoryKiB, int iterations, int parallelism) {
        public static final Kdf DEFAULT = new Kdf("argon2id", 65536, 3, 1);

        /** Server mirror of the client's lower bound: refuse to store weak parameters. */
        public boolean isAcceptable() {
            return "argon2id".equals(algorithm)
                    && memoryKiB >= 19456 && memoryKiB <= 1048576
                    && iterations >= 2 && iterations <= 20
                    && parallelism >= 1 && parallelism <= 16;
        }
    }

    /** The encrypted key bundle a client needs to unlock locally. */
    public record KeyBundle(Kdf kdf, String salt, String protectedAccountKey, String publicKey, String protectedPrivateKey) {}

    public KeyBundle keyBundle() {
        return new KeyBundle(kdf, salt, protectedAccountKey, publicKey, protectedPrivateKey);
    }

    public record Profile(UUID id, String email, String displayName, boolean totpEnabled, Instant createdAt) {}

    public Profile profile() {
        return new Profile(id, email, displayName, totpEnabled, createdAt);
    }
}
