package dev.keyvault.user;

import dev.keyvault.common.Rows;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    private final JdbcClient db;

    public UserRepository(JdbcClient db) {
        this.db = db;
    }

    private static UserRecord map(ResultSet rs, int i) throws SQLException {
        return new UserRecord(
                Rows.uuid(rs, "id"),
                rs.getString("email"),
                rs.getString("display_name"),
                rs.getString("auth_hash"),
                new UserRecord.Kdf(rs.getString("kdf_algorithm"), rs.getInt("kdf_memory_kib"),
                        rs.getInt("kdf_iterations"), rs.getInt("kdf_parallelism")),
                rs.getString("salt"),
                rs.getString("protected_account_key"),
                rs.getString("public_key"),
                rs.getString("protected_private_key"),
                rs.getString("recovery_verifier_hash"),
                rs.getString("recovery_protected_account_key"),
                rs.getString("totp_secret_enc"),
                rs.getBoolean("totp_enabled"),
                rs.getLong("totp_last_step"),
                Rows.instant(rs, "created_at"));
    }

    public Optional<UserRecord> findByEmail(String email) {
        return db.sql("SELECT * FROM users WHERE email = ?").param(email).query(UserRepository::map).optional();
    }

    public Optional<UserRecord> findById(UUID id) {
        return db.sql("SELECT * FROM users WHERE id = ?").param(id).query(UserRepository::map).optional();
    }

    public UserRecord require(UUID id) {
        return findById(id).orElseThrow(() -> new IllegalStateException("User vanished: " + id));
    }

    public boolean emailExists(String email) {
        return db.sql("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)").param(email).query(Boolean.class).single();
    }

    public void insert(UserRecord u) {
        db.sql("""
                INSERT INTO users (id, email, display_name, auth_hash, kdf_algorithm, kdf_memory_kib, kdf_iterations,
                  kdf_parallelism, salt, protected_account_key, public_key, protected_private_key,
                  recovery_verifier_hash, recovery_protected_account_key, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """)
                .params(u.id(), u.email(), u.displayName(), u.authHash(), u.kdf().algorithm(), u.kdf().memoryKiB(),
                        u.kdf().iterations(), u.kdf().parallelism(), u.salt(), u.protectedAccountKey(), u.publicKey(),
                        u.protectedPrivateKey(), u.recoveryVerifierHash(), u.recoveryProtectedAccountKey(),
                        Rows.now(), Rows.now())
                .update();
    }

    public void updatePassword(UUID id, String authHash, UserRecord.Kdf kdf, String salt, String protectedAccountKey) {
        db.sql("""
                UPDATE users SET auth_hash = ?, kdf_algorithm = ?, kdf_memory_kib = ?, kdf_iterations = ?,
                  kdf_parallelism = ?, salt = ?, protected_account_key = ?, updated_at = ? WHERE id = ?
                """)
                .params(authHash, kdf.algorithm(), kdf.memoryKiB(), kdf.iterations(), kdf.parallelism(), salt,
                        protectedAccountKey, Rows.now(), id)
                .update();
    }

    public void updateRecovery(UUID id, String verifierHash, String recoveryProtectedAccountKey) {
        db.sql("UPDATE users SET recovery_verifier_hash = ?, recovery_protected_account_key = ?, updated_at = ? WHERE id = ?")
                .params(verifierHash, recoveryProtectedAccountKey, Rows.now(), id)
                .update();
    }

    public void updateDisplayName(UUID id, String displayName) {
        db.sql("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?").params(displayName, Rows.now(), id).update();
    }

    public void setPendingTotp(UUID id, String secretEnc) {
        db.sql("UPDATE users SET totp_secret_enc = ?, totp_enabled = FALSE, totp_last_step = 0 WHERE id = ?")
                .params(secretEnc, id).update();
    }

    public void enableTotp(UUID id) {
        db.sql("UPDATE users SET totp_enabled = TRUE WHERE id = ?").param(id).update();
    }

    public void disableTotp(UUID id) {
        db.sql("UPDATE users SET totp_enabled = FALSE, totp_secret_enc = NULL, totp_last_step = 0 WHERE id = ?").param(id).update();
        db.sql("DELETE FROM totp_recovery_codes WHERE user_id = ?").param(id).update();
    }

    /** Atomically advance the last-used TOTP step; false means the code was already used (replay). */
    public boolean advanceTotpStep(UUID id, long step) {
        return db.sql("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?")
                .params(step, id, step).update() == 1;
    }

    public void replaceRecoveryCodes(UUID userId, List<String> codeHashes) {
        db.sql("DELETE FROM totp_recovery_codes WHERE user_id = ?").param(userId).update();
        for (String h : codeHashes) {
            db.sql("INSERT INTO totp_recovery_codes (id, user_id, code_hash) VALUES (?,?,?)")
                    .params(UUID.randomUUID(), userId, h).update();
        }
    }

    public boolean consumeRecoveryCode(UUID userId, String codeHash) {
        return db.sql("UPDATE totp_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL")
                .params(Rows.now(), userId, codeHash).update() == 1;
    }

    public int remainingRecoveryCodes(UUID userId) {
        return db.sql("SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL")
                .param(userId).query(Integer.class).single();
    }

    public void delete(UUID id) {
        db.sql("DELETE FROM users WHERE id = ?").param(id).update();
    }
}
