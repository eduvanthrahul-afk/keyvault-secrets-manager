package dev.keyvault.account;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.AuthService;
import dev.keyvault.auth.Principals;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.KeyVaultMetrics;
import dev.keyvault.common.Rows;
import dev.keyvault.common.Validation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

/**
 * Passkey unlock (WebAuthn PRF). The browser derives a key inside the authenticator and wraps the
 * Account Key with it; we only store that wrap plus the PRF salt. Registering one requires the
 * master password again, because it creates a new way to decrypt the vault.
 */
@RestController
@RequestMapping("/api/account/passkeys")
public class PasskeyController {
    private static final int MAX_PASSKEYS = 10;

    private final JdbcClient db;
    private final AuthService auth;
    private final AuditService audit;
    private final KeyVaultMetrics metrics;

    public PasskeyController(JdbcClient db, AuthService auth, AuditService audit, KeyVaultMetrics metrics) {
        this.db = db;
        this.auth = auth;
        this.audit = audit;
        this.metrics = metrics;
    }

    public record PasskeyView(UUID id, String credentialId, String name, String prfSalt, String wrappedAccountKey,
                              Instant createdAt, Instant lastUsedAt) {}

    public record RegisterPasskeyRequest(
            @NotBlank @Pattern(regexp = Validation.KEY_32) String currentAuthKey,
            @NotBlank @Pattern(regexp = Validation.B64U) @Size(max = 512) String credentialId,
            @NotBlank @Size(max = 80) String name,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String prfSalt,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = 400) String wrappedAccountKey) {}

    @GetMapping
    public List<PasskeyView> list() {
        return db.sql("SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at")
                .param(Principals.user().userId())
                .query((rs, i) -> new PasskeyView(Rows.uuid(rs, "id"), rs.getString("credential_id"), rs.getString("name"),
                        rs.getString("prf_salt"), rs.getString("wrapped_account_key"), Rows.instant(rs, "created_at"),
                        Rows.instant(rs, "last_used_at")))
                .list();
    }

    @PostMapping
    @Transactional
    public List<PasskeyView> register(@Valid @RequestBody RegisterPasskeyRequest req) {
        var p = Principals.user();
        auth.reauthenticate(p.userId(), req.currentAuthKey());
        int count = db.sql("SELECT COUNT(*) FROM passkeys WHERE user_id = ?").param(p.userId()).query(Integer.class).single();
        if (count >= MAX_PASSKEYS) throw ApiException.badRequest("You can register up to " + MAX_PASSKEYS + " passkeys");
        int n = db.sql("""
                INSERT INTO passkeys (id, user_id, credential_id, name, prf_salt, wrapped_account_key, created_at)
                VALUES (?,?,?,?,?,?,?) ON CONFLICT (user_id, credential_id) DO NOTHING
                """)
                .params(UUID.randomUUID(), p.userId(), req.credentialId(), req.name().trim(), req.prfSalt(),
                        req.wrappedAccountKey(), Rows.now())
                .update();
        if (n == 0) throw ApiException.conflict("passkey_exists", "This passkey is already registered");
        audit.record(Event.of(Actor.user(p.userId(), p.email()), null, "account.passkey_added").details(Map.of("name", req.name().trim())));
        return list();
    }

    @PostMapping("/{id}/used")
    public ResponseEntity<Void> used(@PathVariable UUID id) {
        var p = Principals.user();
        int n = db.sql("UPDATE passkeys SET last_used_at = ? WHERE id = ? AND user_id = ?").params(Rows.now(), id, p.userId()).update();
        if (n == 0) throw ApiException.notFound("Passkey");
        metrics.passkeyUnlock();
        audit.record(Event.of(Actor.user(p.userId(), p.email()), null, "auth.passkey_unlock").target("passkey", id));
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")
    @Transactional
    public ResponseEntity<Void> remove(@PathVariable UUID id) {
        var p = Principals.user();
        int n = db.sql("DELETE FROM passkeys WHERE id = ? AND user_id = ?").params(id, p.userId()).update();
        if (n == 0) throw ApiException.notFound("Passkey");
        audit.record(Event.of(Actor.user(p.userId(), p.email()), null, "account.passkey_removed").target("passkey", id));
        return ResponseEntity.noContent().build();
    }
}
