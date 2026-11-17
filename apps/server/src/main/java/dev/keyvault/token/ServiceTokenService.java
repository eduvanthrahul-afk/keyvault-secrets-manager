package dev.keyvault.token;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals.ServiceTokenPrincipal;
import dev.keyvault.auth.Principals.UserPrincipal;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.Codec;
import dev.keyvault.common.RateLimiter;
import dev.keyvault.common.Rows;
import dev.keyvault.common.Validation;
import dev.keyvault.project.AccessService;
import dev.keyvault.project.Role;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Machine identities scoped to ONE environment, read-only, optionally expiring.
 * The server stores SHA-256(authSecret) and an env key wrapped with a key it never sees.
 */
@Service
public class ServiceTokenService {
    private static final java.util.regex.Pattern HEADER = java.util.regex.Pattern.compile("^([A-Za-z0-9_-]{22})\\.([A-Za-z0-9_-]{43})$");

    private final JdbcClient db;
    private final AccessService access;
    private final AuditService audit;
    private final RateLimiter limiter;
    private final dev.keyvault.common.KeyVaultMetrics metrics;

    public ServiceTokenService(JdbcClient db, AccessService access, AuditService audit, RateLimiter limiter,
                               dev.keyvault.common.KeyVaultMetrics metrics) {
        this.metrics = metrics;
        this.db = db;
        this.access = access;
        this.audit = audit;
        this.limiter = limiter;
    }

    public record CreateTokenRequest(
            @NotBlank @Pattern(regexp = "^[A-Za-z0-9_-]{22}$") String tokenId,
            @NotBlank @Size(max = 80) String name,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String verifier,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = 400) String wrappedEnvKey,
            int keyVersion,
            @Min(1) @Max(365) Integer expiresInDays) {}

    public record TokenView(UUID id, String tokenId, String name, String createdBy, Instant createdAt, Instant expiresAt,
                            Instant lastUsedAt, String lastUsedIp, int keyVersion) {}

    public Optional<ServiceTokenPrincipal> authenticate(String credential, ClientInfo client) {
        Matcher m = HEADER.matcher(credential);
        if (!m.matches()) throw ApiException.unauthorized("Malformed service token");
        String tokenId = m.group(1);
        limiter.check(RateLimiter.Policy.SERVICE_TOKEN, tokenId);
        limiter.check(RateLimiter.Policy.SERVICE_TOKEN, "ip:" + client.ip());

        record Row(UUID id, String name, String verifier, UUID envId, UUID projectId, int keyVersion, int envKeyVersion,
                   Instant lastUsed) {}
        Row row = db.sql("""
                SELECT t.id, t.name, t.verifier, t.environment_id, e.project_id, t.key_version, e.key_version AS env_kv, t.last_used_at
                FROM service_tokens t JOIN environments e ON e.id = t.environment_id
                WHERE t.token_id = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?)
                """)
                .params(tokenId, Rows.now())
                .query((rs, i) -> new Row(Rows.uuid(rs, "id"), rs.getString("name"), rs.getString("verifier"),
                        Rows.uuid(rs, "environment_id"), Rows.uuid(rs, "project_id"), rs.getInt("key_version"),
                        rs.getInt("env_kv"), Rows.instant(rs, "last_used_at")))
                .optional().orElse(null);
        String presented = Codec.sha256B64u(Codec.fromB64u(m.group(2)));
        if (row == null || !Codec.constantTimeEquals(presented, row.verifier())) {
            throw ApiException.unauthorized("Invalid, expired or revoked service token");
        }
        if (row.keyVersion() != row.envKeyVersion()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "token_stale", "Environment key was rotated; issue a new token");
        }
        if (row.lastUsed() == null || row.lastUsed().isBefore(Instant.now().minus(Duration.ofMinutes(1)))) {
            db.sql("UPDATE service_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?")
                    .params(Rows.now(), client.ip(), row.id()).update();
        }
        return Optional.of(new ServiceTokenPrincipal(row.id(), tokenId, row.name(), row.envId(), row.projectId(), row.keyVersion()));
    }

    public List<TokenView> list(UserPrincipal p, UUID envId) {
        access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        return db.sql("""
                SELECT t.*, u.email FROM service_tokens t LEFT JOIN users u ON u.id = t.created_by
                WHERE t.environment_id = ? AND t.revoked_at IS NULL ORDER BY t.created_at DESC
                """)
                .param(envId)
                .query((rs, i) -> new TokenView(Rows.uuid(rs, "id"), rs.getString("token_id"), rs.getString("name"),
                        rs.getString("email"), Rows.instant(rs, "created_at"), Rows.instant(rs, "expires_at"),
                        Rows.instant(rs, "last_used_at"), rs.getString("last_used_ip"), rs.getInt("key_version")))
                .list();
    }

    @Transactional
    public TokenView create(UserPrincipal p, UUID envId, CreateTokenRequest req) {
        var env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        if (req.keyVersion() != env.keyVersion()) throw ApiException.conflict("stale_key", "Environment key was rotated; reload");
        int active = db.sql("SELECT COUNT(*) FROM service_tokens WHERE environment_id = ? AND revoked_at IS NULL")
                .param(envId).query(Integer.class).single();
        if (active >= 50) throw ApiException.badRequest("Too many active tokens for this environment");
        UUID id = UUID.randomUUID();
        Instant expires = req.expiresInDays() == null ? null : Instant.now().plus(Duration.ofDays(req.expiresInDays()));
        db.sql("""
                INSERT INTO service_tokens (id, token_id, environment_id, name, verifier, wrapped_env_key, key_version,
                  created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)
                """)
                .params(id, req.tokenId(), envId, req.name().trim(), req.verifier(), req.wrappedEnvKey(), env.keyVersion(),
                        p.userId(), Rows.now(), Rows.ts(expires))
                .update();
        audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), "token.created").target("service_token", id)
                .details(Map.of("name", req.name().trim(), "environment", envId.toString(),
                        "expiresInDays", req.expiresInDays() == null ? "never" : req.expiresInDays())));
        return list(p, envId).stream().filter(t -> t.id().equals(id)).findFirst().orElseThrow();
    }

    @Transactional
    public void revoke(UserPrincipal p, UUID envId, UUID tokenRowId) {
        var env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, false);
        UUID creator = db.sql("SELECT created_by FROM service_tokens WHERE id = ? AND environment_id = ? AND revoked_at IS NULL")
                .params(tokenRowId, envId).query(UUID.class).optional()
                .orElseThrow(() -> ApiException.notFound("Token"));
        if (!creator.equals(p.userId()) && !env.role().atLeast(Role.ADMIN)) {
            throw ApiException.forbidden("Only the token's creator or an admin can revoke it");
        }
        db.sql("UPDATE service_tokens SET revoked_at = ? WHERE id = ?").params(Rows.now(), tokenRowId).update();
        audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), "token.revoked").target("service_token", tokenRowId));
    }

    public record ServiceSecrets(UUID projectId, UUID environmentId, String environmentName, String environmentSlug, int keyVersion, String tokenId,
                                 String wrappedEnvKey, List<dev.keyvault.secret.SecretDtos.SecretView> secrets) {}

    @Transactional
    public ServiceSecrets fetchForToken(ServiceTokenPrincipal t, dev.keyvault.secret.SecretService secrets) {
        record Env(String name, String slug, String wrapped) {}
        Env env = db.sql("SELECT e.name, e.slug, t.wrapped_env_key FROM service_tokens t JOIN environments e ON e.id = t.environment_id WHERE t.id = ?")
                .param(t.id()).query((rs, i) -> new Env(rs.getString(1), rs.getString(2), rs.getString(3))).single();
        var list = secrets.load(t.environmentId());
        metrics.secretsRead("service_token", list.size());
        audit.recordAsync(Event.of(Actor.token(t.id(), t.name()), t.projectId(), "secrets.read").target("environment", t.environmentId())
                .details(Map.of("count", list.size(), "via", "service_token")));
        return new ServiceSecrets(t.projectId(), t.environmentId(), env.name(), env.slug(), t.keyVersion(), t.tokenId(), env.wrapped(), list);
    }
}
