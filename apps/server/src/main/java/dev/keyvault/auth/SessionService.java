package dev.keyvault.auth;

import dev.keyvault.auth.Principals.UserPrincipal;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.Codec;
import dev.keyvault.common.Rows;
import dev.keyvault.config.KeyVaultProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.ResponseCookie;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/**
 * Opaque, server-side sessions instead of JWTs: instantly revocable, nothing sensitive in the
 * token, and only SHA-256(token) is stored so a database leak does not yield usable cookies.
 */
@Service
public class SessionService {
    private static final Duration TOUCH_INTERVAL = Duration.ofSeconds(60);

    private final JdbcClient db;
    private final KeyVaultProperties.Session cfg;

    public SessionService(JdbcClient db, KeyVaultProperties props) {
        this.db = db;
        this.cfg = props.session();
    }

    public record SessionView(UUID id, Instant createdAt, Instant lastSeenAt, Instant expiresAt, String ip, String userAgent, boolean current) {}

    public String create(UUID userId, ClientInfo client) {
        String raw = Codec.randomToken(32);
        Instant now = Instant.now();
        db.sql("""
                INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent)
                VALUES (?,?,?,?,?,?,?,?)
                """)
                .params(UUID.randomUUID(), userId, Codec.sha256Hex(raw), Rows.ts(now), Rows.ts(now),
                        Rows.ts(now.plus(cfg.absoluteTimeout())), client.ip(), client.userAgent())
                .update();
        return raw;
    }

    public Optional<UserPrincipal> authenticate(String raw) {
        if (raw == null || raw.length() != 43) return Optional.empty();
        Instant now = Instant.now();
        record Row(UUID id, UUID userId, String email, Instant lastSeen) {}
        Optional<Row> row = db.sql("""
                SELECT s.id, s.user_id, u.email, s.last_seen_at FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.last_seen_at > ?
                """)
                .params(Codec.sha256Hex(raw), Rows.ts(now), Rows.ts(now.minus(cfg.idleTimeout())))
                .query((rs, i) -> new Row(Rows.uuid(rs, "id"), Rows.uuid(rs, "user_id"), rs.getString("email"), Rows.instant(rs, "last_seen_at")))
                .optional();
        row.filter(r -> r.lastSeen().isBefore(now.minus(TOUCH_INTERVAL)))
                .ifPresent(r -> db.sql("UPDATE sessions SET last_seen_at = ? WHERE id = ?").params(Rows.ts(now), r.id()).update());
        return row.map(r -> new UserPrincipal(r.userId(), r.email(), r.id()));
    }

    public List<SessionView> list(UUID userId, UUID currentSessionId) {
        return db.sql("""
                SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
                ORDER BY last_seen_at DESC
                """)
                .params(userId, Rows.now())
                .query((rs, i) -> new SessionView(Rows.uuid(rs, "id"), Rows.instant(rs, "created_at"),
                        Rows.instant(rs, "last_seen_at"), Rows.instant(rs, "expires_at"), rs.getString("ip"),
                        rs.getString("user_agent"), Rows.uuid(rs, "id").equals(currentSessionId)))
                .list();
    }

    public boolean revoke(UUID userId, UUID sessionId) {
        return db.sql("UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL")
                .params(Rows.now(), sessionId, userId).update() == 1;
    }

    public int revokeAll(UUID userId, UUID exceptSessionId) {
        return db.sql("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id <> ?")
                .params(Rows.now(), userId, exceptSessionId == null ? new UUID(0, 0) : exceptSessionId).update();
    }

    public int purgeExpired() {
        return db.sql("DELETE FROM sessions WHERE expires_at < ? OR revoked_at < ?")
                .params(Rows.now(), Rows.ts(Instant.now().minus(Duration.ofDays(7)))).update();
    }

    public String cookieName() { return cfg.cookieName(); }

    public ResponseCookie cookie(String raw) {
        return ResponseCookie.from(cfg.cookieName(), raw)
                .httpOnly(true)
                .secure(cfg.secureCookie())
                .sameSite("Strict")
                .path("/")
                .maxAge(cfg.absoluteTimeout())
                .build();
    }

    public ResponseCookie clearCookie() {
        return ResponseCookie.from(cfg.cookieName(), "").httpOnly(true).secure(cfg.secureCookie())
                .sameSite("Strict").path("/").maxAge(0).build();
    }
}
