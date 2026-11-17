package dev.keyvault.send;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.Codec;
import dev.keyvault.common.RateLimiter;
import dev.keyvault.common.Rows;
import dev.keyvault.common.Validation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

/**
 * One-time encrypted share links ("burn after reading"). The decryption key lives in the URL
 * fragment, which browsers never transmit, so the server only ever holds ciphertext.
 * Opening is a POST, so link-preview bots that issue GETs cannot burn a view.
 */
@RestController
public class SendController {
    private final JdbcClient db;
    private final AuditService audit;
    private final RateLimiter limiter;

    public SendController(JdbcClient db, AuditService audit, RateLimiter limiter) {
        this.db = db;
        this.audit = audit;
        this.limiter = limiter;
    }

    public record CreateSendRequest(
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String ciphertext,
            @Min(1) @Max(10) int maxViews,
            @Min(5) @Max(10080) int expiresInMinutes) {}

    public record SendView(String id, int maxViews, int viewCount, Instant expiresAt, Instant createdAt) {}

    public record OpenedSend(String ciphertext, int remainingViews, Instant expiresAt) {}

    @PostMapping("/api/sends")
    public SendView create(@Valid @RequestBody CreateSendRequest req) {
        var p = Principals.user();
        int active = db.sql("SELECT COUNT(*) FROM sends WHERE created_by = ? AND expires_at > ? AND view_count < max_views")
                .params(p.userId(), Rows.now()).query(Integer.class).single();
        if (active >= 100) throw ApiException.badRequest("Too many active share links");
        String id = Codec.randomToken(16);
        Instant expires = Instant.now().plus(Duration.ofMinutes(req.expiresInMinutes()));
        db.sql("INSERT INTO sends (id, ciphertext, max_views, expires_at, created_by, created_at) VALUES (?,?,?,?,?,?)")
                .params(id, req.ciphertext(), req.maxViews(), Rows.ts(expires), p.userId(), Rows.now()).update();
        audit.record(Event.of(Actor.user(p.userId(), p.email()), null, "send.created").target("send", id)
                .details(Map.of("maxViews", req.maxViews(), "expiresInMinutes", req.expiresInMinutes())));
        return new SendView(id, req.maxViews(), 0, expires, Instant.now());
    }

    @GetMapping("/api/sends")
    public List<SendView> mine() {
        return db.sql("SELECT * FROM sends WHERE created_by = ? ORDER BY created_at DESC LIMIT 100")
                .param(Principals.user().userId())
                .query((rs, i) -> new SendView(rs.getString("id"), rs.getInt("max_views"), rs.getInt("view_count"),
                        Rows.instant(rs, "expires_at"), Rows.instant(rs, "created_at")))
                .list();
    }

    @DeleteMapping("/api/sends/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        int n = db.sql("DELETE FROM sends WHERE id = ? AND created_by = ?").params(id, Principals.user().userId()).update();
        if (n == 0) throw ApiException.notFound("Share link");
        return ResponseEntity.noContent().build();
    }

    @Transactional
    @PostMapping("/api/public/sends/{id}/open")
    public OpenedSend open(@PathVariable String id, HttpServletRequest http) {
        limiter.check(RateLimiter.Policy.SEND_OPEN, ClientInfo.of(http).ip());
        if (!id.matches("^[A-Za-z0-9_-]{22}$")) throw ApiException.notFound("Share link");
        record Row(String ciphertext, int remaining, Instant expiresAt, UUID owner) {}
        // Atomic: two concurrent opens of a 1-view link cannot both succeed.
        Row row = db.sql("""
                UPDATE sends SET view_count = view_count + 1
                WHERE id = ? AND view_count < max_views AND expires_at > ?
                RETURNING ciphertext, max_views - view_count AS remaining, expires_at, created_by
                """)
                .params(id, Rows.now())
                .query((rs, i) -> new Row(rs.getString(1), rs.getInt(2), Rows.instant(rs, "expires_at"), Rows.uuid(rs, "created_by")))
                .optional()
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "send_unavailable",
                        "This link has expired, was already viewed, or never existed."));
        if (row.remaining() == 0) {
            db.sql("UPDATE sends SET ciphertext = '' WHERE id = ?").param(id).update(); // burn
        }
        audit.record(Event.of(Actor.anonymous(), null, "send.opened").target("send", id)
                .details(Map.of("remainingViews", row.remaining())), "user:" + row.owner());
        return new OpenedSend(row.ciphertext(), row.remaining(), row.expiresAt());
    }
}
