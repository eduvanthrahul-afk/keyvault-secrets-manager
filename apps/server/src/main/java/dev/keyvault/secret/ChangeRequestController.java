package dev.keyvault.secret;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.Rows;
import dev.keyvault.common.Validation;
import dev.keyvault.project.AccessService;
import dev.keyvault.project.AccessService.EnvContext;
import dev.keyvault.project.Role;
import dev.keyvault.secret.SecretService.ChangeItem;
import dev.keyvault.webhook.WebhookService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

/**
 * Change requests for protected environments (four-eyes principle). The author's browser encrypts
 * the proposed values with the environment key; a reviewer decrypts them in THEIR browser to see the
 * diff; on approval the server swaps ciphertext in atomically. The server never sees plaintext.
 */
@RestController
@RequestMapping("/api/environments/{envId}/change-requests")
public class ChangeRequestController {
    private final JdbcClient db;
    private final AccessService access;
    private final SecretService secrets;
    private final AuditService audit;
    private final WebhookService webhooks;

    public ChangeRequestController(JdbcClient db, AccessService access, SecretService secrets, AuditService audit, WebhookService webhooks) {
        this.db = db;
        this.access = access;
        this.secrets = secrets;
        this.audit = audit;
        this.webhooks = webhooks;
    }

    public record ItemInput(
            @NotNull @Pattern(regexp = "^(CREATE|UPDATE|DELETE)$") String op,
            @NotBlank @Pattern(regexp = Validation.UUID) String secretId,
            Integer expectedVersion,
            @Pattern(regexp = Validation.KEY_32) String nameIndex,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String nameCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String valueCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String commentCiphertext) {}

    public record CreateRequest(@NotBlank @Size(max = 140) String title, int keyVersion,
                                @NotNull @Size(min = 1, max = 500) List<@Valid ItemInput> items) {}

    public record ReviewRequest(@Size(max = 500) String comment) {}

    public record ItemView(String op, UUID secretId, Integer expectedVersion, String nameCiphertext, String valueCiphertext,
                           String commentCiphertext) {}

    public record ChangeRequestView(UUID id, UUID environmentId, String title, String status, UUID authorId, String author,
                                    String reviewer, String reviewComment, int keyVersion, Instant createdAt, Instant closedAt,
                                    int itemCount, List<ItemView> items) {}

    @GetMapping
    public List<ChangeRequestView> list(@PathVariable UUID envId, @RequestParam(defaultValue = "OPEN") String status) {
        access.requireEnv(envId, Principals.user().userId(), Role.VIEWER, true);
        return db.sql("""
                SELECT c.*, a.email AS author, r.email AS reviewer,
                  (SELECT COUNT(*) FROM change_request_items i WHERE i.change_request_id = c.id) AS item_count
                FROM change_requests c LEFT JOIN users a ON a.id = c.author_id LEFT JOIN users r ON r.id = c.reviewer_id
                WHERE c.environment_id = ? AND (? = 'ALL' OR c.status = ?) ORDER BY c.created_at DESC LIMIT 100
                """)
                .params(envId, status, status)
                .query((rs, i) -> view(rs, List.of()))
                .list();
    }

    @GetMapping("/{id}")
    public ChangeRequestView get(@PathVariable UUID envId, @PathVariable UUID id) {
        access.requireEnv(envId, Principals.user().userId(), Role.VIEWER, true);
        return load(envId, id);
    }

    @PostMapping
    @Transactional
    public ChangeRequestView create(@PathVariable UUID envId, @Valid @RequestBody CreateRequest req) {
        var p = Principals.user();
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        if (req.keyVersion() != env.keyVersion()) throw ApiException.conflict("stale_key", "Environment key was rotated; reload");
        Set<String> ids = new HashSet<>();
        for (ItemInput it : req.items()) {
            if (!ids.add(it.secretId())) throw ApiException.badRequest("Each secret may appear once per request");
            boolean needsBody = !it.op().equals("DELETE");
            if (needsBody && (it.nameIndex() == null || it.nameCiphertext() == null || it.valueCiphertext() == null)) {
                throw ApiException.badRequest(it.op() + " items need name and value ciphertext");
            }
            if (!it.op().equals("CREATE") && it.expectedVersion() == null) {
                throw ApiException.badRequest(it.op() + " items need the version they were based on");
            }
        }
        UUID id = UUID.randomUUID();
        db.sql("INSERT INTO change_requests (id, environment_id, author_id, title, status, key_version, created_at) VALUES (?,?,?,?, 'OPEN', ?, ?)")
                .params(id, envId, p.userId(), req.title().trim(), env.keyVersion(), Rows.now()).update();
        for (ItemInput it : req.items()) {
            db.sql("""
                    INSERT INTO change_request_items (change_request_id, op, secret_id, expected_version, name_index, name_ciphertext,
                      value_ciphertext, comment_ciphertext) VALUES (?,?,?,?,?,?,?,?)
                    """)
                    .params(id, it.op(), UUID.fromString(it.secretId()), it.expectedVersion(), it.nameIndex(), it.nameCiphertext(),
                            it.valueCiphertext(), it.commentCiphertext())
                    .update();
        }
        audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), "change_request.opened").target("change_request", id)
                .details(Map.of("environment", envId.toString(), "title", req.title().trim(), "items", req.items().size())));
        webhooks.enqueue(env.projectId(), envId, "change_request.opened", Map.of("changeRequestId", id.toString(), "author", p.email(), "items", req.items().size()));
        return load(envId, id);
    }

    @PostMapping("/{id}/approve")
    @Transactional
    public ChangeRequestView approve(@PathVariable UUID envId, @PathVariable UUID id, @Valid @RequestBody(required = false) ReviewRequest req) {
        var p = Principals.user();
        EnvContext env = access.requireEnv(envId, p.userId(), Role.ADMIN, true);
        ChangeRequestView cr = lockOpen(envId, id);
        if (p.userId().equals(cr.authorId())) {
            throw ApiException.forbidden("You can't approve your own change request; another admin has to review it");
        }
        List<ChangeItem> items = cr.items().stream().map(i -> new ChangeItem(i.op(), i.secretId(), i.expectedVersion(), null,
                i.nameCiphertext(), i.valueCiphertext(), i.commentCiphertext())).toList();
        // name_index isn't in the view; fetch it alongside
        List<String> indexes = db.sql("SELECT name_index FROM change_request_items WHERE change_request_id = ? ORDER BY id").param(id)
                .query(String.class).list();
        List<ChangeItem> withIndex = new java.util.ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            ChangeItem c = items.get(i);
            withIndex.add(new ChangeItem(c.op(), c.secretId(), c.expectedVersion(), indexes.get(i), c.name(), c.value(), c.comment()));
        }
        String conflict = secrets.applyChangeRequest(env, cr.keyVersion(), cr.authorId() == null ? p.userId() : cr.authorId(), withIndex);
        String comment = req == null ? null : req.comment();
        if (conflict != null) {
            close(id, "CONFLICT", p.userId(), conflict);
            audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), "change_request.conflict").target("change_request", id)
                    .details(Map.of("reason", conflict)));
            return load(envId, id);
        }
        close(id, "APPLIED", p.userId(), comment);
        audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), "change_request.applied").target("change_request", id)
                .details(Map.of("environment", envId.toString(), "author", String.valueOf(cr.author()), "items", items.size())));
        webhooks.enqueue(env.projectId(), envId, "change_request.applied",
                Map.of("changeRequestId", id.toString(), "approvedBy", p.email(), "secretIds", items.stream().map(i -> i.secretId().toString()).toList()));
        return load(envId, id);
    }

    @PostMapping("/{id}/reject")
    @Transactional
    public ChangeRequestView reject(@PathVariable UUID envId, @PathVariable UUID id, @Valid @RequestBody ReviewRequest req) {
        var p = Principals.user();
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        ChangeRequestView cr = lockOpen(envId, id);
        boolean author = p.userId().equals(cr.authorId());
        if (!author && !env.role().atLeast(Role.ADMIN)) throw ApiException.forbidden("Only admins or the author can close this request");
        close(id, author ? "CANCELLED" : "REJECTED", p.userId(), req.comment());
        audit.record(Event.of(Actor.user(p.userId(), p.email()), env.projectId(), author ? "change_request.cancelled" : "change_request.rejected")
                .target("change_request", id));
        if (!author) webhooks.enqueue(env.projectId(), envId, "change_request.rejected", Map.of("changeRequestId", id.toString(), "rejectedBy", p.email()));
        return load(envId, id);
    }

    // ------------------------------------------------------------------ helpers

    private ChangeRequestView lockOpen(UUID envId, UUID id) {
        String status = db.sql("SELECT status FROM change_requests WHERE id = ? AND environment_id = ? FOR UPDATE").params(id, envId)
                .query(String.class).optional().orElseThrow(() -> ApiException.notFound("Change request"));
        if (!status.equals("OPEN")) throw ApiException.conflict("not_open", "This change request is already " + status.toLowerCase());
        return load(envId, id);
    }

    private void close(UUID id, String status, UUID reviewer, String comment) {
        db.sql("UPDATE change_requests SET status = ?, reviewer_id = ?, review_comment = ?, closed_at = ? WHERE id = ?")
                .params(status, reviewer, comment, Rows.now(), id).update();
    }

    private ChangeRequestView load(UUID envId, UUID id) {
        List<ItemView> items = db.sql("SELECT * FROM change_request_items WHERE change_request_id = ? ORDER BY id").param(id)
                .query((rs, i) -> new ItemView(rs.getString("op"), Rows.uuid(rs, "secret_id"), (Integer) rs.getObject("expected_version"),
                        rs.getString("name_ciphertext"), rs.getString("value_ciphertext"), rs.getString("comment_ciphertext")))
                .list();
        return db.sql("""
                SELECT c.*, a.email AS author, r.email AS reviewer, 0 AS item_count
                FROM change_requests c LEFT JOIN users a ON a.id = c.author_id LEFT JOIN users r ON r.id = c.reviewer_id
                WHERE c.id = ? AND c.environment_id = ?
                """)
                .params(id, envId)
                .query((rs, i) -> view(rs, items))
                .optional().orElseThrow(() -> ApiException.notFound("Change request"));
    }

    private static ChangeRequestView view(java.sql.ResultSet rs, List<ItemView> items) throws java.sql.SQLException {
        return new ChangeRequestView(Rows.uuid(rs, "id"), Rows.uuid(rs, "environment_id"), rs.getString("title"), rs.getString("status"),
                Rows.uuid(rs, "author_id"), rs.getString("author"), rs.getString("reviewer"), rs.getString("review_comment"),
                rs.getInt("key_version"), Rows.instant(rs, "created_at"), Rows.instant(rs, "closed_at"),
                items.isEmpty() ? rs.getInt("item_count") : items.size(), items);
    }
}
