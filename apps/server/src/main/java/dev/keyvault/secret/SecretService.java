package dev.keyvault.secret;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals.UserPrincipal;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.Rows;
import dev.keyvault.project.AccessService;
import dev.keyvault.project.AccessService.EnvContext;
import dev.keyvault.project.ProjectDtos.GrantInput;
import dev.keyvault.project.Role;
import dev.keyvault.secret.SecretDtos.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretService {
    private final JdbcClient db;
    private final AccessService access;
    private final AuditService audit;
    private final dev.keyvault.common.KeyVaultMetrics metrics;
    private final dev.keyvault.webhook.WebhookService webhooks;

    public SecretService(JdbcClient db, AccessService access, AuditService audit, dev.keyvault.common.KeyVaultMetrics metrics,
                         dev.keyvault.webhook.WebhookService webhooks) {
        this.webhooks = webhooks;
        this.metrics = metrics;
        this.db = db;
        this.access = access;
        this.audit = audit;
    }

    private static Actor actor(UserPrincipal p) { return Actor.user(p.userId(), p.email()); }

    @Transactional
    public EnvironmentSecrets list(UserPrincipal p, UUID envId) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.VIEWER, true);
        List<SecretView> secrets = load(envId);
        metrics.secretsRead("user", secrets.size());
        audit.recordAsync(Event.of(actor(p), env.projectId(), "secrets.read").target("environment", envId)
                .details(Map.of("count", secrets.size())));
        return new EnvironmentSecrets(env.projectId(), envId, env.name(), env.keyVersion(), secrets);
    }

    public List<SecretView> load(UUID envId) {
        return db.sql("""
                SELECT s.*, u.email AS updated_by_email FROM secrets s LEFT JOIN users u ON u.id = s.updated_by
                WHERE s.environment_id = ? ORDER BY s.created_at, s.id
                """)
                .param(envId)
                .query((rs, i) -> new SecretView(Rows.uuid(rs, "id"), rs.getString("name_ciphertext"),
                        rs.getString("value_ciphertext"), rs.getString("comment_ciphertext"), rs.getInt("version"),
                        rs.getInt("key_version"), Rows.instant(rs, "created_at"), Rows.instant(rs, "updated_at"),
                        rs.getString("updated_by_email")))
                .list();
    }

    @Transactional
    public List<SecretView> create(UserPrincipal p, UUID envId, BulkCreateRequest req) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        guardProtected(env);
        Set<String> ids = insertNew(env, req.secrets(), p.userId());
        metrics.secretsWritten("create", req.secrets().size());
        audit.record(Event.of(actor(p), env.projectId(), "secret.created").target("environment", envId)
                .details(Map.of("count", req.secrets().size(), "ids", ids.stream().sorted().toList())));
        webhooks.enqueue(env.projectId(), envId, "secret.created", Map.of("secretIds", ids.stream().sorted().toList(), "actor", p.email()));
        return load(envId);
    }

    /** Inserts new secrets after checking ids and blind-index uniqueness under the environment lock. */
    private Set<String> insertNew(EnvContext env, List<SecretInput> secrets, UUID by) {
        UUID envId = env.environmentId();
        lockEnvironment(envId);
        Set<String> ids = new HashSet<>();
        Set<String> indexes = new HashSet<>();
        for (SecretInput s : secrets) {
            requireCurrentKey(env, s.keyVersion());
            if (!ids.add(s.id())) throw ApiException.badRequest("Duplicate secret id in request");
            if (!indexes.add(s.nameIndex())) throw ApiException.conflict("duplicate_name", "The same secret name appears twice");
        }
        int clashes = db.sql("SELECT COUNT(*) FROM secrets WHERE environment_id = :env AND name_index IN (:idx)")
                .param("env", envId).param("idx", indexes).query(Integer.class).single();
        if (clashes > 0) throw ApiException.conflict("duplicate_name", clashes + " secret name(s) already exist in this environment");

        var now = Rows.now();
        for (SecretInput s : secrets) {
            UUID id = UUID.fromString(s.id());
            int n = db.sql("""
                    INSERT INTO secrets (id, environment_id, name_index, name_ciphertext, value_ciphertext, comment_ciphertext,
                      version, key_version, created_by, updated_by, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,1,?,?,?,?,?) ON CONFLICT (id) DO NOTHING
                    """)
                    .params(id, envId, s.nameIndex(), s.nameCiphertext(), s.valueCiphertext(), s.commentCiphertext(),
                            env.keyVersion(), by, by, now, now)
                    .update();
            if (n == 0) throw ApiException.conflict("duplicate_id", "Secret id already in use");
            insertVersion(id, 1, s.nameIndex(), s.nameCiphertext(), s.valueCiphertext(), s.commentCiphertext(), env.keyVersion(), "CREATE", by);
        }
        return ids;
    }

    @Transactional
    public SecretView update(UserPrincipal p, UUID envId, UUID secretId, UpdateSecretRequest req) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        guardProtected(env);
        requireCurrentKey(env, req.keyVersion());
        int newVersion = applyChange(p.userId(), envId, secretId, req.expectedVersion(), req.nameIndex(), req.nameCiphertext(),
                req.valueCiphertext(), req.commentCiphertext(), env.keyVersion(), "UPDATE");
        metrics.secretsWritten("update", 1);
        audit.record(Event.of(actor(p), env.projectId(), "secret.updated").target("secret", secretId)
                .details(Map.of("environment", envId.toString(), "version", newVersion)));
        webhooks.enqueue(env.projectId(), envId, "secret.updated", Map.of("secretIds", List.of(secretId.toString()), "version", newVersion, "actor", p.email()));
        return one(envId, secretId);
    }

    @Transactional
    public SecretView rollback(UserPrincipal p, UUID envId, UUID secretId, RollbackRequest req) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        guardProtected(env);
        record Old(String nameIndex, String name, String value, String comment, int keyVersion) {}
        Old old = db.sql("""
                SELECT v.* FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
                WHERE v.secret_id = ? AND s.environment_id = ? AND v.version = ?
                """)
                .params(secretId, envId, req.toVersion())
                .query((rs, i) -> new Old(rs.getString("name_index"), rs.getString("name_ciphertext"), rs.getString("value_ciphertext"),
                        rs.getString("comment_ciphertext"), rs.getInt("key_version")))
                .optional().orElseThrow(() -> ApiException.notFound("Version"));
        requireCurrentKey(env, old.keyVersion());
        int newVersion = applyChange(p.userId(), envId, secretId, req.expectedVersion(), old.nameIndex(), old.name(), old.value(),
                old.comment(), env.keyVersion(), "ROLLBACK");
        audit.record(Event.of(actor(p), env.projectId(), "secret.rolled_back").target("secret", secretId)
                .details(Map.of("environment", envId.toString(), "restoredVersion", req.toVersion(), "version", newVersion)));
        webhooks.enqueue(env.projectId(), envId, "secret.rolled_back", Map.of("secretIds", List.of(secretId.toString()), "version", newVersion, "actor", p.email()));
        return one(envId, secretId);
    }

    @Transactional
    public void delete(UserPrincipal p, UUID envId, UUID secretId) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.DEVELOPER, true);
        guardProtected(env);
        int n = db.sql("DELETE FROM secrets WHERE id = ? AND environment_id = ?").params(secretId, envId).update();
        if (n == 0) throw ApiException.notFound("Secret");
        audit.record(Event.of(actor(p), env.projectId(), "secret.deleted").target("secret", secretId)
                .details(Map.of("environment", envId.toString())));
        webhooks.enqueue(env.projectId(), envId, "secret.deleted", Map.of("secretIds", List.of(secretId.toString()), "actor", p.email()));
    }

    public List<VersionView> versions(UserPrincipal p, UUID envId, UUID secretId) {
        access.requireEnv(envId, p.userId(), Role.VIEWER, true);
        return db.sql("""
                SELECT v.*, u.email FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
                LEFT JOIN users u ON u.id = v.changed_by
                WHERE v.secret_id = ? AND s.environment_id = ? ORDER BY v.version DESC LIMIT 100
                """)
                .params(secretId, envId)
                .query((rs, i) -> new VersionView(rs.getInt("version"), rs.getString("name_ciphertext"),
                        rs.getString("value_ciphertext"), rs.getString("comment_ciphertext"), rs.getInt("key_version"),
                        rs.getString("change_type"), rs.getString("email"), Rows.instant(rs, "created_at")))
                .list();
    }

    /** Everything an admin's client needs to re-encrypt for rotation: all secrets with full history. */
    public Map<String, Object> rotationSnapshot(UserPrincipal p, UUID envId) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.ADMIN, true);
        List<SecretView> secrets = load(envId);
        Map<UUID, List<VersionView>> history = new HashMap<>();
        for (SecretView s : secrets) history.put(s.id(), versions(p, envId, s.id()));
        return Map.of("keyVersion", env.keyVersion(), "projectId", env.projectId(), "secrets", secrets, "versions", history);
    }

    @Transactional
    public RotateResult rotate(UserPrincipal p, UUID envId, RotateRequest req) {
        EnvContext env = access.requireEnv(envId, p.userId(), Role.ADMIN, true);
        int current = lockEnvironment(envId);
        if (current != req.expectedKeyVersion()) {
            throw ApiException.conflict("stale_key", "The environment key changed while you were rotating; reload and retry");
        }
        int next = current + 1;

        // The payload must cover exactly the stored secrets and versions, or data would be orphaned.
        Map<UUID, Set<Integer>> stored = new HashMap<>();
        db.sql("SELECT v.secret_id, v.version FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.environment_id = ?")
                .param(envId).query(rs -> {
                    stored.computeIfAbsent(rs.getObject(1, UUID.class), k -> new HashSet<>()).add(rs.getInt(2));
                });
        Map<UUID, RotatedSecret> incoming = req.secrets().stream().collect(Collectors.toMap(s -> UUID.fromString(s.id()), s -> s, (a, b) -> {
            throw ApiException.badRequest("Duplicate secret in rotation payload");
        }));
        if (!stored.keySet().equals(incoming.keySet())) {
            throw ApiException.conflict("rotation_mismatch", "Secrets changed during rotation; reload and retry");
        }
        for (var e : incoming.entrySet()) {
            Set<Integer> versions = e.getValue().versions().stream().map(RotatedVersion::version).collect(Collectors.toSet());
            if (!versions.equals(stored.get(e.getKey()))) {
                throw ApiException.conflict("rotation_mismatch", "Secret history changed during rotation; reload and retry");
            }
        }
        Set<UUID> grantees = new HashSet<>();
        for (GrantInput g : req.grants()) {
            UUID uid = UUID.fromString(g.userId());
            if (access.roleOf(env.projectId(), uid).isEmpty()) throw ApiException.badRequest("Grant target is not a project member");
            if (!grantees.add(uid)) throw ApiException.badRequest("Duplicate grant");
        }
        if (!grantees.contains(p.userId())) throw ApiException.badRequest("You must keep access to the rotated key");

        var now = Rows.now();
        for (RotatedSecret s : incoming.values()) {
            UUID sid = UUID.fromString(s.id());
            db.sql("""
                    UPDATE secrets SET name_index = ?, name_ciphertext = ?, value_ciphertext = ?, comment_ciphertext = ?,
                      key_version = ? WHERE id = ?
                    """).params(s.nameIndex(), s.nameCiphertext(), s.valueCiphertext(), s.commentCiphertext(), next, sid).update();
            for (RotatedVersion v : s.versions()) {
                db.sql("""
                        UPDATE secret_versions SET name_index = ?, name_ciphertext = ?, value_ciphertext = ?, comment_ciphertext = ?,
                          key_version = ? WHERE secret_id = ? AND version = ?
                        """).params(v.nameIndex(), v.nameCiphertext(), v.valueCiphertext(), v.commentCiphertext(), next, sid, v.version()).update();
            }
        }
        db.sql("DELETE FROM environment_key_grants WHERE environment_id = ?").param(envId).update();
        for (GrantInput g : req.grants()) {
            db.sql("INSERT INTO environment_key_grants (environment_id, user_id, wrapped_key, key_version, granted_by, created_at) VALUES (?,?,?,?,?,?)")
                    .params(envId, UUID.fromString(g.userId()), g.wrappedKey(), next, p.userId(), now).update();
        }
        int tokens = db.sql("UPDATE service_tokens SET revoked_at = ? WHERE environment_id = ? AND revoked_at IS NULL")
                .params(now, envId).update();
        db.sql("UPDATE environments SET key_version = ?, rotation_needed = FALSE WHERE id = ?").params(next, envId).update();

        metrics.rotation();
        audit.record(Event.of(actor(p), env.projectId(), "environment.key_rotated").target("environment", envId)
                .details(Map.of("keyVersion", next, "secrets", incoming.size(), "members", grantees.size(), "tokensRevoked", tokens)));
        webhooks.enqueue(env.projectId(), envId, "environment.key_rotated", Map.of("keyVersion", next, "tokensRevoked", tokens, "actor", p.email()));
        // Open change requests were encrypted with the old key and can no longer apply.
        db.sql("UPDATE change_requests SET status = 'CONFLICT', review_comment = 'Environment key rotated', closed_at = ? WHERE environment_id = ? AND status = 'OPEN'")
                .params(now, envId).update();
        return new RotateResult(next, incoming.size(), grantees.size(), tokens);
    }

    // ------------------------------------------------------------------- helpers

    private int applyChange(UUID by, UUID envId, UUID secretId, int expectedVersion, String nameIndex, String name,
                            String value, String comment, int keyVersion, String changeType) {
        boolean clash = db.sql("SELECT EXISTS(SELECT 1 FROM secrets WHERE environment_id = ? AND name_index = ? AND id <> ?)")
                .params(envId, nameIndex, secretId).query(Boolean.class).single();
        if (clash) throw ApiException.conflict("duplicate_name", "Another secret in this environment already has that name");
        // Optimistic concurrency: the update only applies if nobody changed the secret since the client read it.
        Integer newVersion = db.sql("""
                UPDATE secrets SET name_index = ?, name_ciphertext = ?, value_ciphertext = ?, comment_ciphertext = ?,
                  version = version + 1, key_version = ?, updated_by = ?, updated_at = ?
                WHERE id = ? AND environment_id = ? AND version = ? RETURNING version
                """)
                .params(nameIndex, name, value, comment, keyVersion, by, Rows.now(), secretId, envId, expectedVersion)
                .query(Integer.class).optional().orElse(null);
        if (newVersion == null) {
            boolean exists = db.sql("SELECT EXISTS(SELECT 1 FROM secrets WHERE id = ? AND environment_id = ?)")
                    .params(secretId, envId).query(Boolean.class).single();
            if (!exists) throw ApiException.notFound("Secret");
            throw ApiException.conflict("version_conflict", "Someone else changed this secret. Reload to see the latest value.");
        }
        insertVersion(secretId, newVersion, nameIndex, name, value, comment, keyVersion, changeType, by);
        return newVersion;
    }

    private void insertVersion(UUID secretId, int version, String nameIndex, String name, String value, String comment,
                               int keyVersion, String changeType, UUID by) {
        db.sql("""
                INSERT INTO secret_versions (secret_id, version, name_index, name_ciphertext, value_ciphertext, comment_ciphertext,
                  key_version, change_type, changed_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)
                """)
                .params(secretId, version, nameIndex, name, value, comment, keyVersion, changeType, by, Rows.now()).update();
    }

    private SecretView one(UUID envId, UUID secretId) {
        return load(envId).stream().filter(s -> s.id().equals(secretId)).findFirst()
                .orElseThrow(() -> ApiException.notFound("Secret"));
    }

    /** Protected environments only accept direct writes from admins; everyone else proposes a change request. */
    private static void guardProtected(EnvContext env) {
        if (env.protectedEnv() && !env.role().atLeast(Role.ADMIN)) {
            throw ApiException.conflict("protected_environment", env.name() + " is protected. Propose the change for review instead.");
        }
    }

    public record ChangeItem(String op, UUID secretId, Integer expectedVersion, String nameIndex, String name, String value, String comment) {}

    /**
     * Applies an approved change request atomically under the environment lock. Returns null on
     * success, or the reason it no longer applies cleanly (someone changed the secrets meanwhile).
     * Nothing is written in the conflict case: all checks run before the first write.
     */
    public String applyChangeRequest(EnvContext env, int requestKeyVersion, UUID authorId, List<ChangeItem> items) {
        UUID envId = env.environmentId();
        int current = lockEnvironment(envId);
        if (current != requestKeyVersion) return "The environment key was rotated after this request was opened";
        Set<String> newIndexes = new HashSet<>();
        for (ChangeItem it : items) {
            if (it.op().equals("CREATE")) {
                if (!newIndexes.add(it.nameIndex())) return "The request adds the same name twice";
                boolean taken = db.sql("SELECT EXISTS(SELECT 1 FROM secrets WHERE environment_id = ? AND name_index = ?)")
                        .params(envId, it.nameIndex()).query(Boolean.class).single();
                if (taken) return "A secret with one of the proposed names was created meanwhile";
                continue;
            }
            Integer v = db.sql("SELECT version FROM secrets WHERE id = ? AND environment_id = ?").params(it.secretId(), envId)
                    .query(Integer.class).optional().orElse(null);
            if (v == null) return "A secret in this request was deleted meanwhile";
            if (!v.equals(it.expectedVersion())) return "A secret in this request was changed meanwhile (now v" + v + ")";
            if (it.op().equals("UPDATE")) {
                boolean clash = db.sql("SELECT EXISTS(SELECT 1 FROM secrets WHERE environment_id = ? AND name_index = ? AND id <> ?)")
                        .params(envId, it.nameIndex(), it.secretId()).query(Boolean.class).single();
                if (clash) return "Another secret already uses one of the proposed names";
            }
        }
        List<SecretInput> creates = items.stream().filter(i -> i.op().equals("CREATE"))
                .map(i -> new SecretInput(i.secretId().toString(), i.nameIndex(), i.name(), i.value(), i.comment(), requestKeyVersion)).toList();
        if (!creates.isEmpty()) insertNew(env, creates, authorId);
        for (ChangeItem it : items) {
            switch (it.op()) {
                case "UPDATE" -> applyChange(authorId, envId, it.secretId(), it.expectedVersion(), it.nameIndex(), it.name(),
                        it.value(), it.comment(), requestKeyVersion, "UPDATE");
                case "DELETE" -> db.sql("DELETE FROM secrets WHERE id = ? AND environment_id = ?").params(it.secretId(), envId).update();
                default -> { }
            }
        }
        metrics.secretsWritten("change_request", items.size());
        return null;
    }

    /** Serialises writers per environment so name uniqueness and rotation checks are race-free. */
    private int lockEnvironment(UUID envId) {
        return db.sql("SELECT key_version FROM environments WHERE id = ? FOR UPDATE").param(envId).query(Integer.class).single();
    }

    private static void requireCurrentKey(EnvContext env, int keyVersion) {
        if (keyVersion != env.keyVersion()) {
            throw ApiException.conflict("stale_key", "This environment's key was rotated. Reload to get the new key.");
        }
    }
}
