package dev.keyvault.project;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals.UserPrincipal;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.Rows;
import dev.keyvault.project.ProjectDtos.*;
import java.sql.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProjectService {
    private final JdbcClient db;
    private final AccessService access;
    private final AuditService audit;

    public ProjectService(JdbcClient db, AccessService access, AuditService audit) {
        this.db = db;
        this.access = access;
        this.audit = audit;
    }

    private static Actor actor(UserPrincipal p) { return Actor.user(p.userId(), p.email()); }

    // ------------------------------------------------------------------ projects

    public List<ProjectSummary> list(UserPrincipal p) {
        return db.sql("""
                SELECT pr.id, pr.name, pr.description, m.role, pr.created_at, pr.updated_at,
                  (SELECT COUNT(*) FROM environments e WHERE e.project_id = pr.id) AS env_count,
                  (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = pr.id) AS member_count,
                  (SELECT COUNT(*) FROM secrets s JOIN environments e ON e.id = s.environment_id WHERE e.project_id = pr.id) AS secret_count,
                  EXISTS(SELECT 1 FROM environments e WHERE e.project_id = pr.id AND e.rotation_needed) AS rotation_needed
                FROM projects pr JOIN project_members m ON m.project_id = pr.id AND m.user_id = ?
                ORDER BY pr.updated_at DESC
                """)
                .param(p.userId())
                .query((rs, i) -> new ProjectSummary(Rows.uuid(rs, "id"), rs.getString("name"), rs.getString("description"),
                        Role.valueOf(rs.getString("role")), rs.getInt("env_count"), rs.getInt("member_count"),
                        rs.getInt("secret_count"), rs.getBoolean("rotation_needed"), Rows.instant(rs, "created_at"),
                        Rows.instant(rs, "updated_at")))
                .list();
    }

    @Transactional
    public ProjectDetail create(UserPrincipal p, CreateProjectRequest req) {
        UUID projectId = UUID.fromString(req.id());
        Set<String> slugs = new HashSet<>();
        for (NewEnvironment e : req.environments()) {
            if (!slugs.add(e.slug())) throw ApiException.badRequest("Duplicate environment slug: " + e.slug());
        }
        db.sql("INSERT INTO projects (id, name, description, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)")
                .params(projectId, req.name().trim(), req.description() == null ? "" : req.description().trim(), p.userId(),
                        Rows.now(), Rows.now())
                .update();
        db.sql("INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?,?,?,?)")
                .params(projectId, p.userId(), Role.OWNER.name(), Rows.now()).update();
        int pos = 0;
        for (NewEnvironment e : req.environments()) {
            UUID envId = UUID.fromString(e.id());
            insertEnvironment(envId, projectId, e.name().trim(), e.slug(), pos++);
            if (e.slug().matches("^(prod|production|live)$")) {
                db.sql("UPDATE environments SET protected = TRUE WHERE id = ?").param(envId).update();
            }
            insertGrant(envId, p.userId(), e.wrappedKey(), 1, p.userId());
        }
        audit.record(Event.of(actor(p), projectId, "project.created").target("project", projectId)
                .details(Map.of("name", req.name().trim(), "environments", req.environments().stream().map(NewEnvironment::slug).toList())));
        return detail(p, projectId);
    }

    public ProjectDetail detail(UserPrincipal p, UUID projectId) {
        Role role = access.requireRole(projectId, p.userId(), Role.VIEWER);
        record Head(String name, String description, java.time.Instant createdAt) {}
        Head head = db.sql("SELECT name, description, created_at FROM projects WHERE id = ?").param(projectId)
                .query((rs, i) -> new Head(rs.getString(1), rs.getString(2), Rows.instant(rs, "created_at"))).single();

        List<EnvironmentView> envs = db.sql("""
                SELECT e.*, g.wrapped_key, g.key_version AS grant_version,
                  (SELECT COUNT(*) FROM secrets s WHERE s.environment_id = e.id) AS secret_count,
                  (SELECT COUNT(*) FROM service_tokens t WHERE t.environment_id = e.id AND t.revoked_at IS NULL) AS token_count,
                  (SELECT COUNT(*) FROM change_requests c WHERE c.environment_id = e.id AND c.status = 'OPEN') AS open_crs
                FROM environments e
                LEFT JOIN environment_key_grants g ON g.environment_id = e.id AND g.user_id = ?
                WHERE e.project_id = ? ORDER BY e.position, e.created_at
                """)
                .params(p.userId(), projectId)
                .query((rs, i) -> new EnvironmentView(Rows.uuid(rs, "id"), rs.getString("name"), rs.getString("slug"),
                        rs.getInt("position"), rs.getInt("key_version"), rs.getBoolean("rotation_needed"),
                        rs.getInt("secret_count"), rs.getInt("token_count"), rs.getString("wrapped_key"),
                        (Integer) rs.getObject("grant_version"), rs.getBoolean("protected"), rs.getInt("open_crs")))
                .list();

        List<MemberView> members = db.sql("""
                SELECT u.id, u.email, u.display_name, u.public_key, m.role, m.created_at,
                  ARRAY(SELECT g.environment_id FROM environment_key_grants g JOIN environments e ON e.id = g.environment_id
                        WHERE g.user_id = u.id AND e.project_id = m.project_id) AS env_ids
                FROM project_members m JOIN users u ON u.id = m.user_id
                WHERE m.project_id = ?
                ORDER BY CASE m.role WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 WHEN 'DEVELOPER' THEN 2 ELSE 3 END, u.email
                """)
                .param(projectId)
                .query((rs, i) -> new MemberView(Rows.uuid(rs, "id"), rs.getString("email"), rs.getString("display_name"),
                        rs.getString("public_key"), Role.valueOf(rs.getString("role")), uuidArray(rs.getArray("env_ids")),
                        Rows.instant(rs, "created_at")))
                .list();
        return new ProjectDetail(projectId, head.name(), head.description(), role, head.createdAt(), envs, members);
    }

    @Transactional
    public void update(UserPrincipal p, UUID projectId, UpdateProjectRequest req) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        db.sql("UPDATE projects SET name = ?, description = ?, updated_at = ? WHERE id = ?")
                .params(req.name().trim(), req.description() == null ? "" : req.description().trim(), Rows.now(), projectId).update();
        audit.record(Event.of(actor(p), projectId, "project.updated").target("project", projectId)
                .details(Map.of("name", req.name().trim())));
    }

    @Transactional
    public void delete(UserPrincipal p, UUID projectId, String confirmName) {
        access.requireRole(projectId, p.userId(), Role.OWNER);
        String name = db.sql("SELECT name FROM projects WHERE id = ?").param(projectId).query(String.class).single();
        if (!name.equals(confirmName)) throw ApiException.badRequest("Type the project name exactly to confirm deletion");
        audit.record(Event.of(actor(p), projectId, "project.deleted").target("project", projectId).details(Map.of("name", name)));
        db.sql("DELETE FROM projects WHERE id = ?").param(projectId).update(); // cascades envs, secrets, grants, tokens
    }

    // -------------------------------------------------------------- environments

    @Transactional
    public void createEnvironment(UserPrincipal p, UUID projectId, CreateEnvironmentRequest req) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        UUID envId = UUID.fromString(req.id());
        boolean selfGranted = req.grants().stream().anyMatch(g -> UUID.fromString(g.userId()).equals(p.userId()));
        if (!selfGranted) throw ApiException.badRequest("The creator must grant the new environment key to themselves");
        Integer next = db.sql("SELECT COALESCE(MAX(position), -1) + 1 FROM environments WHERE project_id = ?")
                .param(projectId).query(Integer.class).single();
        int count = db.sql("SELECT COUNT(*) FROM environments WHERE project_id = ?").param(projectId).query(Integer.class).single();
        if (count >= 10) throw ApiException.badRequest("A project can have at most 10 environments");
        insertEnvironment(envId, projectId, req.name().trim(), req.slug(), next);
        for (GrantInput g : req.grants()) {
            UUID uid = UUID.fromString(g.userId());
            if (access.roleOf(projectId, uid).isEmpty()) throw ApiException.badRequest("Grant target is not a project member");
            insertGrant(envId, uid, g.wrappedKey(), 1, p.userId());
        }
        touch(projectId);
        audit.record(Event.of(actor(p), projectId, "environment.created").target("environment", envId)
                .details(Map.of("slug", req.slug(), "grantedTo", req.grants().size())));
    }

    @Transactional
    public void renameEnvironment(UserPrincipal p, UUID projectId, UUID envId, String name) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        int n = db.sql("UPDATE environments SET name = ? WHERE id = ? AND project_id = ?").params(name.trim(), envId, projectId).update();
        if (n == 0) throw ApiException.notFound("Environment");
        audit.record(Event.of(actor(p), projectId, "environment.renamed").target("environment", envId).details(Map.of("name", name.trim())));
    }

    @Transactional
    public void setProtected(UserPrincipal p, UUID projectId, UUID envId, boolean enabled) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        int n = db.sql("UPDATE environments SET protected = ? WHERE id = ? AND project_id = ?").params(enabled, envId, projectId).update();
        if (n == 0) throw ApiException.notFound("Environment");
        audit.record(Event.of(actor(p), projectId, enabled ? "environment.protected" : "environment.unprotected").target("environment", envId));
    }

    @Transactional
    public void deleteEnvironment(UserPrincipal p, UUID projectId, UUID envId) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        int count = db.sql("SELECT COUNT(*) FROM environments WHERE project_id = ?").param(projectId).query(Integer.class).single();
        if (count <= 1) throw ApiException.badRequest("A project needs at least one environment");
        int n = db.sql("DELETE FROM environments WHERE id = ? AND project_id = ?").params(envId, projectId).update();
        if (n == 0) throw ApiException.notFound("Environment");
        touch(projectId);
        audit.record(Event.of(actor(p), projectId, "environment.deleted").target("environment", envId));
    }

    // ------------------------------------------------------------------- members

    @Transactional
    public void addMember(UserPrincipal p, UUID projectId, AddMemberRequest req) {
        Role mine = access.requireRole(projectId, p.userId(), Role.ADMIN);
        UUID target = UUID.fromString(req.userId());
        if (!mine.atLeast(req.role()) || (req.role() == Role.OWNER && mine != Role.OWNER)) {
            throw ApiException.forbidden("You cannot grant a role higher than your own");
        }
        if (access.roleOf(projectId, target).isPresent()) throw ApiException.conflict("already_member", "User is already a member");
        boolean exists = db.sql("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)").param(target).query(Boolean.class).single();
        if (!exists) throw ApiException.notFound("User");
        db.sql("INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?,?,?,?)")
                .params(projectId, target, req.role().name(), Rows.now()).update();
        for (EnvGrantInput g : req.grants()) {
            grantInternal(p, projectId, UUID.fromString(g.environmentId()), target, g.wrappedKey(), null);
        }
        touch(projectId);
        audit.record(Event.of(actor(p), projectId, "member.added").target("user", target)
                .details(Map.of("role", req.role().name(), "environments", req.grants().size())));
    }

    @Transactional
    public void changeRole(UserPrincipal p, UUID projectId, UUID target, Role newRole) {
        Role mine = access.requireRole(projectId, p.userId(), Role.ADMIN);
        Role current = access.roleOf(projectId, target).orElseThrow(() -> ApiException.notFound("Member"));
        boolean ownerAction = current == Role.OWNER || newRole == Role.OWNER;
        if (ownerAction && mine != Role.OWNER) throw ApiException.forbidden("Only owners can change owner roles");
        if (mine != Role.OWNER && !mine.atLeast(newRole)) throw ApiException.forbidden("You cannot grant a role higher than your own");
        if (mine != Role.OWNER && current.atLeast(mine) && !target.equals(p.userId())) {
            throw ApiException.forbidden("You cannot change the role of a member at or above your level");
        }
        if (current == Role.OWNER && newRole != Role.OWNER) ensureAnotherOwner(projectId, target);
        db.sql("UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?")
                .params(newRole.name(), projectId, target).update();
        audit.record(Event.of(actor(p), projectId, "member.role_changed").target("user", target)
                .details(Map.of("from", current.name(), "to", newRole.name())));
    }

    /**
     * Removing a member deletes their wrapped keys, but they may have cached plaintext keys or
     * secrets. Every environment they could decrypt is therefore flagged for key rotation.
     */
    @Transactional
    public void removeMember(UserPrincipal p, UUID projectId, UUID target) {
        boolean self = target.equals(p.userId());
        Role mine = access.requireRole(projectId, p.userId(), self ? Role.VIEWER : Role.ADMIN);
        Role theirs = access.roleOf(projectId, target).orElseThrow(() -> ApiException.notFound("Member"));
        if (!self && mine != Role.OWNER && theirs.atLeast(mine)) {
            throw ApiException.forbidden("You cannot remove a member at or above your level");
        }
        if (theirs == Role.OWNER) ensureAnotherOwner(projectId, target);
        int flagged = db.sql("""
                UPDATE environments SET rotation_needed = TRUE
                WHERE project_id = ? AND id IN (SELECT environment_id FROM environment_key_grants WHERE user_id = ?)
                """).params(projectId, target).update();
        db.sql("DELETE FROM environment_key_grants WHERE user_id = ? AND environment_id IN (SELECT id FROM environments WHERE project_id = ?)")
                .params(target, projectId).update();
        db.sql("DELETE FROM project_members WHERE project_id = ? AND user_id = ?").params(projectId, target).update();
        touch(projectId);
        audit.record(Event.of(actor(p), projectId, self ? "member.left" : "member.removed").target("user", target)
                .details(Map.of("environmentsFlaggedForRotation", flagged)));
    }

    @Transactional
    public void setGrant(UserPrincipal p, UUID projectId, UUID envId, UUID target, SetGrantRequest req) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        if (access.roleOf(projectId, target).isEmpty()) throw ApiException.notFound("Member");
        grantInternal(p, projectId, envId, target, req.wrappedKey(), req.keyVersion());
        audit.record(Event.of(actor(p), projectId, "grant.set").target("environment", envId).details(Map.of("user", target.toString())));
    }

    @Transactional
    public void revokeGrant(UserPrincipal p, UUID projectId, UUID envId, UUID target) {
        access.requireRole(projectId, p.userId(), Role.ADMIN);
        int n = db.sql("""
                DELETE FROM environment_key_grants WHERE environment_id = ? AND user_id = ?
                  AND environment_id IN (SELECT id FROM environments WHERE project_id = ?)
                """).params(envId, target, projectId).update();
        if (n == 0) throw ApiException.notFound("Grant");
        db.sql("UPDATE environments SET rotation_needed = TRUE WHERE id = ?").param(envId).update();
        audit.record(Event.of(actor(p), projectId, "grant.revoked").target("environment", envId).details(Map.of("user", target.toString())));
    }

    // ------------------------------------------------------------------- helpers

    /** The granter must hold the environment key themselves, and must wrap the CURRENT key version. */
    private void grantInternal(UserPrincipal p, UUID projectId, UUID envId, UUID target, String wrappedKey, Integer claimedVersion) {
        var env = access.requireEnv(envId, p.userId(), Role.ADMIN, true);
        if (!env.projectId().equals(projectId)) throw ApiException.notFound("Environment");
        if (claimedVersion != null && claimedVersion != env.keyVersion()) {
            throw ApiException.conflict("stale_key", "Environment key has been rotated; reload and try again");
        }
        db.sql("""
                INSERT INTO environment_key_grants (environment_id, user_id, wrapped_key, key_version, granted_by, created_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT (environment_id, user_id) DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key,
                  key_version = EXCLUDED.key_version, granted_by = EXCLUDED.granted_by, created_at = EXCLUDED.created_at
                """)
                .params(envId, target, wrappedKey, env.keyVersion(), p.userId(), Rows.now()).update();
    }

    private void insertEnvironment(UUID id, UUID projectId, String name, String slug, int position) {
        try {
            db.sql("INSERT INTO environments (id, project_id, name, slug, position, created_at) VALUES (?,?,?,?,?,?)")
                    .params(id, projectId, name, slug, position, Rows.now()).update();
        } catch (org.springframework.dao.DuplicateKeyException e) {
            throw ApiException.conflict("duplicate_environment", "An environment with this slug already exists");
        }
    }

    private void insertGrant(UUID envId, UUID userId, String wrappedKey, int version, UUID grantedBy) {
        db.sql("INSERT INTO environment_key_grants (environment_id, user_id, wrapped_key, key_version, granted_by, created_at) VALUES (?,?,?,?,?,?)")
                .params(envId, userId, wrappedKey, version, grantedBy, Rows.now()).update();
    }

    private void ensureAnotherOwner(UUID projectId, UUID leaving) {
        int owners = db.sql("SELECT COUNT(*) FROM project_members WHERE project_id = ? AND role = 'OWNER' AND user_id <> ?")
                .params(projectId, leaving).query(Integer.class).single();
        if (owners == 0) throw ApiException.conflict("last_owner", "Transfer ownership before removing the last owner");
    }

    private void touch(UUID projectId) {
        db.sql("UPDATE projects SET updated_at = ? WHERE id = ?").params(Rows.now(), projectId).update();
    }

    private static List<UUID> uuidArray(Array array) throws java.sql.SQLException {
        if (array == null) return List.of();
        Object[] raw = (Object[]) array.getArray();
        return new ArrayList<>(Arrays.stream(raw).map(o -> (UUID) o).toList());
    }
}
