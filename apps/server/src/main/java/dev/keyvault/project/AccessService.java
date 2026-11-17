package dev.keyvault.project;

import dev.keyvault.common.ApiException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/**
 * Central authorisation checks. Non-members get 404 (not 403) so project and environment ids
 * cannot be probed for existence.
 */
@Service
public class AccessService {
    private final JdbcClient db;

    public AccessService(JdbcClient db) {
        this.db = db;
    }

    public record EnvContext(UUID environmentId, UUID projectId, String name, String slug, int keyVersion, Role role, boolean hasGrant,
                             boolean protectedEnv) {}

    public Optional<Role> roleOf(UUID projectId, UUID userId) {
        return db.sql("SELECT role FROM project_members WHERE project_id = ? AND user_id = ?")
                .params(projectId, userId).query(String.class).optional().map(Role::valueOf);
    }

    public Role requireRole(UUID projectId, UUID userId, Role minimum) {
        Role role = roleOf(projectId, userId).orElseThrow(() -> ApiException.notFound("Project"));
        if (!role.atLeast(minimum)) {
            throw ApiException.forbidden("This action requires the " + minimum.name().toLowerCase() + " role or higher");
        }
        return role;
    }

    public EnvContext requireEnv(UUID environmentId, UUID userId, Role minimum, boolean requireGrant) {
        EnvContext ctx = db.sql("""
                SELECT e.id, e.project_id, e.name, e.slug, e.key_version, e.protected, m.role,
                       EXISTS(SELECT 1 FROM environment_key_grants g WHERE g.environment_id = e.id AND g.user_id = m.user_id) AS has_grant
                FROM environments e JOIN project_members m ON m.project_id = e.project_id AND m.user_id = ?
                WHERE e.id = ?
                """)
                .params(userId, environmentId)
                .query((rs, i) -> new EnvContext(rs.getObject("id", UUID.class), rs.getObject("project_id", UUID.class),
                        rs.getString("name"), rs.getString("slug"), rs.getInt("key_version"), Role.valueOf(rs.getString("role")),
                        rs.getBoolean("has_grant"), rs.getBoolean("protected")))
                .optional()
                .orElseThrow(() -> ApiException.notFound("Environment"));
        if (!ctx.role().atLeast(minimum)) {
            throw ApiException.forbidden("This action requires the " + minimum.name().toLowerCase() + " role or higher");
        }
        if (requireGrant && !ctx.hasGrant()) {
            throw ApiException.forbidden("You have not been granted access to the " + ctx.name() + " environment");
        }
        return ctx;
    }
}
