package dev.keyvault.project;

import dev.keyvault.auth.Principals;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.RateLimiter;
import dev.keyvault.project.ProjectDtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@Validated
public class ProjectController {
    private final ProjectService projects;
    private final JdbcClient db;
    private final RateLimiter limiter;

    public ProjectController(ProjectService projects, JdbcClient db, RateLimiter limiter) {
        this.projects = projects;
        this.db = db;
        this.limiter = limiter;
    }

    @GetMapping("/projects")
    public List<ProjectSummary> list() {
        return projects.list(Principals.user());
    }

    @PostMapping("/projects")
    public ProjectDetail create(@Valid @RequestBody CreateProjectRequest req) {
        return projects.create(Principals.user(), req);
    }

    @GetMapping("/projects/{projectId}")
    public ProjectDetail detail(@PathVariable UUID projectId) {
        return projects.detail(Principals.user(), projectId);
    }

    @PatchMapping("/projects/{projectId}")
    public ProjectDetail update(@PathVariable UUID projectId, @Valid @RequestBody UpdateProjectRequest req) {
        projects.update(Principals.user(), projectId, req);
        return projects.detail(Principals.user(), projectId);
    }

    @DeleteMapping("/projects/{projectId}")
    public ResponseEntity<Void> delete(@PathVariable UUID projectId, @Valid @RequestBody DeleteProjectRequest req) {
        projects.delete(Principals.user(), projectId, req.confirmName());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/projects/{projectId}/environments")
    public ProjectDetail createEnvironment(@PathVariable UUID projectId, @Valid @RequestBody CreateEnvironmentRequest req) {
        projects.createEnvironment(Principals.user(), projectId, req);
        return projects.detail(Principals.user(), projectId);
    }

    @PatchMapping("/projects/{projectId}/environments/{envId}")
    public ProjectDetail renameEnvironment(@PathVariable UUID projectId, @PathVariable UUID envId,
                                           @Valid @RequestBody RenameEnvironmentRequest req) {
        projects.renameEnvironment(Principals.user(), projectId, envId, req.name());
        return projects.detail(Principals.user(), projectId);
    }

    @PutMapping("/projects/{projectId}/environments/{envId}/protection")
    public ProjectDetail setProtection(@PathVariable UUID projectId, @PathVariable UUID envId, @RequestBody ProtectionRequest req) {
        projects.setProtected(Principals.user(), projectId, envId, req.enabled());
        return projects.detail(Principals.user(), projectId);
    }

    @DeleteMapping("/projects/{projectId}/environments/{envId}")
    public ProjectDetail deleteEnvironment(@PathVariable UUID projectId, @PathVariable UUID envId) {
        projects.deleteEnvironment(Principals.user(), projectId, envId);
        return projects.detail(Principals.user(), projectId);
    }

    @PostMapping("/projects/{projectId}/members")
    public ProjectDetail addMember(@PathVariable UUID projectId, @Valid @RequestBody AddMemberRequest req) {
        projects.addMember(Principals.user(), projectId, req);
        return projects.detail(Principals.user(), projectId);
    }

    @PatchMapping("/projects/{projectId}/members/{userId}")
    public ProjectDetail changeRole(@PathVariable UUID projectId, @PathVariable UUID userId, @Valid @RequestBody ChangeRoleRequest req) {
        projects.changeRole(Principals.user(), projectId, userId, req.role());
        return projects.detail(Principals.user(), projectId);
    }

    @DeleteMapping("/projects/{projectId}/members/{userId}")
    public ResponseEntity<Void> removeMember(@PathVariable UUID projectId, @PathVariable UUID userId) {
        projects.removeMember(Principals.user(), projectId, userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/projects/{projectId}/environments/{envId}/grants/{userId}")
    public ProjectDetail setGrant(@PathVariable UUID projectId, @PathVariable UUID envId, @PathVariable UUID userId,
                                  @Valid @RequestBody SetGrantRequest req) {
        projects.setGrant(Principals.user(), projectId, envId, userId, req);
        return projects.detail(Principals.user(), projectId);
    }

    @DeleteMapping("/projects/{projectId}/environments/{envId}/grants/{userId}")
    public ProjectDetail revokeGrant(@PathVariable UUID projectId, @PathVariable UUID envId, @PathVariable UUID userId) {
        projects.revokeGrant(Principals.user(), projectId, envId, userId);
        return projects.detail(Principals.user(), projectId);
    }

    /**
     * Look up a registered user's public key so it can be used to seal environment keys for them.
     * The inviter should compare the key fingerprint out-of-band (shown in the UI) to rule out a
     * malicious server substituting its own key.
     */
    @GetMapping("/users/lookup")
    public UserLookup lookup(@RequestParam @Email String email, HttpServletRequest http) {
        var p = Principals.user();
        limiter.check(RateLimiter.Policy.LOOKUP, p.userId().toString());
        limiter.check(RateLimiter.Policy.LOOKUP, ClientInfo.of(http).ip());
        return db.sql("SELECT id, email, display_name, public_key FROM users WHERE email = ?")
                .param(email.trim().toLowerCase(Locale.ROOT))
                .query((rs, i) -> new UserLookup(rs.getObject("id", UUID.class), rs.getString("email"),
                        rs.getString("display_name"), rs.getString("public_key")))
                .optional()
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "user_not_found",
                        "No KeyVault account uses this email. Ask them to sign up first."));
    }
}
