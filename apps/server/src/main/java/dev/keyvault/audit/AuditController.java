package dev.keyvault.audit;

import dev.keyvault.audit.AuditService.EventView;
import dev.keyvault.audit.AuditService.VerifyResult;
import dev.keyvault.auth.Principals;
import dev.keyvault.project.AccessService;
import dev.keyvault.project.Role;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/projects/{projectId}/audit")
public class AuditController {
    private final AuditService audit;
    private final AccessService access;

    public AuditController(AuditService audit, AccessService access) {
        this.audit = audit;
        this.access = access;
    }

    @GetMapping
    public List<EventView> list(@PathVariable UUID projectId, @RequestParam(required = false) Long before,
                                @RequestParam(defaultValue = "50") int limit) {
        access.requireRole(projectId, Principals.user().userId(), Role.DEVELOPER);
        return audit.list("project:" + projectId, before, limit);
    }

    @GetMapping("/verify")
    public VerifyResult verify(@PathVariable UUID projectId) {
        access.requireRole(projectId, Principals.user().userId(), Role.DEVELOPER);
        return audit.verify("project:" + projectId);
    }
}
