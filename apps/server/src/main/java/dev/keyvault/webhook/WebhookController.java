package dev.keyvault.webhook;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.Principals;
import dev.keyvault.common.Validation;
import dev.keyvault.project.AccessService;
import dev.keyvault.project.Role;
import dev.keyvault.webhook.WebhookService.Created;
import dev.keyvault.webhook.WebhookService.DeliveryView;
import dev.keyvault.webhook.WebhookService.WebhookView;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/projects/{projectId}/webhooks")
public class WebhookController {
    private final WebhookService webhooks;
    private final AccessService access;
    private final AuditService audit;

    public WebhookController(WebhookService webhooks, AccessService access, AuditService audit) {
        this.webhooks = webhooks;
        this.access = access;
        this.audit = audit;
    }

    public record CreateWebhookRequest(
            @NotBlank @Size(max = 2048) String url,
            @Pattern(regexp = Validation.UUID) String environmentId,
            @NotNull @Size(min = 1, max = 10) List<@NotBlank String> events) {}

    public record ToggleRequest(boolean enabled) {}

    private void admin(UUID projectId) {
        access.requireRole(projectId, Principals.user().userId(), Role.ADMIN);
    }

    @GetMapping
    public Map<String, Object> list(@PathVariable UUID projectId) {
        admin(projectId);
        return Map.of("webhooks", webhooks.list(projectId), "events", WebhookService.EVENTS);
    }

    @PostMapping
    @Transactional
    public Created create(@PathVariable UUID projectId, @Valid @RequestBody CreateWebhookRequest req) {
        admin(projectId);
        var p = Principals.user();
        UUID envId = req.environmentId() == null ? null : UUID.fromString(req.environmentId());
        if (envId != null) access.requireEnv(envId, p.userId(), Role.ADMIN, false);
        Created c = webhooks.create(projectId, envId, req.url(), req.events(), p.userId());
        audit.record(Event.of(Actor.user(p.userId(), p.email()), projectId, "webhook.created").target("webhook", c.webhook().id())
                .details(Map.of("url", c.webhook().url(), "events", req.events())));
        return c;
    }

    @PatchMapping("/{id}")
    public List<WebhookView> toggle(@PathVariable UUID projectId, @PathVariable UUID id, @RequestBody ToggleRequest req) {
        admin(projectId);
        webhooks.setEnabled(projectId, id, req.enabled());
        return webhooks.list(projectId);
    }

    @DeleteMapping("/{id}")
    @Transactional
    public ResponseEntity<Void> delete(@PathVariable UUID projectId, @PathVariable UUID id) {
        admin(projectId);
        var p = Principals.user();
        webhooks.delete(projectId, id);
        audit.record(Event.of(Actor.user(p.userId(), p.email()), projectId, "webhook.deleted").target("webhook", id));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/ping")
    public DeliveryView ping(@PathVariable UUID projectId, @PathVariable UUID id) {
        admin(projectId);
        return webhooks.ping(projectId, id);
    }

    @GetMapping("/{id}/deliveries")
    public List<DeliveryView> deliveries(@PathVariable UUID projectId, @PathVariable UUID id) {
        admin(projectId);
        return webhooks.deliveries(projectId, id);
    }

    @PostMapping("/deliveries/{deliveryId}/redeliver")
    public ResponseEntity<Void> redeliver(@PathVariable UUID projectId, @PathVariable UUID deliveryId) {
        admin(projectId);
        webhooks.redeliver(projectId, deliveryId);
        return ResponseEntity.accepted().build();
    }
}
