package dev.keyvault.secret;

import dev.keyvault.auth.Principals;
import dev.keyvault.secret.SecretDtos.*;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/environments/{envId}")
public class SecretController {
    private final SecretService secrets;

    public SecretController(SecretService secrets) {
        this.secrets = secrets;
    }

    @GetMapping("/secrets")
    public EnvironmentSecrets list(@PathVariable UUID envId) {
        return secrets.list(Principals.user(), envId);
    }

    @PostMapping("/secrets")
    public List<SecretView> create(@PathVariable UUID envId, @Valid @RequestBody BulkCreateRequest req) {
        return secrets.create(Principals.user(), envId, req);
    }

    @PutMapping("/secrets/{secretId}")
    public SecretView update(@PathVariable UUID envId, @PathVariable UUID secretId, @Valid @RequestBody UpdateSecretRequest req) {
        return secrets.update(Principals.user(), envId, secretId, req);
    }

    @DeleteMapping("/secrets/{secretId}")
    public ResponseEntity<Void> delete(@PathVariable UUID envId, @PathVariable UUID secretId) {
        secrets.delete(Principals.user(), envId, secretId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/secrets/{secretId}/versions")
    public List<VersionView> versions(@PathVariable UUID envId, @PathVariable UUID secretId) {
        return secrets.versions(Principals.user(), envId, secretId);
    }

    @PostMapping("/secrets/{secretId}/rollback")
    public SecretView rollback(@PathVariable UUID envId, @PathVariable UUID secretId, @Valid @RequestBody RollbackRequest req) {
        return secrets.rollback(Principals.user(), envId, secretId, req);
    }

    @GetMapping("/rotation")
    public Map<String, Object> rotationSnapshot(@PathVariable UUID envId) {
        return secrets.rotationSnapshot(Principals.user(), envId);
    }

    @PostMapping("/rotation")
    public RotateResult rotate(@PathVariable UUID envId, @Valid @RequestBody RotateRequest req) {
        return secrets.rotate(Principals.user(), envId, req);
    }
}
