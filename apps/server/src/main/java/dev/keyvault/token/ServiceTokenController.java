package dev.keyvault.token;

import dev.keyvault.auth.Principals;
import dev.keyvault.secret.SecretService;
import dev.keyvault.token.ServiceTokenService.CreateTokenRequest;
import dev.keyvault.token.ServiceTokenService.ServiceSecrets;
import dev.keyvault.token.ServiceTokenService.TokenView;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class ServiceTokenController {
    private final ServiceTokenService tokens;
    private final SecretService secrets;

    public ServiceTokenController(ServiceTokenService tokens, SecretService secrets) {
        this.tokens = tokens;
        this.secrets = secrets;
    }

    @GetMapping("/api/environments/{envId}/tokens")
    public List<TokenView> list(@PathVariable UUID envId) {
        return tokens.list(Principals.user(), envId);
    }

    @PostMapping("/api/environments/{envId}/tokens")
    public TokenView create(@PathVariable UUID envId, @Valid @RequestBody CreateTokenRequest req) {
        return tokens.create(Principals.user(), envId, req);
    }

    @DeleteMapping("/api/environments/{envId}/tokens/{tokenId}")
    public ResponseEntity<Void> revoke(@PathVariable UUID envId, @PathVariable UUID tokenId) {
        tokens.revoke(Principals.user(), envId, tokenId);
        return ResponseEntity.noContent().build();
    }

    /** Machine endpoint used by the CLI / CI. Authorization: KV-Service-Token &lt;tokenId&gt;.&lt;authSecret&gt; */
    @GetMapping("/api/v1/service/secrets")
    public ServiceSecrets fetch() {
        return tokens.fetchForToken(Principals.serviceToken(), secrets);
    }
}
