package dev.keyvault.auth;

import dev.keyvault.common.ApiException;
import java.util.List;
import java.util.UUID;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/** The two kinds of callers: humans with a browser session, and machines with a service token. */
public final class Principals {
    private Principals() {}

    public record UserPrincipal(UUID userId, String email, UUID sessionId) {}

    public record ServiceTokenPrincipal(UUID id, String tokenId, String name, UUID environmentId, UUID projectId, int keyVersion) {}

    public static final class KvAuthentication extends AbstractAuthenticationToken {
        private final Object principal;

        public KvAuthentication(Object principal, String role) {
            super(List.of(new SimpleGrantedAuthority("ROLE_" + role)));
            this.principal = principal;
            setAuthenticated(true);
        }

        @Override public Object getCredentials() { return ""; }
        @Override public Object getPrincipal() { return principal; }
    }

    public static UserPrincipal user() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof UserPrincipal p) return p;
        throw ApiException.unauthorized("Sign in required");
    }

    public static ServiceTokenPrincipal serviceToken() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof ServiceTokenPrincipal p) return p;
        throw ApiException.unauthorized("Service token required");
    }
}
