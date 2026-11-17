package dev.keyvault.auth;

import dev.keyvault.auth.Principals.KvAuthentication;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.token.ServiceTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Servlet filters wired into the Spring Security chain by {@link dev.keyvault.config.SecurityConfig}. */
public final class AuthFilters {
    private AuthFilters() {}

    /** Resolves the caller from the session cookie or a service-token Authorization header. */
    public static final class Authenticate extends OncePerRequestFilter {
        private static final String SERVICE_SCHEME = "KV-Service-Token ";
        private final SessionService sessions;
        private final ServiceTokenService tokens;

        public Authenticate(SessionService sessions, ServiceTokenService tokens) {
            this.sessions = sessions;
            this.tokens = tokens;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            String authz = req.getHeader("Authorization");
            try {
                if (authz != null && authz.startsWith(SERVICE_SCHEME)) {
                    tokens.authenticate(authz.substring(SERVICE_SCHEME.length()).trim(), ClientInfo.of(req))
                            .ifPresent(p -> SecurityContextHolder.getContext().setAuthentication(new KvAuthentication(p, "SERVICE")));
                } else if (req.getCookies() != null) {
                    for (Cookie c : req.getCookies()) {
                        if (c.getName().equals(sessions.cookieName())) {
                            sessions.authenticate(c.getValue()).ifPresent(p -> SecurityContextHolder.getContext()
                                    .setAuthentication(new KvAuthentication(p, "USER")));
                            break;
                        }
                    }
                }
            } catch (ApiException e) {
                writeError(res, e.status(), e.code(), e.getMessage());
                return;
            }
            chain.doFilter(req, res);
        }
    }

    /**
     * CSRF defence for cookie-authenticated, state-changing requests:
     *  1. SameSite=Strict session cookie (browser-level),
     *  2. a custom header that cross-site forms cannot send without a CORS preflight we never allow,
     *  3. Origin header, when present, must match the configured app origin.
     */
    public static final class CsrfGuard extends OncePerRequestFilter {
        private static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS", "TRACE");
        private final String appOrigin;

        public CsrfGuard(String appOrigin) {
            URI u = URI.create(appOrigin);
            this.appOrigin = u.getScheme() + "://" + u.getRawAuthority();
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            boolean unsafe = !SAFE.contains(req.getMethod());
            boolean api = req.getRequestURI().startsWith("/api/");
            boolean serviceCall = req.getHeader("Authorization") != null;
            if (unsafe && api && !serviceCall) {
                String origin = req.getHeader("Origin");
                if (!"1".equals(req.getHeader("X-KV-Request")) || (origin != null && !origin.equals(appOrigin))) {
                    writeError(res, HttpStatus.FORBIDDEN, "csrf_rejected", "Cross-site request rejected");
                    return;
                }
            }
            chain.doFilter(req, res);
        }
    }

    static void writeError(HttpServletResponse res, HttpStatus status, String code, String message) throws IOException {
        res.setStatus(status.value());
        res.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        String safe = message.replace("\\", "\\\\").replace("\"", "\\\"");
        res.getWriter().write("{\"status\":" + status.value() + ",\"title\":\"" + status.getReasonPhrase()
                + "\",\"code\":\"" + code + "\",\"detail\":\"" + safe + "\"}");
    }
}
