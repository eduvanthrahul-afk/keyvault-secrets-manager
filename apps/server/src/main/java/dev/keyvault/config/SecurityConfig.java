package dev.keyvault.config;

import dev.keyvault.auth.AuthFilters;
import dev.keyvault.auth.SessionService;
import dev.keyvault.token.ServiceTokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

@Configuration
public class SecurityConfig {

    /**
     * Strict CSP: no inline scripts, no third-party origins. 'wasm-unsafe-eval' is required only to
     * instantiate the Argon2 WebAssembly module (it does NOT permit JS eval).
     */
    static final String CSP = String.join("; ",
            "default-src 'self'",
            "script-src 'self' 'wasm-unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests");

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, SessionService sessions, ServiceTokenService tokens,
                                    KeyVaultProperties props) throws Exception {
        http
                .csrf(c -> c.disable()) // replaced by AuthFilters.CsrfGuard (SameSite + custom header + Origin)
                .cors(c -> c.disable()) // single origin: the SPA is served by this app
                .formLogin(f -> f.disable())
                .httpBasic(b -> b.disable())
                .logout(l -> l.disable())
                .requestCache(r -> r.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/prelogin", "/api/auth/register", "/api/auth/login",
                                "/api/auth/login/mfa", "/api/auth/recover/start", "/api/auth/recover/complete").permitAll()
                        .requestMatchers("/api/public/**", "/api/config").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/actuator/prometheus").access((authentication, ctx) -> new AuthorizationDecision(
                                metricsAuthorized(props.metricsToken(), ctx.getRequest().getHeader("Authorization"))))
                        .requestMatchers("/api/v1/service/**").hasRole("SERVICE")
                        .requestMatchers("/api/**", "/actuator/**").hasRole("USER")
                        .anyRequest().permitAll()) // static SPA assets
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) -> problem(res, 401, "unauthorized", "Sign in required"))
                        .accessDeniedHandler((req, res, ex) -> problem(res, 403, "forbidden", "Not allowed")))
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CSP))
                        .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                        .frameOptions(f -> f.deny())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()"))
                        .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Opener-Policy", "same-origin"))
                        .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Resource-Policy", "same-origin")))
                .addFilterBefore(new AuthFilters.Authenticate(sessions, tokens), AnonymousAuthenticationFilter.class)
                .addFilterAfter(new AuthFilters.CsrfGuard(props.appOrigin()), AuthFilters.Authenticate.class);
        return http.build();
    }

    /** Constant-time bearer check; a blank configured token always denies. */
    static boolean metricsAuthorized(String token, String header) {
        if (token == null || token.isBlank() || header == null) return false;
        return dev.keyvault.common.Codec.constantTimeEquals("Bearer " + token.trim(), header.trim());
    }

    private static void problem(HttpServletResponse res, int status, String code, String detail) throws java.io.IOException {
        res.setStatus(status);
        res.setContentType("application/problem+json");
        res.getWriter().write("{\"status\":" + status + ",\"code\":\"" + code + "\",\"detail\":\"" + detail + "\"}");
    }
}
