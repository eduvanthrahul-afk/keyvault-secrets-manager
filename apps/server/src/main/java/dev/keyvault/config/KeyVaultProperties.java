package dev.keyvault.config;

import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * All runtime configuration lives here and is supplied through environment variables
 * in production (see .env.example). Nothing secret is committed to the repository.
 */
@Validated
@ConfigurationProperties("keyvault")
public record KeyVaultProperties(
        /** Public origin of the web app, e.g. https://keyvault.example.com. Used for Origin checks. */
        @NotBlank String appOrigin,
        /** Base64 32-byte key used for server-side encryption of TOTP seeds and anti-enumeration HMACs. */
        @NotBlank String serverKey,
        Session session,
        @DefaultValue("true") boolean registrationEnabled,
        /** Bearer token required to scrape /actuator/prometheus; blank disables scraping. */
        String metricsToken) {

    public record Session(
            @DefaultValue("__Host-kv_session") String cookieName,
            @DefaultValue("true") boolean secureCookie,
            @DefaultValue("30m") Duration idleTimeout,
            @DefaultValue("12h") Duration absoluteTimeout) {}

    public KeyVaultProperties {
        if (session == null) {
            session = new Session("__Host-kv_session", true, Duration.ofMinutes(30), Duration.ofHours(12));
        }
    }
}
