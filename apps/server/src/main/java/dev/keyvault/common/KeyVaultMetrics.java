package dev.keyvault.common;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Security-relevant counters exported to Prometheus (see monitoring/grafana). Labels are low
 * cardinality on purpose: never user ids, emails or project ids.
 */
@Component
public class KeyVaultMetrics {
    private final MeterRegistry registry;

    public KeyVaultMetrics(MeterRegistry registry, RateLimiter limiter) {
        this.registry = registry;
        limiter.onLimited(p -> registry.counter("keyvault.rate_limited", "policy", p.name().toLowerCase()).increment());
    }

    public void login(String result) {
        registry.counter("keyvault.auth.logins", "result", result).increment();
    }

    public void secretsRead(String via, int count) {
        registry.counter("keyvault.secrets.reads", "via", via).increment();
        registry.counter("keyvault.secrets.decryptable_values_served", "via", via).increment(count);
    }

    public void secretsWritten(String kind, int count) {
        registry.counter("keyvault.secrets.writes", "kind", kind).increment(count);
    }

    public void rotation() {
        registry.counter("keyvault.keys.rotations").increment();
    }

    public void passkeyUnlock() {
        registry.counter("keyvault.auth.passkey_unlocks").increment();
    }

    public Counter registrations() {
        return registry.counter("keyvault.auth.registrations");
    }
}
