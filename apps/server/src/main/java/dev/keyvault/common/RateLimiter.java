package dev.keyvault.common;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;

/**
 * Token-bucket rate limiting (Bucket4j). Buckets live in a bounded Caffeine cache so an
 * attacker spraying random keys cannot exhaust memory. For multi-instance deployments swap
 * the cache for Bucket4j's Redis/Postgres proxy manager; the call sites stay the same.
 */
@Component
public class RateLimiter {
    public enum Policy {
        LOGIN_IP(20, Duration.ofMinutes(5)),
        LOGIN_ACCOUNT(8, Duration.ofMinutes(15)),
        REGISTER_IP(5, Duration.ofHours(1)),
        MFA(6, Duration.ofMinutes(5)),
        RECOVERY(5, Duration.ofHours(1)),
        LOOKUP(60, Duration.ofMinutes(1)),
        SERVICE_TOKEN(120, Duration.ofMinutes(1)),
        SEND_OPEN(30, Duration.ofMinutes(5)),
        API(600, Duration.ofMinutes(1));

        final long capacity;
        final Duration period;

        Policy(long capacity, Duration period) {
            this.capacity = capacity;
            this.period = period;
        }
    }

    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .maximumSize(200_000)
            .expireAfterAccess(2, TimeUnit.HOURS)
            .build();

    private final boolean enabled;
    private volatile java.util.function.Consumer<Policy> onLimited = p -> {};

    /** Hook for metrics; kept as a callback so the limiter has no Micrometer dependency. */
    public void onLimited(java.util.function.Consumer<Policy> listener) {
        this.onLimited = listener;
    }

    public RateLimiter(@org.springframework.beans.factory.annotation.Value("${keyvault.rate-limit.enabled:true}") boolean enabled) {
        this.enabled = enabled;
    }

    public void check(Policy policy, String key) {
        if (!enabled) return;
        Bucket bucket = buckets.get(policy.name() + ':' + key, k -> Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(policy.capacity).refillGreedy(policy.capacity, policy.period).build())
                .build());
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            onLimited.accept(policy);
            throw new RateLimitedException(Math.max(1, TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill())));
        }
    }

    /** Clears an account bucket after a successful login so honest typos don't accumulate. */
    public void reset(Policy policy, String key) {
        buckets.invalidate(policy.name() + ':' + key);
    }
}
