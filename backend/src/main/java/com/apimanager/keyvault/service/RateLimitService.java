package com.apimanager.keyvault.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimitService {

    // Defense-in-Depth: Use a cache with eviction to prevent Heap Exhaustion (DoS)
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .maximumSize(100_000) // Limit total unique keys in memory
            .expireAfterAccess(1, TimeUnit.HOURS) // Evict inactive buckets
            .build();

    /**
     * Resolve a bucket for a given key.
     * 
     * @param key            The identifier (IP or username)
     * @param capacity       Maximum tokens
     * @param refillTokens   Number of tokens to refill
     * @param refillDuration Duration for refill
     */
    public Bucket resolveBucket(String key, int capacity, int refillTokens, Duration refillDuration) {
        return buckets.get(key, k -> createNewBucket(capacity, refillTokens, refillDuration));
    }

    // Keep compatibility for existing Auth calls
    public Bucket resolveKeyBucket(String key) {
        return resolveBucket(key, 5, 5, Duration.ofMinutes(1));
    }

    private Bucket createNewBucket(int capacity, int refillTokens, Duration refillDuration) {
        Refill refill = Refill.intervally(refillTokens, refillDuration);
        Bandwidth limit = Bandwidth.classic(capacity, refill);
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
}
