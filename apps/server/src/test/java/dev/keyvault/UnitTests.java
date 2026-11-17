package dev.keyvault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.keyvault.auth.TotpService;
import dev.keyvault.common.RateLimitedException;
import dev.keyvault.common.RateLimiter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class UnitTests {

    /** RFC 6238 Appendix B test vectors (SHA-1, 8 digits truncated to the last 6). */
    @Test
    void totpMatchesRfc6238Vectors() {
        byte[] seed = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        assertThat(TotpService.generate(seed, 59L / 30)).isEqualTo("287082");
        assertThat(TotpService.generate(seed, 1111111109L / 30)).isEqualTo("081804");
        assertThat(TotpService.generate(seed, 1234567890L / 30)).isEqualTo("005924");
        assertThat(TotpService.generate(seed, 2000000000L / 30)).isEqualTo("279037");
    }

    @Test
    void loginRateLimitKicksIn() {
        RateLimiter limiter = new RateLimiter(true);
        for (int i = 0; i < 8; i++) limiter.check(RateLimiter.Policy.LOGIN_ACCOUNT, "victim@example.com");
        assertThatThrownBy(() -> limiter.check(RateLimiter.Policy.LOGIN_ACCOUNT, "victim@example.com"))
                .isInstanceOf(RateLimitedException.class);
        // other accounts are unaffected
        limiter.check(RateLimiter.Policy.LOGIN_ACCOUNT, "someone-else@example.com");
        limiter.reset(RateLimiter.Policy.LOGIN_ACCOUNT, "victim@example.com");
        limiter.check(RateLimiter.Policy.LOGIN_ACCOUNT, "victim@example.com");
    }
}
