package me.stiglio.authManager.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthRateLimiterTest {

    @Test
    void shouldBlockAfterConfiguredFailures() {
        AuthRateLimiter limiter = new AuthRateLimiter(
                120,
                new AuthRateLimiter.Policy(2, 1, 4),
                new AuthRateLimiter.Policy(2, 1, 4),
                new AuthRateLimiter.Policy(4, 1, 4)
        );

        assertFalse(limiter.check(AuthRateLimiter.Action.LOGIN, "PlayerOne", "127.0.0.1").blocked());
        limiter.recordFailure(AuthRateLimiter.Action.LOGIN, "PlayerOne", "127.0.0.1");
        assertFalse(limiter.check(AuthRateLimiter.Action.LOGIN, "PlayerOne", "127.0.0.1").blocked());

        limiter.recordFailure(AuthRateLimiter.Action.LOGIN, "PlayerOne", "127.0.0.1");
        assertTrue(limiter.check(AuthRateLimiter.Action.LOGIN, "PlayerOne", "127.0.0.1").blocked());
    }

    @Test
    void shouldUnblockAfterCooldown() throws InterruptedException {
        AuthRateLimiter limiter = new AuthRateLimiter(
                120,
                new AuthRateLimiter.Policy(1, 1, 2),
                new AuthRateLimiter.Policy(1, 1, 2),
                new AuthRateLimiter.Policy(4, 1, 4)
        );

        limiter.recordFailure(AuthRateLimiter.Action.REGISTER, "PlayerTwo", "127.0.0.2");
        assertTrue(limiter.check(AuthRateLimiter.Action.REGISTER, "PlayerTwo", "127.0.0.2").blocked());

        Thread.sleep(1_100L);
        assertFalse(limiter.check(AuthRateLimiter.Action.REGISTER, "PlayerTwo", "127.0.0.2").blocked());
    }

    @Test
    void shouldResetLimiterOnSuccess() {
        AuthRateLimiter limiter = new AuthRateLimiter(
                120,
                new AuthRateLimiter.Policy(1, 5, 5),
                new AuthRateLimiter.Policy(1, 5, 5),
                new AuthRateLimiter.Policy(4, 1, 4)
        );

        limiter.recordFailure(AuthRateLimiter.Action.LOGIN, "PlayerThree", "127.0.0.3");
        assertTrue(limiter.check(AuthRateLimiter.Action.LOGIN, "PlayerThree", "127.0.0.3").blocked());

        limiter.recordSuccess(AuthRateLimiter.Action.LOGIN, "PlayerThree", "127.0.0.3");
        assertFalse(limiter.check(AuthRateLimiter.Action.LOGIN, "PlayerThree", "127.0.0.3").blocked());
    }
}
