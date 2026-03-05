package me.stiglio.authManager.service;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthRateLimiter {
    public enum Action {
        LOGIN,
        REGISTER,
        PRE_LOGIN
    }

    public record Policy(int maxAttempts, int baseCooldownSeconds, int maxCooldownSeconds) {
    }

    public record Decision(boolean blocked, long secondsLeft, int attempts) {
    }

    private final Map<String, AttemptState> states = new ConcurrentHashMap<>();
    private final long windowMillis;
    private final Policy loginPolicy;
    private final Policy registerPolicy;
    private final Policy preLoginPolicy;

    public AuthRateLimiter(int windowSeconds, Policy loginPolicy, Policy registerPolicy, Policy preLoginPolicy) {
        this.windowMillis = Math.max(30, windowSeconds) * 1000L;
        this.loginPolicy = loginPolicy;
        this.registerPolicy = registerPolicy;
        this.preLoginPolicy = preLoginPolicy;
    }

    public Decision check(Action action, String playerName, String ipAddress) {
        long now = System.currentTimeMillis();
        AttemptState byPlayer = readState(action, "p:" + normalize(playerName), now);
        AttemptState byIp = readState(action, "ip:" + normalizeIp(ipAddress), now);

        long blockedUntil = Math.max(byPlayer.blockedUntilMillis, byIp.blockedUntilMillis);
        int attempts = Math.max(byPlayer.failures, byIp.failures);
        if (blockedUntil <= now) {
            return new Decision(false, 0L, attempts);
        }

        long secondsLeft = (blockedUntil - now + 999L) / 1000L;
        return new Decision(true, Math.max(1L, secondsLeft), attempts);
    }

    public void recordFailure(Action action, String playerName, String ipAddress) {
        long now = System.currentTimeMillis();
        applyFailure(action, "p:" + normalize(playerName), now);
        applyFailure(action, "ip:" + normalizeIp(ipAddress), now);
    }

    public void recordSuccess(Action action, String playerName, String ipAddress) {
        states.remove(rateKey(action, "p:" + normalize(playerName)));
        states.remove(rateKey(action, "ip:" + normalizeIp(ipAddress)));
    }

    public Decision checkIpOnly(Action action, String ipAddress) {
        long now = System.currentTimeMillis();
        AttemptState byIp = readState(action, "ip:" + normalizeIp(ipAddress), now);
        if (byIp.blockedUntilMillis <= now) {
            return new Decision(false, 0L, byIp.failures);
        }

        long secondsLeft = (byIp.blockedUntilMillis - now + 999L) / 1000L;
        return new Decision(true, Math.max(1L, secondsLeft), byIp.failures);
    }

    public void recordFailureIpOnly(Action action, String ipAddress) {
        applyFailure(action, "ip:" + normalizeIp(ipAddress), System.currentTimeMillis());
    }

    public void clearAll() {
        states.clear();
    }

    public int clearPlayer(String playerName) {
        String subjectKey = "p:" + normalize(playerName);
        int removed = 0;
        for (Action action : Action.values()) {
            if (states.remove(rateKey(action, subjectKey)) != null) {
                removed++;
            }
        }
        return removed;
    }

    public int clearIp(String ipAddress) {
        String subjectKey = "ip:" + normalizeIp(ipAddress);
        int removed = 0;
        for (Action action : Action.values()) {
            if (states.remove(rateKey(action, subjectKey)) != null) {
                removed++;
            }
        }
        return removed;
    }

    public int countEntries(Action action) {
        String prefix = action.name() + ":";
        int count = 0;
        for (String key : states.keySet()) {
            if (key.startsWith(prefix)) {
                count++;
            }
        }
        return count;
    }

    private void applyFailure(Action action, String subjectKey, long now) {
        Policy policy = policyFor(action);
        states.compute(rateKey(action, subjectKey), (key, current) -> {
            AttemptState state = current == null ? new AttemptState() : current;
            if (now - state.lastFailureMillis > windowMillis) {
                state.failures = 0;
                state.blockedUntilMillis = 0L;
            }

            state.lastFailureMillis = now;
            state.failures++;
            if (state.failures >= policy.maxAttempts()) {
                int overflow = Math.max(0, state.failures - policy.maxAttempts());
                long cooldownSeconds = (long) policy.baseCooldownSeconds() << Math.min(overflow, 10);
                cooldownSeconds = Math.min(policy.maxCooldownSeconds(), cooldownSeconds);
                state.blockedUntilMillis = Math.max(state.blockedUntilMillis, now + cooldownSeconds * 1000L);
            }
            return state;
        });
    }

    private AttemptState readState(Action action, String subjectKey, long now) {
        String rateKey = rateKey(action, subjectKey);
        AttemptState state = states.get(rateKey);
        if (state == null) {
            return new AttemptState();
        }

        if (now - state.lastFailureMillis > windowMillis && state.blockedUntilMillis <= now) {
            states.remove(rateKey, state);
            return new AttemptState();
        }
        return state.copy();
    }

    private Policy policyFor(Action action) {
        return switch (action) {
            case LOGIN -> loginPolicy;
            case REGISTER -> registerPolicy;
            case PRE_LOGIN -> preLoginPolicy;
        };
    }

    private String rateKey(Action action, String subjectKey) {
        return action.name() + ":" + subjectKey;
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private String normalizeIp(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return "unknown";
        }
        return ipAddress.trim();
    }

    private static final class AttemptState {
        private int failures;
        private long blockedUntilMillis;
        private long lastFailureMillis;

        private AttemptState copy() {
            AttemptState copy = new AttemptState();
            copy.failures = this.failures;
            copy.blockedUntilMillis = this.blockedUntilMillis;
            copy.lastFailureMillis = this.lastFailureMillis;
            return copy;
        }
    }
}
