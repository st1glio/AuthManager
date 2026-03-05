package me.stiglio.authManager.service;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class AccountLockManager {
    public record Decision(boolean blocked, long secondsLeft, int failures) {
    }

    private final Map<String, LockState> states = new ConcurrentHashMap<>();
    private final long windowMillis;
    private final int maxFailures;
    private final int lockSeconds;
    private final boolean enabled;

    public AccountLockManager(int windowSeconds, int maxFailures, int lockSeconds, boolean enabled) {
        this.windowMillis = Math.max(30, windowSeconds) * 1000L;
        this.maxFailures = Math.max(1, maxFailures);
        this.lockSeconds = Math.max(1, lockSeconds);
        this.enabled = enabled;
    }

    public Decision check(String username) {
        if (!enabled) {
            return new Decision(false, 0L, 0);
        }

        long now = System.currentTimeMillis();
        String key = normalizeName(username);
        LockState state = states.get(key);
        if (state == null) {
            return new Decision(false, 0L, 0);
        }

        if (now - state.lastFailureMillis > windowMillis && state.blockedUntilMillis <= now) {
            states.remove(key, state);
            return new Decision(false, 0L, 0);
        }

        if (state.blockedUntilMillis <= now) {
            return new Decision(false, 0L, state.failures);
        }

        long secondsLeft = (state.blockedUntilMillis - now + 999L) / 1000L;
        return new Decision(true, Math.max(1L, secondsLeft), state.failures);
    }

    public void recordFailure(String username) {
        if (!enabled) {
            return;
        }

        long now = System.currentTimeMillis();
        String key = normalizeName(username);
        states.compute(key, (ignored, current) -> {
            LockState state = current == null ? new LockState() : current;
            if (now - state.lastFailureMillis > windowMillis) {
                state.failures = 0;
                state.blockedUntilMillis = 0L;
            }

            state.lastFailureMillis = now;
            state.failures++;
            if (state.failures >= maxFailures) {
                state.blockedUntilMillis = Math.max(state.blockedUntilMillis, now + lockSeconds * 1000L);
            }
            return state;
        });
    }

    public void recordSuccess(String username) {
        states.remove(normalizeName(username));
    }

    public boolean clear(String username) {
        return states.remove(normalizeName(username)) != null;
    }

    public int cleanupExpired() {
        if (!enabled) {
            states.clear();
            return 0;
        }

        long now = System.currentTimeMillis();
        int removed = 0;
        for (Map.Entry<String, LockState> entry : states.entrySet()) {
            LockState state = entry.getValue();
            if (state == null) {
                continue;
            }
            if (now - state.lastFailureMillis > windowMillis && state.blockedUntilMillis <= now) {
                if (states.remove(entry.getKey(), state)) {
                    removed++;
                }
            }
        }
        return removed;
    }

    public int size() {
        return states.size();
    }

    public void clearAll() {
        states.clear();
    }

    private String normalizeName(String username) {
        if (username == null || username.isBlank()) {
            return "unknown";
        }
        return username.toLowerCase(Locale.ROOT);
    }

    private static final class LockState {
        private int failures;
        private long blockedUntilMillis;
        private long lastFailureMillis;
    }
}
