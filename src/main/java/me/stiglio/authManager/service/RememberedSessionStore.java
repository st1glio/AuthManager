package me.stiglio.authManager.service;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class RememberedSessionStore {
    private final Map<String, SessionEntry> sessions = new ConcurrentHashMap<>();

    public void remember(String playerName, String ip, int durationMinutes) {
        if (playerName == null || playerName.isBlank() || durationMinutes <= 0) {
            return;
        }

        long expiresAt = System.currentTimeMillis() + durationMinutes * 60_000L;
        sessions.put(normalizeName(playerName), new SessionEntry(normalizeIp(ip), expiresAt));
    }

    public boolean hasValidSession(String playerName, String ip, boolean requireSameIp) {
        if (playerName == null || playerName.isBlank()) {
            return false;
        }

        SessionEntry entry = sessions.get(normalizeName(playerName));
        if (entry == null) {
            return false;
        }

        long now = System.currentTimeMillis();
        if (now >= entry.expiresAtMillis()) {
            sessions.remove(normalizeName(playerName), entry);
            return false;
        }

        if (!requireSameIp) {
            return true;
        }

        String normalizedCurrentIp = normalizeIp(ip);
        if (entry.ipAddress().isBlank() || normalizedCurrentIp.isBlank()) {
            return false;
        }
        return entry.ipAddress().equals(normalizedCurrentIp);
    }

    public long secondsLeft(String playerName) {
        if (playerName == null || playerName.isBlank()) {
            return 0L;
        }

        SessionEntry entry = sessions.get(normalizeName(playerName));
        if (entry == null) {
            return 0L;
        }

        long now = System.currentTimeMillis();
        if (now >= entry.expiresAtMillis()) {
            sessions.remove(normalizeName(playerName), entry);
            return 0L;
        }

        long secondsLeft = (entry.expiresAtMillis() - now + 999L) / 1000L;
        return Math.max(1L, secondsLeft);
    }

    public boolean clear(String playerName) {
        if (playerName == null || playerName.isBlank()) {
            return false;
        }
        return sessions.remove(normalizeName(playerName)) != null;
    }

    public int cleanupExpired() {
        long now = System.currentTimeMillis();
        int removed = 0;
        for (Map.Entry<String, SessionEntry> entry : sessions.entrySet()) {
            SessionEntry session = entry.getValue();
            if (session == null) {
                continue;
            }
            if (now >= session.expiresAtMillis()) {
                if (sessions.remove(entry.getKey(), session)) {
                    removed++;
                }
            }
        }
        return removed;
    }

    public int size() {
        return sessions.size();
    }

    public void clearAll() {
        sessions.clear();
    }

    private String normalizeName(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "";
        }
        return ip.trim();
    }

    private record SessionEntry(String ipAddress, long expiresAtMillis) {
    }
}
