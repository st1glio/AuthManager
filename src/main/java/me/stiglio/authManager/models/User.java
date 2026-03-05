package me.stiglio.authManager.models;

import java.util.UUID;

public final class User {
    private final UUID uuid;
    private final String username;
    private final String passwordHash;
    private final boolean premium;
    private final long createdAt;
    private final long lastLoginAt;
    private final String lastLoginIp;

    public User(UUID uuid, String username, String passwordHash, boolean premium,
                long createdAt, long lastLoginAt, String lastLoginIp) {
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.premium = premium;
        this.createdAt = createdAt;
        this.lastLoginAt = lastLoginAt;
        this.lastLoginIp = lastLoginIp == null ? "" : lastLoginIp;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public boolean isPremium() {
        return premium;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getLastLoginAt() {
        return lastLoginAt;
    }

    public String getLastLoginIp() {
        return lastLoginIp;
    }
}
