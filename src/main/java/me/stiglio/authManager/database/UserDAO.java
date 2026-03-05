package me.stiglio.authManager.database;

import me.stiglio.authManager.models.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

public final class UserDAO {
    private final DatabaseManager databaseManager;
    private final Object dbLock = new Object();

    public UserDAO(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public Optional<User> findByName(String name) {
        final String sql = "SELECT uuid, name, password, premium, created_at, last_login_at, last_login_ip "
                + "FROM users WHERE name = ? COLLATE NOCASE LIMIT 1";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setString(1, name);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }

                    UUID uuid = UUID.fromString(result.getString("uuid"));
                    String username = result.getString("name");
                    String password = result.getString("password");
                    boolean premium = result.getInt("premium") == 1;
                    long createdAt = result.getLong("created_at");
                    long lastLoginAt = result.getLong("last_login_at");
                    if (result.wasNull()) {
                        lastLoginAt = 0L;
                    }
                    String lastLoginIp = result.getString("last_login_ip");
                    return Optional.of(new User(uuid, username, password, premium, createdAt, lastLoginAt, lastLoginIp));
                }
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while fetching user by name", exception);
            }
        }
    }

    public boolean createUser(UUID uuid, String name, String passwordHash, boolean premium, String loginIp) {
        final String sql = "INSERT INTO users(uuid, name, password, premium, created_at, last_login_at, last_login_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";
        long now = System.currentTimeMillis();

        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setString(1, uuid.toString());
                statement.setString(2, name);
                statement.setString(3, passwordHash);
                statement.setInt(4, premium ? 1 : 0);
                statement.setLong(5, now);
                statement.setLong(6, now);
                statement.setString(7, normalizeIp(loginIp));
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                if (isConstraintViolation(exception)) {
                    return false;
                }
                throw new IllegalStateException("Database error while creating user", exception);
            }
        }
    }

    public boolean updateLastLogin(UUID uuid, String loginIp) {
        final String sql = "UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE uuid = ?";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setLong(1, System.currentTimeMillis());
                statement.setString(2, normalizeIp(loginIp));
                statement.setString(3, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while updating last login", exception);
            }
        }
    }

    public boolean setPremium(UUID uuid, boolean premium) {
        final String sql = "UPDATE users SET premium = ? WHERE uuid = ?";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setInt(1, premium ? 1 : 0);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while updating premium status", exception);
            }
        }
    }

    public boolean updateName(UUID uuid, String name) {
        final String sql = "UPDATE users SET name = ? WHERE uuid = ?";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setString(1, name);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                if (isConstraintViolation(exception)) {
                    return false;
                }
                throw new IllegalStateException("Database error while updating username", exception);
            }
        }
    }

    public boolean updatePassword(UUID uuid, String passwordHash) {
        final String sql = "UPDATE users SET password = ? WHERE uuid = ?";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setString(1, passwordHash);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while updating password", exception);
            }
        }
    }

    public int countUsersByLastLoginIp(String ipAddress) {
        String normalizedIp = normalizeIp(ipAddress);
        if (normalizedIp.isBlank()) {
            return 0;
        }

        final String sql = "SELECT COUNT(*) AS total FROM users WHERE last_login_ip = ?";
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setString(1, normalizedIp);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        return 0;
                    }
                    return Math.max(0, result.getInt("total"));
                }
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while counting users by last login IP", exception);
            }
        }
    }

    public Optional<UserStatistics> fetchStatistics(int activeWindowDays) {
        final String sql = """
                SELECT
                    COUNT(*) AS total_users,
                    COALESCE(SUM(CASE WHEN premium = 1 THEN 1 ELSE 0 END), 0) AS premium_users,
                    COALESCE(SUM(CASE WHEN last_login_at >= ? THEN 1 ELSE 0 END), 0) AS active_users
                FROM users
                """;

        long since = Instant.now().minus(Math.max(1, activeWindowDays), ChronoUnit.DAYS).toEpochMilli();
        synchronized (dbLock) {
            try (PreparedStatement statement = connection().prepareStatement(sql)) {
                statement.setLong(1, since);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }

                    int totalUsers = result.getInt("total_users");
                    int premiumUsers = result.getInt("premium_users");
                    int activeUsers = result.getInt("active_users");
                    int inactiveUsers = Math.max(0, totalUsers - activeUsers);
                    return Optional.of(new UserStatistics(totalUsers, premiumUsers, activeUsers, inactiveUsers));
                }
            } catch (SQLException exception) {
                throw new IllegalStateException("Database error while fetching user statistics", exception);
            }
        }
    }

    private boolean isConstraintViolation(SQLException exception) {
        return exception.getErrorCode() == 19 || "23000".equals(exception.getSQLState());
    }

    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "";
        }
        return ip.trim();
    }

    private Connection connection() {
        return databaseManager.getConnection();
    }

    public record UserStatistics(int totalUsers, int premiumUsers, int activeUsers, int inactiveUsers) {
    }
}
