package me.stiglio.authManager.database;

import me.stiglio.authManager.models.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

public final class UserDAO {
    private final DatabaseManager databaseManager;

    public UserDAO(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public Optional<User> findByName(String name) {
        final String sql = databaseManager.isSqlite()
                ? "SELECT uuid, name, password, premium, created_at, last_login_at, last_login_ip "
                + "FROM users WHERE name = ? COLLATE NOCASE LIMIT 1"
                : "SELECT uuid, name, password, premium, created_at, last_login_at, last_login_ip "
                + "FROM users WHERE LOWER(name) = LOWER(?) LIMIT 1";

        return execute("findByName", "Database error while fetching user by name", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, name);
                try (ResultSet result = statement.executeQuery()) {
                    return readUser(result);
                }
            }
        });
    }

    public Optional<User> findByUuid(UUID uuid) {
        final String sql = "SELECT uuid, name, password, premium, created_at, last_login_at, last_login_ip FROM users WHERE uuid = ? LIMIT 1";
        return execute("findByUuid", "Database error while fetching user by uuid", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, uuid.toString());
                try (ResultSet result = statement.executeQuery()) {
                    return readUser(result);
                }
            }
        });
    }

    public boolean createUser(UUID uuid, String name, String passwordHash, boolean premium, String loginIp) {
        final String sql = "INSERT INTO users(uuid, name, password, premium, created_at, last_login_at, last_login_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";
        long now = System.currentTimeMillis();

        return execute("createUser", "Database error while creating user", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, uuid.toString());
                statement.setString(2, name);
                statement.setString(3, passwordHash);
                statement.setBoolean(4, premium);
                statement.setLong(5, now);
                statement.setLong(6, now);
                statement.setString(7, normalizeIp(loginIp));
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                if (isConstraintViolation(exception)) {
                    return false;
                }
                throw exception;
            }
        });
    }

    public boolean updateLastLogin(UUID uuid, String loginIp) {
        final String sql = "UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE uuid = ?";
        return execute("updateLastLogin", "Database error while updating last login", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setLong(1, System.currentTimeMillis());
                statement.setString(2, normalizeIp(loginIp));
                statement.setString(3, uuid.toString());
                return statement.executeUpdate() == 1;
            }
        });
    }

    public boolean setPremium(UUID uuid, boolean premium) {
        final String sql = "UPDATE users SET premium = ? WHERE uuid = ?";
        return execute("setPremium", "Database error while updating premium status", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setBoolean(1, premium);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            }
        });
    }

    public boolean updateName(UUID uuid, String name) {
        final String sql = "UPDATE users SET name = ? WHERE uuid = ?";
        return execute("updateName", "Database error while updating username", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, name);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException exception) {
                if (isConstraintViolation(exception)) {
                    return false;
                }
                throw exception;
            }
        });
    }

    public boolean updatePassword(UUID uuid, String passwordHash) {
        final String sql = "UPDATE users SET password = ? WHERE uuid = ?";
        return execute("updatePassword", "Database error while updating password", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, passwordHash);
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            }
        });
    }

    public int countUsersByLastLoginIp(String ipAddress) {
        String normalizedIp = normalizeIp(ipAddress);
        if (normalizedIp.isBlank()) {
            return 0;
        }

        final String sql = "SELECT COUNT(*) AS total FROM users WHERE last_login_ip = ?";
        return execute("countUsersByLastLoginIp", "Database error while counting users by last login IP", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, normalizedIp);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        return 0;
                    }
                    return Math.max(0, result.getInt("total"));
                }
            }
        });
    }

    public Optional<UserStatistics> fetchStatistics(int activeWindowDays) {
        final String sql = """
                SELECT
                    COUNT(*) AS total_users,
                    COALESCE(SUM(CASE WHEN premium THEN 1 ELSE 0 END), 0) AS premium_users,
                    COALESCE(SUM(CASE WHEN last_login_at >= ? THEN 1 ELSE 0 END), 0) AS active_users
                FROM users
                """;

        long since = Instant.now().minus(Math.max(1, activeWindowDays), ChronoUnit.DAYS).toEpochMilli();
        return execute("fetchStatistics", "Database error while fetching user statistics", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
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
            }
        });
    }

    public ImportWriteOutcome upsertImportedUser(User user) {
        return execute("upsertImportedUser", "Database error while importing user", connection -> {
            Optional<User> existing = findByUuidInternal(connection, user.getUuid());
            if (existing.isPresent()) {
                String sql = "UPDATE users SET name = ?, password = ?, premium = ?, created_at = ?, last_login_at = ?, last_login_ip = ? WHERE uuid = ?";
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    applyQueryTimeout(statement);
                    statement.setString(1, user.getUsername());
                    statement.setString(2, user.getPasswordHash());
                    statement.setBoolean(3, user.isPremium());
                    statement.setLong(4, user.getCreatedAt());
                    statement.setLong(5, user.getLastLoginAt());
                    statement.setString(6, normalizeIp(user.getLastLoginIp()));
                    statement.setString(7, user.getUuid().toString());
                    statement.executeUpdate();
                }
                return ImportWriteOutcome.UPDATED;
            }

            String sql = "INSERT INTO users(uuid, name, password, premium, created_at, last_login_at, last_login_ip) VALUES(?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                applyQueryTimeout(statement);
                statement.setString(1, user.getUuid().toString());
                statement.setString(2, user.getUsername());
                statement.setString(3, user.getPasswordHash());
                statement.setBoolean(4, user.isPremium());
                statement.setLong(5, user.getCreatedAt());
                statement.setLong(6, user.getLastLoginAt());
                statement.setString(7, normalizeIp(user.getLastLoginIp()));
                statement.executeUpdate();
                return ImportWriteOutcome.CREATED;
            } catch (SQLException exception) {
                if (isConstraintViolation(exception)) {
                    return ImportWriteOutcome.SKIPPED;
                }
                throw exception;
            }
        });
    }

    public DatabaseManager.DatabaseRuntimeSnapshot snapshotDatabaseRuntime() {
        return databaseManager.snapshotRuntime();
    }

    public DatabaseManager.DatabaseHealthSnapshot checkDatabaseHealth() {
        return databaseManager.checkHealth();
    }

    public DatabaseManager.DatabaseType getDatabaseType() {
        return databaseManager.getDatabaseType();
    }

    public DatabaseManager.MigrationSnapshot snapshotMigrations() {
        return databaseManager.snapshotMigrations();
    }

    private Optional<User> readUser(ResultSet result) throws SQLException {
        if (!result.next()) {
            return Optional.empty();
        }

        UUID uuid = UUID.fromString(result.getString("uuid"));
        String username = result.getString("name");
        String password = result.getString("password");
        boolean premium = result.getBoolean("premium");
        long createdAt = result.getLong("created_at");
        long lastLoginAt = result.getLong("last_login_at");
        if (result.wasNull()) {
            lastLoginAt = 0L;
        }
        String lastLoginIp = result.getString("last_login_ip");
        return Optional.of(new User(uuid, username, password, premium, createdAt, lastLoginAt, lastLoginIp));
    }

    private Optional<User> findByUuidInternal(Connection connection, UUID uuid) throws SQLException {
        String sql = "SELECT uuid, name, password, premium, created_at, last_login_at, last_login_ip FROM users WHERE uuid = ? LIMIT 1";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            applyQueryTimeout(statement);
            statement.setString(1, uuid.toString());
            try (ResultSet result = statement.executeQuery()) {
                return readUser(result);
            }
        }
    }

    private boolean isConstraintViolation(SQLException exception) {
        String state = exception.getSQLState();
        if (state != null && state.startsWith("23")) {
            return true;
        }

        int code = exception.getErrorCode();
        return code == 19 || code == 1062 || code == 23505;
    }

    private boolean isRetryable(SQLException exception) {
        String state = exception.getSQLState();
        if (state != null) {
            if (state.startsWith("08") || state.startsWith("40")) {
                return true;
            }
            if ("HYT00".equalsIgnoreCase(state) || "HYT01".equalsIgnoreCase(state)) {
                return true;
            }
            if ("55P03".equalsIgnoreCase(state)) {
                return true;
            }
        }

        int code = exception.getErrorCode();
        if (code == 5 || code == 6 || code == 1205 || code == 1213 || code == 2006 || code == 2013) {
            return true;
        }

        String message = exception.getMessage();
        if (message == null) {
            return false;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        return lower.contains("database is locked") || lower.contains("deadlock") || lower.contains("lock wait timeout");
    }

    private void applyQueryTimeout(Statement statement) throws SQLException {
        statement.setQueryTimeout(databaseManager.getQueryTimeoutSeconds());
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

    private <T> T execute(String operation, String errorMessage, SqlCallable<T> action) {
        int maxAttempts = Math.max(1, databaseManager.getRetryMaxAttempts());
        long backoffMillis = Math.max(0L, databaseManager.getRetryBackoffMillis());

        Exception lastError = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            long startedAt = System.nanoTime();
            try (Connection connection = connection()) {
                T result = action.call(connection);
                databaseManager.recordQuery(operation, System.nanoTime() - startedAt, true, attempt - 1);
                return result;
            } catch (SQLException exception) {
                databaseManager.recordQuery(operation, System.nanoTime() - startedAt, false, attempt - 1);
                if (attempt < maxAttempts && isRetryable(exception)) {
                    lastError = exception;
                    sleep(backoffMillis * attempt);
                    continue;
                }
                throw new IllegalStateException(errorMessage, exception);
            } catch (RuntimeException exception) {
                databaseManager.recordQuery(operation, System.nanoTime() - startedAt, false, attempt - 1);
                SQLException nestedSql = extractSqlException(exception);
                if (attempt < maxAttempts && nestedSql != null && isRetryable(nestedSql)) {
                    lastError = exception;
                    sleep(backoffMillis * attempt);
                    continue;
                }
                throw exception;
            }
        }

        throw new IllegalStateException(errorMessage, lastError);
    }

    private SQLException extractSqlException(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof SQLException sqlException) {
                return sqlException;
            }
            current = current.getCause();
        }
        return null;
    }

    private void sleep(long millis) {
        if (millis <= 0L) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    @FunctionalInterface
    private interface SqlCallable<T> {
        T call(Connection connection) throws SQLException;
    }

    public enum ImportWriteOutcome {
        CREATED,
        UPDATED,
        SKIPPED
    }

    public record UserStatistics(int totalUsers, int premiumUsers, int activeUsers, int inactiveUsers) {
    }
}
