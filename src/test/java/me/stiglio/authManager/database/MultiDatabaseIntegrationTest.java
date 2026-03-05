package me.stiglio.authManager.database;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiDatabaseIntegrationTest {

    @Test
    void sqliteSchemaShouldSupportUserReadWrite() throws Exception {
        Path sqlite = Files.createTempFile("authmanager-it-", ".sqlite");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + sqlite.toAbsolutePath())) {
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS users ("
                        + "uuid TEXT PRIMARY KEY,"
                        + "name TEXT NOT NULL UNIQUE COLLATE NOCASE,"
                        + "password TEXT NOT NULL,"
                        + "premium INTEGER NOT NULL DEFAULT 0,"
                        + "created_at INTEGER NOT NULL,"
                        + "last_login_at INTEGER,"
                        + "last_login_ip TEXT)");
                statement.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_name_lower ON users ((LOWER(name)))");
            }

            insertUser(connection, "11111111-1111-1111-1111-111111111111", "PlayerOne", true);

            assertEquals(1, queryInt(connection,
                    "SELECT COUNT(*) FROM users WHERE name = ? COLLATE NOCASE", "playerone"));
        } finally {
            Files.deleteIfExists(sqlite);
        }
    }

    @Test
    void mysqlSchemaShouldSupportUserReadWrite() throws Exception {
        Assumptions.assumeTrue(isDockerAvailable(), "Docker unavailable, skipping MySQL integration test.");

        try (MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.4")) {
            mysql.start();
            try (Connection connection = DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword())) {
                try (Statement statement = connection.createStatement()) {
                    statement.executeUpdate("CREATE TABLE IF NOT EXISTS users ("
                            + "uuid VARCHAR(36) PRIMARY KEY,"
                            + "name VARCHAR(16) NOT NULL UNIQUE,"
                            + "password VARCHAR(255) NOT NULL,"
                            + "premium TINYINT(1) NOT NULL DEFAULT 0,"
                            + "created_at BIGINT NOT NULL,"
                            + "last_login_at BIGINT NULL,"
                            + "last_login_ip VARCHAR(64) NULL)"
                            + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    statement.executeUpdate("CREATE INDEX idx_users_last_login_at ON users(last_login_at)");
                    statement.executeUpdate("CREATE INDEX idx_users_premium ON users(premium)");
                }

                insertUser(connection, "22222222-2222-2222-2222-222222222222", "PlayerTwo", false);
                assertEquals(1, queryInt(connection,
                        "SELECT COUNT(*) FROM users WHERE LOWER(name) = LOWER(?)", "playertwo"));
            }
        }
    }

    @Test
    void postgresSchemaShouldSupportUserReadWrite() throws Exception {
        Assumptions.assumeTrue(isDockerAvailable(), "Docker unavailable, skipping PostgreSQL integration test.");

        try (PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")) {
            postgres.start();
            try (Connection connection = DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())) {
                try (Statement statement = connection.createStatement()) {
                    statement.executeUpdate("CREATE TABLE IF NOT EXISTS users ("
                            + "uuid VARCHAR(36) PRIMARY KEY,"
                            + "name VARCHAR(16) NOT NULL,"
                            + "password VARCHAR(255) NOT NULL,"
                            + "premium BOOLEAN NOT NULL DEFAULT FALSE,"
                            + "created_at BIGINT NOT NULL,"
                            + "last_login_at BIGINT,"
                            + "last_login_ip VARCHAR(64))");
                    statement.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_name_lower ON users ((LOWER(name)))");
                    statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at)");
                }

                insertUser(connection, "33333333-3333-3333-3333-333333333333", "PlayerThree", true);
                assertEquals(1, queryInt(connection,
                        "SELECT COUNT(*) FROM users WHERE LOWER(name) = LOWER(?)", "playerthree"));
            }
        }
    }

    private void insertUser(Connection connection, String uuid, String name, boolean premium) throws Exception {
        String sql = "INSERT INTO users(uuid, name, password, premium, created_at, last_login_at, last_login_ip) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, uuid);
            statement.setString(2, name);
            statement.setString(3, "$2a$10$fakehashforintegrationtests");
            statement.setBoolean(4, premium);
            statement.setLong(5, System.currentTimeMillis());
            statement.setLong(6, System.currentTimeMillis());
            statement.setString(7, "127.0.0.1");
            int updated = statement.executeUpdate();
            assertTrue(updated >= 1);
        }
    }

    private int queryInt(Connection connection, String sql, String value) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, value);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return 0;
                }
                return result.getInt(1);
            }
        }
    }

    private boolean isDockerAvailable() {
        try {
            return DockerClientFactory.instance().isDockerAvailable();
        } catch (Throwable throwable) {
            return false;
        }
    }
}
