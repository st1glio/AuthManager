package me.stiglio.authManager.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;

import java.io.File;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

public final class DatabaseManager {
    public enum DatabaseType {
        SQLITE,
        MYSQL,
        POSTGRESQL;

        public static DatabaseType fromConfig(String raw) {
            if (raw == null || raw.isBlank()) {
                return SQLITE;
            }

            return switch (raw.trim().toLowerCase(Locale.ROOT)) {
                case "mysql", "mariadb" -> MYSQL;
                case "postgres", "postgresql" -> POSTGRESQL;
                default -> SQLITE;
            };
        }

        public String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private static final String MIGRATIONS_TABLE = "authmanager_schema_migrations";

    private final AuthManager plugin;
    private final ConfigManager configManager;

    private final LongAdder totalQueries = new LongAdder();
    private final LongAdder failedQueries = new LongAdder();
    private final LongAdder retriedQueries = new LongAdder();
    private final LongAdder totalLatencyNanos = new LongAdder();
    private final Map<String, OperationMetricsCounter> operationMetrics = new ConcurrentHashMap<>();

    private HikariDataSource dataSource;
    private DatabaseType databaseType = DatabaseType.SQLITE;
    private volatile MigrationSnapshot migrationSnapshot = new MigrationSnapshot(0, 0, List.of(), List.of());

    public DatabaseManager(AuthManager plugin, ConfigManager configManager) {
        this.plugin = plugin;
        this.configManager = configManager;
    }

    public void connect() {
        if (dataSource != null && !dataSource.isClosed()) {
            return;
        }

        databaseType = DatabaseType.fromConfig(configManager.getDatabaseType());
        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setPoolName("AuthManagerPool");
        hikariConfig.setMaximumPoolSize(configManager.getDatabasePoolMaximumSize());
        hikariConfig.setMinimumIdle(configManager.getDatabasePoolMinimumIdle());
        hikariConfig.setConnectionTimeout(configManager.getDatabasePoolConnectionTimeoutMillis());
        hikariConfig.setIdleTimeout(configManager.getDatabasePoolIdleTimeoutMillis());
        hikariConfig.setMaxLifetime(configManager.getDatabasePoolMaxLifetimeMillis());
        hikariConfig.setAutoCommit(true);

        switch (databaseType) {
            case SQLITE -> configureSqlite(hikariConfig);
            case MYSQL -> configureMysql(hikariConfig);
            case POSTGRESQL -> configurePostgresql(hikariConfig);
        }

        try {
            dataSource = new HikariDataSource(hikariConfig);
            initializeSchema();
            logInfo("INIT", "Database ready type=" + databaseType.id()
                    + " poolMax=" + configManager.getDatabasePoolMaximumSize()
                    + " queryTimeoutSec=" + configManager.getDatabaseQueryTimeoutSeconds()
                    + " retries=" + configManager.getDatabaseRetryMaxAttempts());
        } catch (Exception exception) {
            disconnect();
            throw new IllegalStateException("Failed to initialize database", exception);
        }
    }

    public Connection getConnection() {
        if (dataSource == null || dataSource.isClosed()) {
            throw new IllegalStateException("Database connection pool is not initialized.");
        }

        try {
            return dataSource.getConnection();
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to acquire database connection", exception);
        }
    }

    public void disconnect() {
        if (dataSource == null) {
            return;
        }

        try {
            dataSource.close();
        } catch (Exception exception) {
            logWarn("DISCONNECT", "Failed to close pool: " + safeMessage(exception));
        } finally {
            dataSource = null;
        }
    }

    public boolean isSqlite() {
        return databaseType == DatabaseType.SQLITE;
    }

    public DatabaseType getDatabaseType() {
        return databaseType;
    }

    public int getQueryTimeoutSeconds() {
        return configManager.getDatabaseQueryTimeoutSeconds();
    }

    public int getRetryMaxAttempts() {
        return configManager.getDatabaseRetryMaxAttempts();
    }

    public long getRetryBackoffMillis() {
        return configManager.getDatabaseRetryBackoffMillis();
    }

    public void recordQuery(String operation, long elapsedNanos, boolean success, int retries) {
        totalQueries.increment();
        totalLatencyNanos.add(Math.max(0L, elapsedNanos));
        if (!success) {
            failedQueries.increment();
        }
        if (retries > 0) {
            retriedQueries.add(retries);
        }

        OperationMetricsCounter bucket = operationMetrics.computeIfAbsent(operation,
                ignored -> new OperationMetricsCounter());
        bucket.total.increment();
        bucket.totalLatencyNanos.add(Math.max(0L, elapsedNanos));
        if (!success) {
            bucket.failed.increment();
        }
    }

    public QueryMetricsSnapshot snapshotQueryMetrics() {
        long total = totalQueries.sum();
        long failed = failedQueries.sum();
        long retries = retriedQueries.sum();
        double avgMs = total == 0L ? 0D : nanosToMillis(totalLatencyNanos.sum()) / total;

        List<QueryOperationSnapshot> topOperations = operationMetrics.entrySet().stream()
                .map(entry -> {
                    OperationMetricsCounter counter = entry.getValue();
                    long count = counter.total.sum();
                    long failures = counter.failed.sum();
                    double operationAvg = count == 0L
                            ? 0D
                            : nanosToMillis(counter.totalLatencyNanos.sum()) / count;
                    return new QueryOperationSnapshot(entry.getKey(), count, failures, operationAvg);
                })
                .sorted((left, right) -> Long.compare(right.totalQueries(), left.totalQueries()))
                .limit(5)
                .toList();

        return new QueryMetricsSnapshot(total, failed, retries, avgMs, topOperations);
    }

    public MigrationSnapshot snapshotMigrations() {
        return migrationSnapshot;
    }

    public DatabaseRuntimeSnapshot snapshotRuntime() {
        QueryMetricsSnapshot queryMetrics = snapshotQueryMetrics();
        PoolSnapshot pool = snapshotPool();
        MigrationSnapshot migrations = migrationSnapshot;

        return new DatabaseRuntimeSnapshot(
                databaseType.id(),
                pool.activeConnections(),
                pool.idleConnections(),
                pool.totalConnections(),
                pool.threadsAwaitingConnection(),
                queryMetrics,
                migrations
        );
    }

    public DatabaseHealthSnapshot checkHealth() {
        if (dataSource == null || dataSource.isClosed()) {
            return new DatabaseHealthSnapshot(false, "pool_not_initialized", 0L, snapshotRuntime());
        }

        long startedAt = System.nanoTime();
        try (Connection connection = getConnection();
             Statement statement = connection.createStatement()) {
            statement.setQueryTimeout(getQueryTimeoutSeconds());
            statement.execute("SELECT 1");
            long latencyMs = Math.max(0L, Math.round(nanosToMillis(System.nanoTime() - startedAt)));
            return new DatabaseHealthSnapshot(true, "ok", latencyMs, snapshotRuntime());
        } catch (Exception exception) {
            long latencyMs = Math.max(0L, Math.round(nanosToMillis(System.nanoTime() - startedAt)));
            return new DatabaseHealthSnapshot(false, safeMessage(exception), latencyMs, snapshotRuntime());
        }
    }

    private void configureSqlite(HikariConfig hikariConfig) {
        if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
            throw new IllegalStateException("Unable to create plugin data folder");
        }

        File databaseFile = new File(plugin.getDataFolder(), configManager.getDatabaseFile());
        hikariConfig.setJdbcUrl("jdbc:sqlite:" + databaseFile.getAbsolutePath());
        hikariConfig.setDriverClassName("org.sqlite.JDBC");
        hikariConfig.setConnectionInitSql("PRAGMA foreign_keys = ON;");
        hikariConfig.setConnectionTestQuery("SELECT 1;");
    }

    private void configureMysql(HikariConfig hikariConfig) {
        String jdbcUrl = "jdbc:mysql://" + configManager.getDatabaseMysqlHost() + ":" + configManager.getDatabaseMysqlPort()
                + "/" + configManager.getDatabaseMysqlName()
                + "?useSSL=" + configManager.isDatabaseMysqlSsl()
                + "&allowPublicKeyRetrieval=true&characterEncoding=utf8&useUnicode=true&serverTimezone=UTC";
        hikariConfig.setJdbcUrl(jdbcUrl);
        hikariConfig.setDriverClassName("com.mysql.cj.jdbc.Driver");
        hikariConfig.setUsername(configManager.getDatabaseMysqlUsername());
        hikariConfig.setPassword(configManager.getDatabaseMysqlPassword());
    }

    private void configurePostgresql(HikariConfig hikariConfig) {
        String sslMode = configManager.isDatabasePostgresqlSsl() ? "require" : "disable";
        String jdbcUrl = "jdbc:postgresql://" + configManager.getDatabasePostgresqlHost() + ":"
                + configManager.getDatabasePostgresqlPort() + "/" + configManager.getDatabasePostgresqlName()
                + "?sslmode=" + sslMode;
        hikariConfig.setJdbcUrl(jdbcUrl);
        hikariConfig.setDriverClassName("org.postgresql.Driver");
        hikariConfig.setUsername(configManager.getDatabasePostgresqlUsername());
        hikariConfig.setPassword(configManager.getDatabasePostgresqlPassword());
    }

    private void initializeSchema() throws SQLException {
        try (Connection connection = getConnection()) {
            if (databaseType == DatabaseType.SQLITE) {
                try (Statement statement = connection.createStatement()) {
                    statement.executeUpdate("PRAGMA journal_mode = WAL;");
                }
            }

            migrationSnapshot = applyVersionedMigrations(connection);
        }
    }

    private MigrationSnapshot applyVersionedMigrations(Connection connection) throws SQLException {
        ensureMigrationsTable(connection);
        int latestVersion = 4;
        int currentVersion = readCurrentVersion(connection);
        List<Integer> appliedThisStartup = new ArrayList<>();

        if (currentVersion < 1) {
            createUsersTable(connection);
            recordMigration(connection, 1, "create_users_table");
            appliedThisStartup.add(1);
            currentVersion = 1;
        }

        if (currentVersion < 2) {
            ensureColumnExists(connection, "users", "created_at", "BIGINT NOT NULL DEFAULT 0");
            ensureColumnExists(connection, "users", "last_login_at", "BIGINT");
            ensureColumnExists(connection, "users", "last_login_ip", databaseType == DatabaseType.SQLITE ? "TEXT" : "VARCHAR(64)");
            recordMigration(connection, 2, "ensure_audit_columns");
            appliedThisStartup.add(2);
            currentVersion = 2;
        }

        if (currentVersion < 3) {
            ensureIndexes(connection);
            recordMigration(connection, 3, "add_login_and_premium_indexes");
            appliedThisStartup.add(3);
            currentVersion = 3;
        }

        if (currentVersion < 4) {
            ensureCaseInsensitiveNameIndex(connection);
            recordMigration(connection, 4, "add_case_insensitive_name_index");
            appliedThisStartup.add(4);
            currentVersion = 4;
        }

        List<Integer> pending = new ArrayList<>();
        for (int version = currentVersion + 1; version <= latestVersion; version++) {
            pending.add(version);
        }

        if (!appliedThisStartup.isEmpty()) {
            logInfo("MIGRATION", "Applied migrations=" + appliedThisStartup + " currentVersion=" + currentVersion);
        } else {
            logInfo("MIGRATION", "Schema already up-to-date at version=" + currentVersion);
        }

        return new MigrationSnapshot(currentVersion, latestVersion, List.copyOf(appliedThisStartup), List.copyOf(pending));
    }

    private void ensureMigrationsTable(Connection connection) throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS " + MIGRATIONS_TABLE + " ("
                + "version INT PRIMARY KEY, "
                + "description VARCHAR(255) NOT NULL, "
                + "installed_at BIGINT NOT NULL" + ")";

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }

    private int readCurrentVersion(Connection connection) throws SQLException {
        String sql = "SELECT COALESCE(MAX(version), 0) AS current_version FROM " + MIGRATIONS_TABLE;
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            if (!result.next()) {
                return 0;
            }
            return Math.max(0, result.getInt("current_version"));
        }
    }

    private void recordMigration(Connection connection, int version, String description) throws SQLException {
        String sql = "INSERT INTO " + MIGRATIONS_TABLE + "(version, description, installed_at) VALUES(?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, version);
            statement.setString(2, description);
            statement.setLong(3, Instant.now().toEpochMilli());
            statement.executeUpdate();
        }
    }

    private void createUsersTable(Connection connection) throws SQLException {
        String sql = switch (databaseType) {
            case SQLITE -> """
                    CREATE TABLE IF NOT EXISTS users (
                      uuid TEXT PRIMARY KEY,
                      name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                      password TEXT NOT NULL,
                      premium INTEGER NOT NULL DEFAULT 0,
                      created_at INTEGER NOT NULL,
                      last_login_at INTEGER,
                      last_login_ip TEXT
                    );
                    """;
            case MYSQL -> """
                    CREATE TABLE IF NOT EXISTS users (
                      uuid VARCHAR(36) PRIMARY KEY,
                      name VARCHAR(16) NOT NULL UNIQUE,
                      password VARCHAR(255) NOT NULL,
                      premium TINYINT(1) NOT NULL DEFAULT 0,
                      created_at BIGINT NOT NULL,
                      last_login_at BIGINT NULL,
                      last_login_ip VARCHAR(64) NULL
                    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                    """;
            case POSTGRESQL -> """
                    CREATE TABLE IF NOT EXISTS users (
                      uuid VARCHAR(36) PRIMARY KEY,
                      name VARCHAR(16) NOT NULL,
                      password VARCHAR(255) NOT NULL,
                      premium BOOLEAN NOT NULL DEFAULT FALSE,
                      created_at BIGINT NOT NULL,
                      last_login_at BIGINT,
                      last_login_ip VARCHAR(64)
                    );
                    """;
        };

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }

    private void ensureIndexes(Connection connection) throws SQLException {
        if (databaseType == DatabaseType.MYSQL) {
            ensureMysqlIndex(connection, "users", "idx_users_last_login_at",
                    "CREATE INDEX idx_users_last_login_at ON users(last_login_at)");
            ensureMysqlIndex(connection, "users", "idx_users_premium",
                    "CREATE INDEX idx_users_premium ON users(premium)");
            return;
        }

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_users_premium ON users(premium)");
        }
    }

    private void ensureCaseInsensitiveNameIndex(Connection connection) throws SQLException {
        if (databaseType == DatabaseType.MYSQL) {
            return;
        }

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_name_lower ON users ((LOWER(name)))");
        }
    }

    private void ensureMysqlIndex(Connection connection, String table, String indexName, String createSql) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet indexes = metaData.getIndexInfo(connection.getCatalog(), null, table, false, false)) {
            while (indexes.next()) {
                String existing = indexes.getString("INDEX_NAME");
                if (existing != null && existing.equalsIgnoreCase(indexName)) {
                    return;
                }
            }
        }

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(createSql);
        }
    }

    private void ensureColumnExists(Connection connection, String table, String column, String definition) throws SQLException {
        if (columnExists(connection, table, column)) {
            return;
        }

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
        }
    }

    private boolean columnExists(Connection connection, String table, String column) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet columns = metaData.getColumns(connection.getCatalog(), null, table, column)) {
            if (columns.next()) {
                return true;
            }
        }

        try (ResultSet columns = metaData.getColumns(connection.getCatalog(), null, table, null)) {
            while (columns.next()) {
                String existing = columns.getString("COLUMN_NAME");
                if (existing != null && existing.equalsIgnoreCase(column)) {
                    return true;
                }
            }
        }
        return false;
    }

    private PoolSnapshot snapshotPool() {
        if (dataSource == null || dataSource.isClosed()) {
            return new PoolSnapshot(0, 0, 0, 0);
        }

        HikariPoolMXBean bean = dataSource.getHikariPoolMXBean();
        if (bean == null) {
            return new PoolSnapshot(0, 0, 0, 0);
        }

        return new PoolSnapshot(
                Math.max(0, bean.getActiveConnections()),
                Math.max(0, bean.getIdleConnections()),
                Math.max(0, bean.getTotalConnections()),
                Math.max(0, bean.getThreadsAwaitingConnection())
        );
    }

    private double nanosToMillis(long nanos) {
        return nanos / 1_000_000D;
    }

    private void logInfo(String scope, String message) {
        plugin.getLogger().info("[DB][" + scope + "] " + message);
    }

    private void logWarn(String scope, String message) {
        plugin.getLogger().warning("[DB][" + scope + "] " + message);
    }

    private String safeMessage(Throwable throwable) {
        if (throwable == null || throwable.getMessage() == null || throwable.getMessage().isBlank()) {
            return "unknown_error";
        }
        return throwable.getMessage().replace('\n', ' ').trim();
    }

    public record DatabaseHealthSnapshot(
            boolean healthy,
            String note,
            long pingMillis,
            DatabaseRuntimeSnapshot runtime
    ) {
    }

    public record DatabaseRuntimeSnapshot(
            String type,
            int activeConnections,
            int idleConnections,
            int totalConnections,
            int threadsAwaitingConnection,
            QueryMetricsSnapshot queryMetrics,
            MigrationSnapshot migrations
    ) {
    }

    public record QueryMetricsSnapshot(
            long totalQueries,
            long failedQueries,
            long retriedQueries,
            double averageQueryMillis,
            List<QueryOperationSnapshot> topOperations
    ) {
    }

    public record QueryOperationSnapshot(
            String operation,
            long totalQueries,
            long failedQueries,
            double averageQueryMillis
    ) {
    }

    public record MigrationSnapshot(
            int currentVersion,
            int latestVersion,
            List<Integer> appliedThisStartup,
            List<Integer> pendingVersions
    ) {
    }

    private record PoolSnapshot(
            int activeConnections,
            int idleConnections,
            int totalConnections,
            int threadsAwaitingConnection
    ) {
    }

    private static final class OperationMetricsCounter {
        private final LongAdder total = new LongAdder();
        private final LongAdder failed = new LongAdder();
        private final LongAdder totalLatencyNanos = new LongAdder();
    }
}
