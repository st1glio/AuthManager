package me.stiglio.authManager.database;

import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;

import java.io.File;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public final class DatabaseManager {
    private final AuthManager plugin;
    private final ConfigManager configManager;
    private Connection connection;

    public DatabaseManager(AuthManager plugin, ConfigManager configManager) {
        this.plugin = plugin;
        this.configManager = configManager;
    }

    public void connect() {
        try {
            if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
                throw new IllegalStateException("Unable to create plugin data folder");
            }

            File databaseFile = new File(plugin.getDataFolder(), configManager.getDatabaseFile());
            String url = "jdbc:sqlite:" + databaseFile.getAbsolutePath();
            this.connection = DriverManager.getConnection(url);

            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("PRAGMA foreign_keys = ON;");
                statement.executeUpdate("PRAGMA journal_mode = WAL;");
                statement.executeUpdate("""
                        CREATE TABLE IF NOT EXISTS users (
                          uuid TEXT PRIMARY KEY,
                          name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                          password TEXT NOT NULL,
                          premium INTEGER NOT NULL DEFAULT 0,
                          created_at INTEGER NOT NULL,
                          last_login_at INTEGER,
                          last_login_ip TEXT
                        );
                        """);
                statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);");
                statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_users_premium ON users(premium);");
            }

            ensureColumnExists("users", "created_at", "INTEGER NOT NULL DEFAULT 0");
            ensureColumnExists("users", "last_login_at", "INTEGER");
            ensureColumnExists("users", "last_login_ip", "TEXT");
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to initialize database", exception);
        }
    }

    private void ensureColumnExists(String table, String column, String definition) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet columns = metaData.getColumns(null, null, table, column)) {
            if (columns.next()) {
                return;
            }
        }

        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public void disconnect() {
        if (connection == null) {
            return;
        }

        try {
            connection.close();
        } catch (SQLException exception) {
            plugin.getLogger().warning("Failed to close database connection: " + exception.getMessage());
        }
    }
}
