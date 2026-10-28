package edu.course.pqfileshare;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Local SQLite metadata for completed encrypt/decrypt operations. It stores no file contents or keys. */
public final class TransferHistoryRepository {
    private TransferHistoryRepository() { }

    public static Path databasePath() {
        return Path.of(System.getProperty("user.home"), ".pq-file-share", "transfers.db");
    }

    public static void initialize() throws SQLException {
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS file_transfers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id INTEGER REFERENCES users(id),
                        direction TEXT NOT NULL CHECK (direction IN ('ENCRYPTED', 'DECRYPTED')),
                        file_name TEXT NOT NULL,
                        saved_path TEXT NOT NULL,
                        key_fingerprint TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """);
            if (!hasColumn(connection, "file_transfers", "account_id")) {
                statement.executeUpdate("ALTER TABLE file_transfers ADD COLUMN account_id INTEGER REFERENCES users(id)");
            }
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_file_transfers_user_created "
                    + "ON file_transfers(account_id, id DESC)");
        }
    }

    public static void record(long accountId, String direction, String fileName, String savedPath, String fingerprint)
            throws SQLException {
        String sql = "INSERT INTO file_transfers(account_id, direction, file_name, saved_path, key_fingerprint, created_at) "
                + "VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection connection = open(); PreparedStatement insert = connection.prepareStatement(sql)) {
            insert.setLong(1, accountId);
            insert.setString(2, direction);
            insert.setString(3, fileName);
            insert.setString(4, savedPath);
            insert.setString(5, fingerprint);
            insert.setString(6, Instant.now().toString());
            insert.executeUpdate();
        }
    }

    /** Returns short display lines for the newest transfers. */
    public static List<String> recentSummaries(long accountId, int limit) throws SQLException {
        String sql = "SELECT direction, file_name, created_at FROM file_transfers WHERE account_id = ? "
                + "ORDER BY id DESC LIMIT ?";
        List<String> summaries = new ArrayList<>();
        try (Connection connection = open(); PreparedStatement query = connection.prepareStatement(sql)) {
            query.setLong(1, accountId);
            query.setInt(2, Math.max(1, Math.min(limit, 50)));
            try (ResultSet result = query.executeQuery()) {
                while (result.next()) {
                    String direction = result.getString("direction").equals("ENCRYPTED")
                            ? "Encrypted" : "Decrypted";
                    summaries.add(direction + "  •  " + result.getString("file_name")
                            + "  •  " + result.getString("created_at"));
                }
            }
        }
        return summaries;
    }

    private static boolean hasColumn(Connection connection, String table, String column) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet columns = statement.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (columns.next()) {
                if (column.equalsIgnoreCase(columns.getString("name"))) return true;
            }
            return false;
        }
    }

    private static Connection open() throws SQLException {
        Path database = databasePath();
        try {
            Files.createDirectories(database.getParent());
        } catch (java.io.IOException e) {
            throw new SQLException("Could not create the local application data folder.", e);
        }
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        return connection;
    }
}
