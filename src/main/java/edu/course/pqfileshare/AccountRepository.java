package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Pattern;

/** Local account records and per-account ML-KEM key stores. */
public final class AccountRepository {
    private static final int PBKDF2_ITERATIONS = 310_000;
    private static final int SALT_LENGTH = 16;
    private static final int PASSWORD_HASH_BITS = 256;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9_.-]{3,24}");

    static {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    }

    private AccountRepository() { }

    public static void initialize() throws SQLException {
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                        key_id TEXT NOT NULL UNIQUE,
                        password_salt BLOB NOT NULL,
                        password_hash BLOB NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """);
        }
    }

    public static AccountSession register(String username, char[] password, Path legacyKeyPath)
            throws GeneralSecurityException, IOException, SQLException {
        String normalizedUsername = username == null ? "" : username.trim();
        if (!USERNAME_PATTERN.matcher(normalizedUsername).matches()) {
            throw new IllegalArgumentException("Choose a username with 3–24 letters, numbers, dots, dashes, or underscores.");
        }
        requirePassword(password);

        int accountCount;
        try (Connection connection = open(); PreparedStatement query = connection.prepareStatement("SELECT COUNT(*) FROM users");
             ResultSet result = query.executeQuery()) {
            result.next();
            accountCount = result.getInt(1);
        }

        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        byte[] passwordHash = derivePasswordHash(password, salt);
        String keyId = UUID.randomUUID().toString();
        Path accountKeyPath = accountKeyPath(keyId);
        Path signingKeyPath = signingKeyPath(keyId);
        Files.createDirectories(accountKeyPath.getParent());

        KeyPair keys;
        KeyPair signingKeys;
        try {
            if (accountCount == 0 && Files.exists(legacyKeyPath)) {
                // Keep the key created during the earlier checkpoint so existing .pqpub files still match.
                keys = RecipientKeyStore.load(legacyKeyPath, password.clone());
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", "BC");
                generator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
                keys = generator.generateKeyPair();
            }
            RecipientKeyStore.save(accountKeyPath, keys, password.clone());
            KeyPairGenerator signingGenerator = KeyPairGenerator.getInstance("MLDSA", "BC");
            signingGenerator.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
            signingKeys = signingGenerator.generateKeyPair();
            SigningKeyStore.save(signingKeyPath, signingKeys, password.clone());
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(passwordHash, (byte) 0);
            Files.deleteIfExists(accountKeyPath);
            Files.deleteIfExists(signingKeyPath);
            throw e;
        }

        String sql = "INSERT INTO users(username, key_id, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)";
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                insert.setString(1, normalizedUsername);
                insert.setString(2, keyId);
                insert.setBytes(3, salt);
                insert.setBytes(4, passwordHash);
                insert.setString(5, Instant.now().toString());
                insert.executeUpdate();
                long id;
                try (ResultSet generated = insert.getGeneratedKeys()) {
                    if (!generated.next()) throw new SQLException("Could not create the account record.");
                    id = generated.getLong(1);
                }
                if (accountCount == 0) {
                    try (Statement attachHistory = connection.createStatement()) {
                        attachHistory.executeUpdate("UPDATE file_transfers SET account_id = " + id + " WHERE account_id IS NULL");
                    }
                }
                connection.commit();
                return new AccountSession(id, normalizedUsername, accountKeyPath, keys, signingKeys);
            } catch (SQLException e) {
                connection.rollback();
                Files.deleteIfExists(accountKeyPath);
                Files.deleteIfExists(signingKeyPath);
                if (e.getMessage() != null && e.getMessage().toLowerCase().contains("unique")) {
                    throw new IllegalArgumentException("That username is already taken.", e);
                }
                throw e;
            }
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(passwordHash, (byte) 0);
        }
    }

    public static AccountSession login(String username, char[] password)
            throws GeneralSecurityException, SQLException, IOException {
        requirePassword(password);
        String sql = "SELECT id, username, key_id, password_salt, password_hash FROM users WHERE username = ?";
        try (Connection connection = open(); PreparedStatement query = connection.prepareStatement(sql)) {
            query.setString(1, username == null ? "" : username.trim());
            try (ResultSet result = query.executeQuery()) {
                if (!result.next()) throw new IllegalArgumentException("Account not found. Check the username or create an account.");
                long id = result.getLong("id");
                String savedUsername = result.getString("username");
                String keyId = result.getString("key_id");
                byte[] salt = result.getBytes("password_salt");
                byte[] expectedHash = result.getBytes("password_hash");
                byte[] actualHash = derivePasswordHash(password, salt);
                try {
                    if (!MessageDigest.isEqual(expectedHash, actualHash)) {
                        throw new IllegalArgumentException("Password is incorrect.");
                    }
                    Path keyPath = accountKeyPath(keyId);
                    KeyPair keys = RecipientKeyStore.load(keyPath, password.clone());
                    Path signingPath = signingKeyPath(keyId);
                    KeyPair signingKeys;
                    if (Files.exists(signingPath)) {
                        signingKeys = SigningKeyStore.load(signingPath, password.clone());
                    } else {
                        KeyPairGenerator signingGenerator = KeyPairGenerator.getInstance("MLDSA", "BC");
                        signingGenerator.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
                        signingKeys = signingGenerator.generateKeyPair();
                        SigningKeyStore.save(signingPath, signingKeys, password.clone());
                    }
                    return new AccountSession(id, savedUsername, keyPath, keys, signingKeys);
                } finally {
                    Arrays.fill(salt, (byte) 0);
                    Arrays.fill(expectedHash, (byte) 0);
                    Arrays.fill(actualHash, (byte) 0);
                }
            }
        }
    }

    private static byte[] derivePasswordHash(char[] password, byte[] salt) throws GeneralSecurityException {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password, salt,
                PBKDF2_ITERATIONS, PASSWORD_HASH_BITS);
        try {
            return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length < 8) {
            throw new IllegalArgumentException("Use a password of at least 8 characters.");
        }
    }

    private static Path accountKeyPath(String keyId) {
        return Path.of(System.getProperty("user.home"), ".pq-file-share", "accounts", keyId + ".pqky");
    }

    private static Path signingKeyPath(String keyId) {
        return Path.of(System.getProperty("user.home"), ".pq-file-share", "accounts", keyId + ".pqsigky");
    }

    private static Connection open() throws SQLException {
        Path database = TransferHistoryRepository.databasePath();
        try {
            Files.createDirectories(database.getParent());
        } catch (IOException e) {
            throw new SQLException("Could not create the local application data folder.", e);
        }
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        return connection;
    }
}
