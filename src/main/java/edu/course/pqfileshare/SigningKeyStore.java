package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** Password-protected storage for an account's ML-DSA signing key pair. */
public final class SigningKeyStore {
    private static final String PROVIDER = "BC";
    private static final byte[] MAGIC = {'P', 'Q', 'S', 'K'};
    private static final int VERSION = 1;
    private static final int ITERATIONS = 310_000;
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int MAX_KEY_LENGTH = 16_384;

    static {
        if (Security.getProvider(PROVIDER) == null) Security.addProvider(new BouncyCastleProvider());
    }

    private SigningKeyStore() { }

    public static void save(Path path, KeyPair keys, char[] password)
            throws IOException, GeneralSecurityException {
        requirePassword(password);
        byte[] publicBytes = keys.getPublic().getEncoded();
        byte[] privateBytes = keys.getPrivate().getEncoded();
        if (publicBytes == null || privateBytes == null
                || publicBytes.length == 0 || privateBytes.length == 0
                || publicBytes.length > MAX_KEY_LENGTH || privateBytes.length > MAX_KEY_LENGTH) {
            Arrays.fill(password, '\0');
            if (privateBytes != null) Arrays.fill(privateBytes, (byte) 0);
            throw new GeneralSecurityException("The ML-DSA provider returned an unsupported key encoding.");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        byte[] wrappingKey = null;
        byte[] encryptedPrivate = null;
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(nonce);
        try {
            wrappingKey = deriveWrappingKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(makeAad(ITERATIONS, salt, nonce, publicBytes));
            encryptedPrivate = cipher.doFinal(privateBytes);

            Path absolute = path.toAbsolutePath();
            Path parent = absolute.getParent();
            if (parent != null) Files.createDirectories(parent);
            Path temporary = Files.createTempFile(parent, ".pqsk-", ".tmp");
            try {
                try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                    out.write(MAGIC);
                    out.writeByte(VERSION);
                    out.writeInt(ITERATIONS);
                    out.write(salt);
                    out.write(nonce);
                    out.writeInt(publicBytes.length);
                    out.write(publicBytes);
                    out.writeInt(encryptedPrivate.length);
                    out.write(encryptedPrivate);
                }
                replaceAfterSuccess(temporary, absolute);
            } catch (IOException e) {
                Files.deleteIfExists(temporary);
                throw e;
            }
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(privateBytes, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            if (wrappingKey != null) Arrays.fill(wrappingKey, (byte) 0);
            if (encryptedPrivate != null) Arrays.fill(encryptedPrivate, (byte) 0);
        }
    }

    public static KeyPair load(Path path, char[] password) throws IOException, GeneralSecurityException {
        requirePassword(password);
        byte[] salt;
        byte[] nonce;
        byte[] publicBytes;
        byte[] encryptedPrivate;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)))) {
            if (!Arrays.equals(in.readNBytes(MAGIC.length), MAGIC)) throw new IOException("Not a PQSK signing-key store.");
            int version = in.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported signing-key store version: " + version);
            int iterations = in.readInt();
            if (iterations < 100_000 || iterations > 2_000_000) throw new IOException("Invalid password-work factor.");
            salt = in.readNBytes(SALT_LENGTH);
            nonce = in.readNBytes(NONCE_LENGTH);
            int publicLength = in.readInt();
            if (publicLength < 1 || publicLength > MAX_KEY_LENGTH) throw new IOException("Invalid ML-DSA public-key length.");
            publicBytes = in.readNBytes(publicLength);
            int encryptedLength = in.readInt();
            if (encryptedLength < 17 || encryptedLength > MAX_KEY_LENGTH + 16) {
                throw new IOException("Invalid encrypted ML-DSA private-key length.");
            }
            encryptedPrivate = in.readNBytes(encryptedLength);
            if (salt.length != SALT_LENGTH || nonce.length != NONCE_LENGTH
                    || publicBytes.length != publicLength || encryptedPrivate.length != encryptedLength
                    || in.read() != -1) {
                throw new IOException("Signing-key store is incomplete or contains unexpected data.");
            }
            byte[] privateBytes = null;
            byte[] wrappingKey = null;
            try {
                wrappingKey = deriveWrappingKey(password, salt, iterations);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                        new GCMParameterSpec(128, nonce));
                cipher.updateAAD(makeAad(iterations, salt, nonce, publicBytes));
                privateBytes = cipher.doFinal(encryptedPrivate);
                KeyFactory factory = KeyFactory.getInstance("MLDSA", PROVIDER);
                return new KeyPair(factory.generatePublic(new X509EncodedKeySpec(publicBytes)),
                        factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes)));
            } catch (GeneralSecurityException e) {
                throw new GeneralSecurityException("Could not unlock the signing key; check the password or file integrity.", e);
            } finally {
                Arrays.fill(password, '\0');
                Arrays.fill(salt, (byte) 0);
                Arrays.fill(nonce, (byte) 0);
                Arrays.fill(publicBytes, (byte) 0);
                Arrays.fill(encryptedPrivate, (byte) 0);
                if (privateBytes != null) Arrays.fill(privateBytes, (byte) 0);
                if (wrappingKey != null) Arrays.fill(wrappingKey, (byte) 0);
            }
        } catch (IOException | RuntimeException e) {
            Arrays.fill(password, '\0');
            throw e;
        }
    }

    private static byte[] deriveWrappingKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] deriveWrappingKey(char[] password, byte[] salt) throws GeneralSecurityException {
        return deriveWrappingKey(password, salt, ITERATIONS);
    }

    private static byte[] makeAad(int iterations, byte[] salt, byte[] nonce, byte[] publicBytes) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeInt(iterations);
            out.write(salt);
            out.write(nonce);
            out.writeInt(publicBytes.length);
            out.write(publicBytes);
        }
        return bytes.toByteArray();
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length < 8) throw new IllegalArgumentException("Use a password of at least 8 characters.");
    }

    private static void replaceAfterSuccess(Path temporary, Path output) throws IOException {
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
