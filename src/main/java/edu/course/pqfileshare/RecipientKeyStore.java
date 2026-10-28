package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** Stores a public ML-KEM key and a password-encrypted private ML-KEM key. */
public final class RecipientKeyStore {
    private static final String PROVIDER = "BC";
    private static final byte[] MAGIC = {'P', 'Q', 'K', 'Y'};
    private static final int VERSION = 1;
    private static final int PBKDF2_ITERATIONS = 310_000;
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;
    private static final int MAX_PUBLIC_KEY_LENGTH = 8192;
    private static final int MAX_PRIVATE_KEY_LENGTH = 8192;

    static {
        if (Security.getProvider(PROVIDER) == null) Security.addProvider(new BouncyCastleProvider());
    }

    private RecipientKeyStore() { }

    /** Saves the public key in clear and encrypts the private PKCS#8 key with PBKDF2 + AES-GCM. */
    public static void save(Path path, KeyPair keyPair, char[] password) throws IOException, GeneralSecurityException {
        requirePassword(password);
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        if (publicKey == null || privateKey == null) {
            throw new GeneralSecurityException("The ML-KEM provider did not expose an encodable key format.");
        }
        if (publicKey.length > MAX_PUBLIC_KEY_LENGTH || privateKey.length > MAX_PRIVATE_KEY_LENGTH) {
            throw new GeneralSecurityException("The encoded key is larger than the supported key-store limit.");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        new java.security.SecureRandom().nextBytes(salt);
        new java.security.SecureRandom().nextBytes(nonce);
        byte[] aad = makeAad(VERSION, PBKDF2_ITERATIONS, salt, nonce, publicKey);
        byte[] wrappingKey = deriveWrappingKey(password, salt, PBKDF2_ITERATIONS);
        byte[] encryptedPrivateKey;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            encryptedPrivateKey = cipher.doFinal(privateKey);
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            Arrays.fill(privateKey, (byte) 0);
            Arrays.fill(password, '\0');
        }

        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".pqky-", ".tmp");
        try {
            try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                out.write(MAGIC);
                out.writeByte(VERSION);
                out.writeInt(PBKDF2_ITERATIONS);
                out.writeByte(salt.length);
                out.write(salt);
                out.writeByte(nonce.length);
                out.write(nonce);
                out.writeInt(publicKey.length);
                out.write(publicKey);
                out.writeInt(encryptedPrivateKey.length);
                out.write(encryptedPrivateKey);
            }
            replaceAfterSuccess(temporary, absolute);
        } catch (IOException e) {
            Files.deleteIfExists(temporary);
            throw e;
        } finally {
            Arrays.fill(encryptedPrivateKey, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    /** Loads a recipient key pair, failing with an authentication error if the password is wrong. */
    public static KeyPair load(Path path, char[] password) throws IOException, GeneralSecurityException {
        requirePassword(password);
        byte[] salt;
        byte[] nonce;
        byte[] publicKeyBytes;
        byte[] encryptedPrivateKey;
        int version;
        int iterations;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)))) {
            if (!Arrays.equals(in.readNBytes(MAGIC.length), MAGIC)) throw new IOException("Not a PQKY key-store file.");
            version = in.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported key-store version: " + version);
            iterations = in.readInt();
            if (iterations < 100_000 || iterations > 2_000_000) throw new IOException("Invalid password-work factor.");
            int saltLength = in.readUnsignedByte();
            if (saltLength != SALT_LENGTH) throw new IOException("Invalid key-store salt length.");
            salt = in.readNBytes(saltLength);
            int nonceLength = in.readUnsignedByte();
            if (nonceLength != NONCE_LENGTH) throw new IOException("Invalid key-store nonce length.");
            nonce = in.readNBytes(nonceLength);
            int publicLength = in.readInt();
            if (publicLength < 1 || publicLength > MAX_PUBLIC_KEY_LENGTH) throw new IOException("Invalid public-key length.");
            publicKeyBytes = in.readNBytes(publicLength);
            int privateLength = in.readInt();
            if (privateLength < 17 || privateLength > MAX_PRIVATE_KEY_LENGTH + 16) {
                throw new IOException("Invalid encrypted private-key length.");
            }
            encryptedPrivateKey = in.readNBytes(privateLength);
            if (salt.length != saltLength || nonce.length != nonceLength
                    || publicKeyBytes.length != publicLength || encryptedPrivateKey.length != privateLength
                    || in.read() != -1) {
                throw new IOException("Key-store file is incomplete or contains unexpected trailing data.");
            }
        }

        byte[] wrappingKey = deriveWrappingKey(password, salt, iterations);
        Arrays.fill(password, '\0');
        byte[] privateKeyBytes;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(makeAad(version, iterations, salt, nonce, publicKeyBytes));
            privateKeyBytes = cipher.doFinal(encryptedPrivateKey);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Could not unlock the key store; check the password or file integrity.", e);
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(encryptedPrivateKey, (byte) 0);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", PROVIDER);
            return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)));
        } finally {
            Arrays.fill(publicKeyBytes, (byte) 0);
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }

    private static byte[] makeAad(int version, int iterations, byte[] salt, byte[] nonce, byte[] publicKey)
            throws IOException {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC);
            out.writeByte(version);
            out.writeInt(iterations);
            out.writeByte(salt.length);
            out.write(salt);
            out.writeByte(nonce.length);
            out.write(nonce);
            out.writeInt(publicKey.length);
            out.write(publicKey);
        }
        return bytes.toByteArray();
    }

    private static byte[] deriveWrappingKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length < 8) {
            throw new IllegalArgumentException("Use a password of at least 8 characters.");
        }
    }

    private static void replaceAfterSuccess(Path temporary, Path output) throws IOException {
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
