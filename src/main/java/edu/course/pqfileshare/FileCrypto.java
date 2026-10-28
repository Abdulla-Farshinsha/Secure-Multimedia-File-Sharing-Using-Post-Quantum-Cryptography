package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.spec.GCMParameterSpec;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/** Streaming ML-KEM + HKDF + AES-GCM file encryption for the first file-workflow checkpoint. */
public final class FileCrypto {
    private static final String PROVIDER = "BC";
    private static final byte[] MAGIC = {'P', 'Q', 'F', 'S'};
    private static final int VERSION = 1;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final byte[] HKDF_INFO = "pq-file-share:file-encryption:v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private FileCrypto() { }

    /** Encrypts a file and writes a self-contained .pqf container. */
    public static void encrypt(Path input, Path encryptedOutput, PublicKey recipientPublicKey)
            throws IOException, GeneralSecurityException {
        byte[] encapsulation;
        byte[] sharedSecret;
        try {
            KEM.Encapsulated result = KEM.getInstance("ML-KEM", PROVIDER)
                    .newEncapsulator(recipientPublicKey).encapsulate();
            encapsulation = result.encapsulation();
            sharedSecret = result.key().getEncoded();
        } catch (GeneralSecurityException e) {
            throw e;
        }
        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);
        byte[] fileKey = deriveFileKey(sharedSecret, encapsulation);
        Arrays.fill(sharedSecret, (byte) 0);

        Cipher cipher = aesCipher(Cipher.ENCRYPT_MODE, fileKey, nonce);
        Path temporary = createTemporaryBeside(encryptedOutput);
        try {
            try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(input)));
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                out.write(MAGIC);
                out.writeByte(VERSION);
                out.writeShort(encapsulation.length);
                out.write(encapsulation);
                out.write(nonce);
                transform(in, out, cipher);
                out.write(cipher.doFinal());
            }
            replaceAfterSuccess(temporary, encryptedOutput);
        } catch (Exception e) {
            Files.deleteIfExists(temporary);
            if (e instanceof IOException io) throw io;
            if (e instanceof GeneralSecurityException security) throw security;
            throw new GeneralSecurityException("Could not encrypt the file", e);
        } finally {
            Arrays.fill(fileKey, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    /** Decrypts a .pqf container. The destination is replaced only after GCM authenticates fully. */
    public static void decrypt(Path encryptedInput, Path decryptedOutput, PrivateKey recipientPrivateKey)
            throws IOException, GeneralSecurityException {
        Path temporary = createTemporaryBeside(decryptedOutput);
        byte[] fileKey = null;
        try {
            try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(encryptedInput)));
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                byte[] magic = in.readNBytes(MAGIC.length);
                if (!Arrays.equals(magic, MAGIC)) throw new IOException("This is not a PQFS encrypted file.");
                int version = in.readUnsignedByte();
                if (version != VERSION) throw new IOException("Unsupported encrypted-file version: " + version);
                int encapsulationLength = in.readUnsignedShort();
                if (encapsulationLength < 1 || encapsulationLength > 4096) {
                    throw new IOException("Invalid ML-KEM encapsulation length.");
                }
                byte[] encapsulation = in.readNBytes(encapsulationLength);
                byte[] nonce = in.readNBytes(NONCE_LENGTH);
                if (encapsulation.length != encapsulationLength || nonce.length != NONCE_LENGTH) {
                    throw new IOException("Encrypted file is incomplete or damaged.");
                }

                byte[] sharedSecret = KEM.getInstance("ML-KEM", PROVIDER)
                        .newDecapsulator(recipientPrivateKey).decapsulate(encapsulation).getEncoded();
                fileKey = deriveFileKey(sharedSecret, encapsulation);
                Arrays.fill(sharedSecret, (byte) 0);
                Cipher cipher = aesCipher(Cipher.DECRYPT_MODE, fileKey, nonce);
                transform(in, out, cipher);
                // GCM verifies the authentication tag here. Do not publish the temp file before this succeeds.
                out.write(cipher.doFinal());
                Arrays.fill(nonce, (byte) 0);
            }
            replaceAfterSuccess(temporary, decryptedOutput);
        } catch (Exception e) {
            Files.deleteIfExists(temporary);
            if (e instanceof IOException io) throw io;
            if (e instanceof GeneralSecurityException security) throw security;
            throw new GeneralSecurityException("Could not decrypt the file; it may be damaged or for another recipient", e);
        } finally {
            if (fileKey != null) Arrays.fill(fileKey, (byte) 0);
        }
    }

    private static byte[] deriveFileKey(byte[] sharedSecret, byte[] encapsulation) throws GeneralSecurityException {
        try {
            return Hkdf.sha256(sharedSecret, encapsulation, HKDF_INFO, 32);
        } catch (Exception e) {
            throw new GeneralSecurityException("HKDF key derivation failed", e);
        }
    }

    private static Cipher aesCipher(int mode, byte[] key, byte[] nonce) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        return cipher;
    }

    private static void transform(DataInputStream in, DataOutputStream out, Cipher cipher)
            throws IOException, GeneralSecurityException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int count;
        while ((count = in.read(buffer)) != -1) {
            byte[] transformed = cipher.update(buffer, 0, count);
            if (transformed != null && transformed.length != 0) out.write(transformed);
        }
        Arrays.fill(buffer, (byte) 0);
    }

    private static Path createTemporaryBeside(Path output) throws IOException {
        Path absolute = output.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        return Files.createTempFile(parent, ".pqfs-", ".tmp");
    }

    private static void replaceAfterSuccess(Path temporary, Path output) throws IOException {
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
