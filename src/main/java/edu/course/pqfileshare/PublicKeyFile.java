package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.Arrays;

/** Read/write support for shareable recipient ML-KEM public-key files (.pqpub). */
public final class PublicKeyFile {
    private static final byte[] MAGIC = {'P', 'Q', 'P', 'B'};
    private static final int VERSION = 1;
    private static final int MAX_KEY_LENGTH = 8192;

    static {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    }

    private PublicKeyFile() { }

    public static void write(Path path, PublicKey publicKey) throws IOException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_KEY_LENGTH) {
            throw new IOException("The ML-KEM public key has an unsupported encoded size.");
        }
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".pqpub-", ".tmp");
        try {
            try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                out.write(MAGIC);
                out.writeByte(VERSION);
                out.writeInt(encoded.length);
                out.write(encoded);
            }
            try {
                Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            Files.deleteIfExists(temporary);
            throw e;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public static PublicKey read(Path path) throws IOException {
        byte[] encoded;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)))) {
            if (!Arrays.equals(in.readNBytes(MAGIC.length), MAGIC)) throw new IOException("Not a PQFS public-key file.");
            int version = in.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported public-key file version: " + version);
            int length = in.readInt();
            if (length < 1 || length > MAX_KEY_LENGTH) throw new IOException("Invalid public-key size.");
            encoded = in.readNBytes(length);
            if (encoded.length != length || in.read() != -1) throw new IOException("Public-key file is incomplete or has extra data.");
        }

        try {
            return KeyFactory.getInstance("ML-KEM", "BC").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IOException("Could not read this ML-KEM public key.", e);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /** A SHA-256 digest to compare with the recipient over a separate trusted channel. */
    public static String fingerprint(PublicKey publicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }
}
