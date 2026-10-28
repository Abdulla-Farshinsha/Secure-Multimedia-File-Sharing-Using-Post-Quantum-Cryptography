package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Read/write support for shareable ML-DSA public verification keys (.pqsigpub). */
public final class SigningPublicKeyFile {
    private static final byte[] MAGIC = {'P', 'Q', 'S', 'P'};
    private static final int VERSION = 1;
    private static final int MAX_KEY_LENGTH = 8192;

    static {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    }

    private SigningPublicKeyFile() { }

    public static void write(Path path, PublicKey publicKey) throws IOException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_KEY_LENGTH) {
            throw new IOException("The ML-DSA public key has an unsupported encoded size.");
        }
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(absolute)))) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeInt(encoded.length);
            out.write(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public static PublicKey read(Path path) throws IOException {
        byte[] encoded;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)))) {
            if (!Arrays.equals(in.readNBytes(MAGIC.length), MAGIC)) throw new IOException("Not a PQFS signature public-key file.");
            int version = in.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported signature-key file version: " + version);
            int length = in.readInt();
            if (length < 1 || length > MAX_KEY_LENGTH) throw new IOException("Invalid ML-DSA public-key size.");
            encoded = in.readNBytes(length);
            if (encoded.length != length || in.read() != -1) {
                throw new IOException("Signature public-key file is incomplete or has extra data.");
            }
        }
        try {
            return KeyFactory.getInstance("MLDSA", "BC").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IOException("Could not read this ML-DSA public key.", e);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public static String fingerprint(PublicKey publicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }
}
