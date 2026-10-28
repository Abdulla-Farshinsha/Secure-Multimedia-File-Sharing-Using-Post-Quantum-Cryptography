package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

/** Adds and verifies an ML-DSA signature trailer on an encrypted PQFS file. */
public final class FileSignature {
    private static final byte[] MAGIC = {'P', 'Q', 'S', 'G'};
    private static final int VERSION = 1;
    private static final int FOOTER_LENGTH = Integer.BYTES;
    private static final int TRAILER_HEADER_LENGTH = MAGIC.length + 1 + Integer.BYTES;
    private static final int MAX_SIGNATURE_LENGTH = 16_384;
    private static final int BUFFER_SIZE = 64 * 1024;

    static {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    }

    private FileSignature() { }

    /** Signs the existing encrypted bytes, then atomically replaces the file with a signed container. */
    public static void sign(Path encryptedFile, PrivateKey signingKey)
            throws IOException, GeneralSecurityException {
        Signature signature = Signature.getInstance("MLDSA", "BC");
        signature.initSign(signingKey, new SecureRandom());
        Path absolute = encryptedFile.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".pqfs-signed-", ".tmp");
        byte[] buffer = new byte[BUFFER_SIZE];
        byte[] signatureBytes = null;
        try {
            try (InputStream in = new BufferedInputStream(Files.newInputStream(absolute));
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                int count;
                while ((count = in.read(buffer)) != -1) {
                    signature.update(buffer, 0, count);
                    out.write(buffer, 0, count);
                }
                signatureBytes = signature.sign();
                if (signatureBytes.length > MAX_SIGNATURE_LENGTH) throw new IOException("ML-DSA signature is larger than the supported limit.");
                int trailerLength = TRAILER_HEADER_LENGTH + signatureBytes.length;
                out.write(MAGIC);
                out.writeByte(VERSION);
                out.writeInt(signatureBytes.length);
                out.write(signatureBytes);
                out.writeInt(trailerLength);
            }
            replaceAfterSuccess(temporary, absolute);
        } catch (IOException | GeneralSecurityException e) {
            Files.deleteIfExists(temporary);
            throw e;
        } finally {
            Arrays.fill(buffer, (byte) 0);
            if (signatureBytes != null) Arrays.fill(signatureBytes, (byte) 0);
        }
    }

    /** Returns false only for a legacy unsigned file. A malformed signature trailer is rejected. */
    public static boolean hasSignature(Path file) throws IOException {
        return readTrailer(file) != null;
    }

    /** Returns the length of the original .pqf container before its signature trailer. */
    public static long encryptedContainerLength(Path file) throws IOException {
        Trailer trailer = readTrailer(file);
        return trailer == null ? Files.size(file) : trailer.contentLength;
    }

    /** Verifies the signature over every encrypted-container byte before the trailer. */
    public static void verify(Path file, PublicKey senderPublicKey)
            throws IOException, GeneralSecurityException {
        Trailer trailer = readTrailer(file);
        if (trailer == null) throw new IOException("This encrypted file has no sender signature.");
        try {
            Signature verifier = Signature.getInstance("MLDSA", "BC");
            verifier.initVerify(senderPublicKey);
            try (InputStream in = new BufferedInputStream(Files.newInputStream(file))) {
                byte[] buffer = new byte[BUFFER_SIZE];
                long remaining = trailer.contentLength;
                try {
                    while (remaining > 0) {
                        int count = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                        if (count < 0) throw new IOException("Signed file ended before the signed content was complete.");
                        verifier.update(buffer, 0, count);
                        remaining -= count;
                    }
                } finally {
                    Arrays.fill(buffer, (byte) 0);
                }
            }
            if (!verifier.verify(trailer.signature)) {
                throw new GeneralSecurityException("The sender signature is invalid. The file may have been changed or signed with another key.");
            }
        } finally {
            Arrays.fill(trailer.signature, (byte) 0);
        }
    }

    private static Trailer readTrailer(Path file) throws IOException {
        long fileLength = Files.size(file);
        if (fileLength < FOOTER_LENGTH + TRAILER_HEADER_LENGTH) return null;
        try (RandomAccessFile input = new RandomAccessFile(file.toFile(), "r")) {
            input.seek(fileLength - FOOTER_LENGTH);
            int trailerLength = input.readInt();
            if (trailerLength < TRAILER_HEADER_LENGTH || trailerLength > TRAILER_HEADER_LENGTH + MAX_SIGNATURE_LENGTH
                    || trailerLength + FOOTER_LENGTH > fileLength) {
                return null;
            }
            long contentLength = fileLength - FOOTER_LENGTH - trailerLength;
            input.seek(contentLength);
            byte[] magic = new byte[MAGIC.length];
            input.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) return null;
            int version = input.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported ML-DSA signature trailer version: " + version);
            int signatureLength = input.readInt();
            if (signatureLength < 1 || signatureLength > MAX_SIGNATURE_LENGTH
                    || trailerLength != TRAILER_HEADER_LENGTH + signatureLength) {
                throw new IOException("Invalid ML-DSA signature length.");
            }
            byte[] signature = new byte[signatureLength];
            input.readFully(signature);
            if (input.getFilePointer() != fileLength - FOOTER_LENGTH) {
                Arrays.fill(signature, (byte) 0);
                throw new IOException("Signature trailer contains unexpected data.");
            }
            return new Trailer(contentLength, signature);
        }
    }

    private static void replaceAfterSuccess(Path temporary, Path output) throws IOException {
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private record Trailer(long contentLength, byte[] signature) { }
}
