package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/** Minimal end-to-end proof of concept: ML-KEM-768 -> HKDF-SHA-256 -> AES-256-GCM. */
public final class CryptoDemo {
    private static final String PROVIDER = "BC";
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoDemo() { }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Receiver creates a public/private ML-KEM key pair.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", PROVIDER);
        keyPairGenerator.initialize(MLKEMParameterSpec.ml_kem_768, RANDOM);
        KeyPair receiverKeys = keyPairGenerator.generateKeyPair();

        // Sender encapsulates to the receiver's public key; only the receiver can decapsulate.
        KEM kem = KEM.getInstance("ML-KEM", PROVIDER);
        KEM.Encapsulated encapsulated = kem.newEncapsulator(receiverKeys.getPublic()).encapsulate();
        byte[] sharedSecret = encapsulated.key().getEncoded();
        byte[] fileKey = hkdfSha256(sharedSecret, encapsulated.encapsulation(),
                "pq-file-share:file-encryption:v1".getBytes(StandardCharsets.UTF_8), 32);

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] plaintext = "Hello from the post-quantum file-sharing proof of concept."
                .getBytes(StandardCharsets.UTF_8);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"), new GCMParameterSpec(128, nonce));
        byte[] ciphertext = aes.doFinal(plaintext);

        byte[] receiverSecret = kem.newDecapsulator(receiverKeys.getPrivate())
                .decapsulate(encapsulated.encapsulation()).getEncoded();
        byte[] receiverKey = hkdfSha256(receiverSecret, encapsulated.encapsulation(),
                "pq-file-share:file-encryption:v1".getBytes(StandardCharsets.UTF_8), 32);
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(receiverKey, "AES"), new GCMParameterSpec(128, nonce));
        byte[] recovered = aes.doFinal(ciphertext);

        if (!Arrays.equals(plaintext, recovered)) {
            throw new IllegalStateException("Decryption check failed");
        }
        System.out.println("ML-KEM-768 encapsulation and AES-256-GCM round trip succeeded.");
        System.out.println("Recovered: " + new String(recovered, StandardCharsets.UTF_8));
        System.out.printf("Encapsulation: %d bytes; ciphertext: %d bytes%n",
                encapsulated.encapsulation().length, ciphertext.length);
    }

    /** RFC 5869 HKDF with SHA-256. */
    private static byte[] hkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] actualSalt = salt.length == 0 ? new byte[mac.getMacLength()] : salt;
        mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(inputKeyMaterial);

        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for (int counter = 1; offset < length; counter++) {
            mac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int count = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, output, offset, count);
            offset += count;
        }
        Arrays.fill(pseudorandomKey, (byte) 0);
        Arrays.fill(previous, (byte) 0);
        return output;
    }
}
