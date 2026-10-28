package edu.course.pqfileshare;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/** Small RFC 5869 HKDF-SHA-256 implementation for deriving a file-encryption key. */
final class Hkdf {
    private Hkdf() { }

    static byte[] sha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] actualSalt = salt.length == 0 ? new byte[mac.getMacLength()] : salt;
        mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(inputKeyMaterial);

        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        try {
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
            return output;
        } finally {
            Arrays.fill(pseudorandomKey, (byte) 0);
            Arrays.fill(previous, (byte) 0);
        }
    }
}
