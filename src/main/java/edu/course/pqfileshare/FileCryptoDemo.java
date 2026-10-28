package edu.course.pqfileshare;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.Console;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/** Runs a local file round-trip so file encryption can be tried before the GUI exists. */
public final class FileCryptoDemo {
    private FileCryptoDemo() { }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path keyStorePath = Path.of(System.getProperty("user.home"), ".pq-file-share", "recipient.pqky");
        KeyPair recipientKeys = loadOrCreateRecipientKeys(keyStorePath);

        Path demoFolder = Path.of("target", "file-demo");
        Files.createDirectories(demoFolder);
        Path input = demoFolder.resolve("sample.txt");
        Path encrypted = demoFolder.resolve("sample.txt.pqf");
        Path recovered = demoFolder.resolve("sample-recovered.txt");
        byte[] sample = "This file passed through ML-KEM-768, HKDF-SHA-256, and AES-256-GCM.\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Files.write(input, sample);

        FileCrypto.encrypt(input, encrypted, recipientKeys.getPublic());
        FileCrypto.decrypt(encrypted, recovered, recipientKeys.getPrivate());
        if (!Arrays.equals(sample, Files.readAllBytes(recovered))) {
            throw new IllegalStateException("The recovered file differs from the original.");
        }
        System.out.println("File encryption/decryption round trip succeeded.");
        System.out.println("Recipient key store: " + keyStorePath.toAbsolutePath());
        System.out.println("Created: " + encrypted.toAbsolutePath());
        System.out.println("Recovered: " + recovered.toAbsolutePath());
    }

    private static KeyPair loadOrCreateRecipientKeys(Path keyStorePath) throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Run this demo from an interactive PowerShell or terminal to enter the key-store password.");
        }
        if (Files.exists(keyStorePath)) {
            char[] password = console.readPassword("Password for your saved recipient key: ");
            if (password == null) throw new IllegalStateException("No password was entered.");
            return RecipientKeyStore.load(keyStorePath, password);
        }

        console.printf("Creating a recipient key store at %s%n", keyStorePath.toAbsolutePath());
        char[] password = console.readPassword("Choose a key-store password (at least 8 characters): ");
        char[] confirmation = console.readPassword("Enter the password again: ");
        if (password == null || confirmation == null || !Arrays.equals(password, confirmation)) {
            if (password != null) Arrays.fill(password, '\0');
            if (confirmation != null) Arrays.fill(confirmation, '\0');
            throw new IllegalArgumentException("The passwords were empty or did not match.");
        }
        Arrays.fill(confirmation, '\0');

        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", "BC");
        generator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair generated = generator.generateKeyPair();
        RecipientKeyStore.save(keyStorePath, generated, password);
        console.printf("Recipient keys saved. Keep the password safe; it cannot be recovered.%n");

        char[] unlockPassword = console.readPassword("Unlock the saved recipient key to continue: ");
        if (unlockPassword == null) throw new IllegalStateException("No password was entered.");
        return RecipientKeyStore.load(keyStorePath, unlockPassword);
    }
}
