# PQ File Share — JavaFX checkpoint

This is the next runnable checkpoint for **Secure Multimedia File Sharing Using Post-Quantum Cryptography: ML-KEM and AES-GCM**.

The desktop app supports local accounts and the first two-person file exchange:

1. Each person creates an account with a username and password. Each account has its own ML-KEM keys and private activity history.
2. The recipient selects **Create or export my public key** and shares the resulting `.pqpub` file.
3. The sender selects **Encrypt for a recipient**, chooses a file and the recipient's `.pqpub`, checks the displayed fingerprint with the recipient over a trusted channel, and saves the `.pqf` file.
4. For a direct transfer, the recipient clicks **Start receiving** and shares the displayed IP address and port. The sender enters those values and selects **Send encrypted file**. The received file appears in the recipient's Inbox. (Alternatively, share the `.pqf` file outside the app and add it to the Inbox.)
5. The recipient selects the file in the Inbox and decrypts it.

Cryptographic and file operations run in a background worker so the window remains responsive. Direct transfer works between computers that can reach each other on the same local network. The TCP connection carries only the already-encrypted `.pqf` file. If Windows Firewall asks, allow the app on your private network. The app keeps each account's incoming `.pqf` files in its own local inbox folder and shows the six most recent completed file operations in that account's activity list. Activity is saved in a local SQLite database at `~/.pq-file-share/transfers.db`. It stores file names, paths, timestamps, direction, and recipient-key fingerprints; it does not store file contents or private keys in the history database.

## Work with your teammate using Git

The shared repository is [Secure Multimedia File Sharing Using Post-Quantum Cryptography](https://github.com/Abdulla-Farshinsha/Secure-Multimedia-File-Sharing-Using-Post-Quantum-Cryptography). Your teammate clones it once:

```text
git clone https://github.com/Abdulla-Farshinsha/Secure-Multimedia-File-Sharing-Using-Post-Quantum-Cryptography.git
```

Before starting work, each person gets the latest changes:

```text
git pull
```

After making a change, save and share it:

```text
git add .
git commit -m "Describe the change"
git push
```

The other person then runs `git pull`. Try not to edit the same file at the same time; Git may ask you to resolve a conflict if both people change the same lines.

## Requirements

- JDK 21 or later (the current environment has Java 25).
- Apache Maven 3.9 or later.
- Internet access the first time, so Maven can download dependencies.

## Run the desktop app

From the project folder:

```text
mvn javafx:run
```

On first use, choose **Create account**, enter a username (3–24 letters, numbers, dots, dashes, or underscores), and choose a password of at least 8 characters. If you already made a recipient key in the earlier version of the app, use that same password when creating the first account; this keeps your existing public key valid. Later, sign in using the account username and password. Use **Log out** to switch accounts.

The earlier command-line cryptography demo remains available:

```text
mvn compile exec:java
```

It asks for the key-store password in the terminal and creates example files under `target/file-demo`.

## What the first checkpoint proves

- ML-KEM is used to establish a shared secret; it does not encrypt the file directly.
- HKDF derives the 256-bit symmetric key from that secret.
- AES-GCM provides file-content confidentiality and detects tampering.
- The encapsulation and 12-byte nonce must travel with the encrypted data. The private key stays with the recipient.

The `.pqf` format currently stores a magic marker, version, ML-KEM encapsulation, nonce, and encrypted bytes. The `.pqpub` file contains the recipient's ML-KEM public key. The `.pqky` key store keeps the public key available and encrypts the private key using PBKDF2-HMAC-SHA-256 and AES-GCM.
