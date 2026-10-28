package edu.course.pqfileshare;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

/** Sends and receives already-encrypted PQFS files over a local TCP connection. */
public final class NetworkFileTransfer {
    private static final int MAGIC = 0x50514653; // "PQFS"
    private static final long MAX_FILE_SIZE = 4L * 1024 * 1024 * 1024;

    private NetworkFileTransfer() { }

    public static void send(Path encryptedFile, String host, int port) throws IOException {
        String fileName = encryptedFile.getFileName().toString();
        if (!fileName.toLowerCase().endsWith(".pqf")) {
            throw new IOException("Choose an encrypted .pqf file to send.");
        }
        long size = Files.size(encryptedFile);
        if (size <= 0 || size > MAX_FILE_SIZE) {
            throw new IOException("The encrypted file must be between 1 byte and 4 GB.");
        }

        try (Socket socket = new Socket(host, port);
             DataOutputStream output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
             DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             var fileInput = Files.newInputStream(encryptedFile)) {
            output.writeInt(MAGIC);
            output.writeUTF(fileName);
            output.writeLong(size);
            byte[] buffer = new byte[64 * 1024];
            long remaining = size;
            while (remaining > 0) {
                int count = fileInput.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (count < 0) throw new EOFException("The encrypted file changed during transfer.");
                output.write(buffer, 0, count);
                remaining -= count;
            }
            output.flush();
            if (input.readBoolean() != true) throw new IOException("The recipient could not save the file.");
        }
    }

    /** Receives one file from an accepted socket and saves it without overwriting inbox files. */
    public static Path receive(Socket socket, Path inboxFolder) throws IOException {
        Files.createDirectories(inboxFolder);
        Path temporary = null;
        boolean saved = false;
        try (socket;
             DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             DataOutputStream output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {
            if (input.readInt() != MAGIC) throw new IOException("This is not a PQFS file transfer.");
            String fileName = input.readUTF();
            if (!validFileName(fileName)) throw new IOException("The sender provided an invalid encrypted file name.");
            long size = input.readLong();
            if (size <= 0 || size > MAX_FILE_SIZE) throw new IOException("The received file size is not allowed.");

            temporary = Files.createTempFile(inboxFolder, ".incoming-", ".tmp");
            try (var fileOutput = new BufferedOutputStream(Files.newOutputStream(temporary))) {
                byte[] buffer = new byte[64 * 1024];
                long remaining = size;
                while (remaining > 0) {
                    int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                    if (count < 0) throw new EOFException("The sender disconnected before the file was complete.");
                    fileOutput.write(buffer, 0, count);
                    remaining -= count;
                }
            }

            Path destination = unusedPath(inboxFolder, fileName);
            Files.move(temporary, destination);
            saved = true;
            output.writeBoolean(true);
            output.flush();
            return destination;
        } finally {
            if (!saved && temporary != null) Files.deleteIfExists(temporary);
        }
    }

    private static boolean validFileName(String fileName) {
        return fileName != null && fileName.length() <= 240
                && fileName.toLowerCase().endsWith(".pqf")
                && Path.of(fileName).getFileName().toString().equals(fileName)
                && !fileName.contains("/") && !fileName.contains("\\");
    }

    private static Path unusedPath(Path folder, String fileName) {
        String base = fileName.substring(0, fileName.length() - 4);
        Path candidate = folder.resolve(fileName);
        int copy = 1;
        while (Files.exists(candidate)) candidate = folder.resolve(base + " (" + copy++ + ").pqf");
        return candidate;
    }
}
