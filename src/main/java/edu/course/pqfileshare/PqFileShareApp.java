package edu.course.pqfileshare;

import javafx.application.Application;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ListCell;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.sql.SQLException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Desktop workflow for exporting a key, encrypting for a recipient, and decrypting a received file. */
public final class PqFileShareApp extends Application {
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "pq-file-worker");
        thread.setDaemon(true);
        return thread;
    });

    private Stage stage;
    private AccountSession currentAccount;
    private boolean busy;
    private Button encryptButton;
    private Button decryptButton;
    private Button exportKeyButton;
    private Button exportSigningKeyButton;
    private Button importButton;
    private Button sendFileButton;
    private Button receiveButton;
    private Button logoutButton;
    private TextField recipientAddress;
    private TextField sendPortField;
    private TextField receivePortField;
    private Label networkStatus;
    private Task<Path> receiveTask;
    private volatile ServerSocket receivingServer;
    private ProgressIndicator progress;
    private Label status;
    private ListView<String> history;
    private ListView<Path> inbox;

    @Override
    public void start(Stage primaryStage) {
        stage = primaryStage;
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        try {
            AccountRepository.initialize();
            TransferHistoryRepository.initialize();
            showLoginScreen();
        } catch (SQLException e) {
            showMessage(Alert.AlertType.ERROR, "Startup failed", "Could not open the local account database: " + readableError(e));
        }
        primaryStage.setTitle("Secure File Share");
        primaryStage.setMinWidth(560);
        primaryStage.setMinHeight(510);
        primaryStage.show();
    }

    private void showLoginScreen() {
        TextField username = new TextField();
        username.setPromptText("Username (3–24 characters)");
        PasswordField password = new PasswordField();
        password.setPromptText("Password (at least 8 characters)");
        PasswordField confirmation = new PasswordField();
        confirmation.setPromptText("Repeat password (for new accounts)");
        Button signIn = new Button("Sign in");
        Button create = new Button("Create account");
        signIn.setStyle(buttonStyle(true));
        create.setStyle(buttonStyle(false));
        signIn.setMaxWidth(Double.MAX_VALUE);
        create.setMaxWidth(Double.MAX_VALUE);
        ProgressIndicator loginProgress = new ProgressIndicator();
        loginProgress.setMaxSize(22, 22);
        loginProgress.setVisible(false);
        Label loginStatus = new Label("Your account keeps your private key and activity separate.");
        loginStatus.setWrapText(true);
        HBox actions = new HBox(10, signIn, create);
        HBox.setHgrow(signIn, Priority.ALWAYS);
        HBox.setHgrow(create, Priority.ALWAYS);
        VBox fields = new VBox(10, username, password, confirmation, actions);
        VBox.setMargin(actions, new Insets(8, 0, 0, 0));
        signIn.setOnAction(event -> runAccountAction(false, username, password, confirmation, loginProgress, loginStatus, signIn, create));
        create.setOnAction(event -> runAccountAction(true, username, password, confirmation, loginProgress, loginStatus, signIn, create));

        Label eyebrow = new Label("PRIVATE FILE TRANSFER");
        eyebrow.setStyle("-fx-text-fill: #4e877f; -fx-font-size: 11px; -fx-font-weight: bold;");
        Label title = new Label("Secure File Share");
        title.setStyle("-fx-text-fill: #182b35; -fx-font-size: 30px; -fx-font-weight: bold;");
        VBox card = new VBox(16, eyebrow, title,
                new Label("Sign in, or create an account to get started."), fields,
                new HBox(10, loginProgress, loginStatus));
        card.setPadding(new Insets(32));
        card.setMaxWidth(540);
        card.setStyle("-fx-background-color: white; -fx-background-radius: 18; -fx-effect: dropshadow(gaussian, rgba(23,48,56,0.12), 24, 0.15, 0, 8);");
        VBox root = new VBox(card);
        root.setAlignment(Pos.CENTER);
        root.setPadding(new Insets(28));
        root.setStyle("-fx-background-color: #f1f5f3;");
        stage.setScene(new Scene(root, 700, 500));
    }

    private void runAccountAction(boolean creating, TextField username, PasswordField passwordField,
                                  PasswordField confirmation, ProgressIndicator indicator, Label message,
                                  Button signIn, Button create) {
        String name = username.getText();
        char[] secret = passwordField.getText().toCharArray();
        if (creating && !passwordField.getText().equals(confirmation.getText())) {
            message.setText("Those passwords do not match. Please try again.");
            java.util.Arrays.fill(secret, '\0');
            return;
        }
        signIn.setDisable(true);
        create.setDisable(true);
        indicator.setVisible(true);
        message.setText(creating ? "Creating your account and private key…" : "Signing in…");
        Task<AccountSession> task = new Task<>() {
            @Override protected AccountSession call() throws Exception {
                try {
                    return creating
                            ? AccountRepository.register(name, secret, legacyKeyPath())
                            : AccountRepository.login(name, secret);
                } finally {
                    java.util.Arrays.fill(secret, '\0');
                }
            }
        };
        task.setOnSucceeded(event -> {
            currentAccount = task.getValue();
            showHomeScreen();
        });
        task.setOnFailed(event -> {
            indicator.setVisible(false);
            signIn.setDisable(false);
            create.setDisable(false);
            message.setText(readableError(task.getException()));
        });
        executor.execute(task);
    }

    private void showHomeScreen() {

        Label eyebrow = new Label("PRIVATE FILE TRANSFER");
        eyebrow.setStyle("-fx-text-fill: #4e877f; -fx-font-size: 11px; -fx-font-weight: bold; -fx-letter-spacing: 1.4px;");
        Label title = new Label("Secure File Share");
        title.setStyle("-fx-text-fill: #182b35; -fx-font-size: 30px; -fx-font-weight: bold;");
        Label subtitle = new Label("Exchange public keys, then protect files with post-quantum key exchange and authenticated encryption.");
        subtitle.setWrapText(true);
        subtitle.setStyle("-fx-text-fill: #60737a; -fx-font-size: 14px;");

        encryptButton = new Button("Encrypt for a recipient");
        encryptButton.setMaxWidth(Double.MAX_VALUE);
        encryptButton.setMinHeight(48);
        encryptButton.setStyle(buttonStyle(true));
        encryptButton.setOnAction(event -> encryptForRecipient());

        decryptButton = new Button("Decrypt selected inbox file");
        decryptButton.setMaxWidth(Double.MAX_VALUE);
        decryptButton.setMinHeight(48);
        decryptButton.setStyle(buttonStyle(false));
        decryptButton.setOnAction(event -> decryptReceivedFile());

        exportKeyButton = new Button("Export my ML-KEM encryption key");
        exportKeyButton.setMaxWidth(Double.MAX_VALUE);
        exportKeyButton.setMinHeight(44);
        exportKeyButton.setStyle(buttonStyle(false));
        exportKeyButton.setOnAction(event -> exportPublicKey());

        exportSigningKeyButton = new Button("Export my ML-DSA signature key");
        exportSigningKeyButton.setMaxWidth(Double.MAX_VALUE);
        exportSigningKeyButton.setMinHeight(44);
        exportSigningKeyButton.setStyle(buttonStyle(false));
        exportSigningKeyButton.setOnAction(event -> exportSigningPublicKey());

        importButton = new Button("Add received .pqf file to inbox");
        importButton.setMaxWidth(Double.MAX_VALUE);
        importButton.setMinHeight(44);
        importButton.setStyle(buttonStyle(false));
        importButton.setOnAction(event -> importReceivedFile());

        Label networkTitle = new Label("Direct transfer over the local network");
        networkTitle.setStyle("-fx-text-fill: #26454b; -fx-font-size: 14px; -fx-font-weight: bold;");
        Label networkNote = new Label("The recipient starts listening first. The encrypted file carries its sender signature.");
        networkNote.setWrapText(true);
        recipientAddress = new TextField();
        recipientAddress.setPromptText("Recipient IP address");
        sendPortField = new TextField("45821");
        sendPortField.setPromptText("Port");
        sendPortField.setPrefWidth(88);
        sendFileButton = new Button("Send encrypted file");
        sendFileButton.setStyle(buttonStyle(false));
        sendFileButton.setOnAction(event -> sendEncryptedFile());
        HBox senderRow = new HBox(8, recipientAddress, sendPortField, sendFileButton);
        HBox.setHgrow(recipientAddress, Priority.ALWAYS);

        receivePortField = new TextField("45821");
        receivePortField.setPromptText("Port");
        receivePortField.setPrefWidth(88);
        receiveButton = new Button("Start receiving");
        receiveButton.setStyle(buttonStyle(false));
        receiveButton.setOnAction(event -> toggleReceiving());
        networkStatus = new Label("Not listening");
        networkStatus.setWrapText(true);
        HBox receiverRow = new HBox(8, new Label("Receive port:"), receivePortField, receiveButton);
        VBox networkPanel = new VBox(8, networkTitle, networkNote, senderRow, receiverRow, networkStatus);

        VBox actions = new VBox(12, encryptButton, exportKeyButton, exportSigningKeyButton);
        Label inboxTitle = new Label("Inbox");
        inboxTitle.setStyle("-fx-text-fill: #26454b; -fx-font-size: 14px; -fx-font-weight: bold;");
        Label inboxNote = new Label("Select a received file, verify the sender's signature key, then decrypt it.");
        inboxNote.setWrapText(true);
        inbox = new ListView<>();
        inbox.setPlaceholder(new Label("Your inbox is empty"));
        inbox.setPrefHeight(100);
        inbox.setMaxHeight(100);
        inbox.setCellFactory(list -> new ListCell<>() {
            @Override protected void updateItem(Path item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : item.getFileName().toString());
            }
        });
        inbox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) ->
                decryptButton.setDisable(busy || newValue == null));
        decryptButton.setMaxWidth(Double.MAX_VALUE);
        VBox inboxPanel = new VBox(8, inboxTitle, inboxNote, importButton, inbox, decryptButton);
        Label keyNote = new Label("Share .pqpub with the sender and .pqsigpub with the recipient. Compare both key fingerprints over a trusted channel.");
        keyNote.setWrapText(true);
        keyNote.setStyle("-fx-text-fill: #74858a; -fx-font-size: 12px;");

        progress = new ProgressIndicator();
        progress.setMaxSize(22, 22);
        progress.setVisible(false);
        status = new Label("Ready");
        status.setStyle("-fx-text-fill: #60737a; -fx-font-size: 12px;");
        HBox statusRow = new HBox(10, progress, status);
        statusRow.setAlignment(Pos.CENTER_LEFT);

        Label historyTitle = new Label("Recent activity");
        historyTitle.setStyle("-fx-text-fill: #26454b; -fx-font-size: 14px; -fx-font-weight: bold;");
        history = new ListView<>();
        history.setPlaceholder(new Label("No files processed yet"));
        history.setPrefHeight(120);
        history.setMaxHeight(120);

        Label accountLabel = new Label("Signed in as " + currentAccount.username());
        logoutButton = new Button("Log out");
        logoutButton.setOnAction(event -> { currentAccount = null; showLoginScreen(); });
        HBox accountRow = new HBox(10, accountLabel, logoutButton);
        accountRow.setAlignment(Pos.CENTER_RIGHT);
        VBox card = new VBox(14, accountRow, eyebrow, title, subtitle, actions, keyNote,
                networkPanel, inboxPanel, historyTitle, history, statusRow);
        card.setPadding(new Insets(32));
        card.setMaxWidth(540);
        card.setStyle("-fx-background-color: white; -fx-background-radius: 18; -fx-effect: dropshadow(gaussian, rgba(23,48,56,0.12), 24, 0.15, 0, 8);");
        ScrollPane scroll = new ScrollPane(card);
        scroll.setFitToWidth(true);
        scroll.setStyle("-fx-background: #f1f5f3; -fx-background-color: #f1f5f3;");
        VBox screen = new VBox(scroll);
        screen.setAlignment(Pos.CENTER);
        screen.setPadding(new Insets(18));
        screen.setStyle("-fx-background-color: #f1f5f3;");
        VBox.setVgrow(scroll, Priority.ALWAYS);
        stage.setScene(new Scene(screen, 760, 820));
        refreshHistory();
        refreshInbox();
    }

    private static String buttonStyle(boolean primary) {
        return primary
                ? "-fx-background-color: #26766e; -fx-text-fill: white; -fx-font-size: 14px; -fx-font-weight: bold; -fx-background-radius: 10; -fx-cursor: hand;"
                : "-fx-background-color: #e8efed; -fx-text-fill: #26454b; -fx-font-size: 14px; -fx-font-weight: bold; -fx-background-radius: 10; -fx-cursor: hand;";
    }

    private void encryptForRecipient() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a file to encrypt");
        File source = chooser.showOpenDialog(stage);
        if (source == null) return;

        FileChooser keyChooser = new FileChooser();
        keyChooser.setTitle("Choose the recipient's public key");
        keyChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PQFS public keys", "*.pqpub"));
        File publicKeyFile = keyChooser.showOpenDialog(stage);
        if (publicKeyFile == null) return;

        java.security.PublicKey recipientPublicKey;
        String fingerprint;
        try {
            recipientPublicKey = PublicKeyFile.read(publicKeyFile.toPath());
            fingerprint = PublicKeyFile.fingerprint(recipientPublicKey);
        } catch (Exception e) {
            showMessage(Alert.AlertType.ERROR, "Public key could not be read", readableError(e));
            return;
        }
        Alert verify = new Alert(Alert.AlertType.CONFIRMATION);
        verify.initOwner(stage);
        verify.setTitle("Verify recipient key");
        verify.setHeaderText("Confirm this key belongs to the intended recipient");
        verify.setContentText("Compare this fingerprint with the recipient over a trusted channel before continuing:\n\n"
                + fingerprint + "\n\nContinue only if it matches.");
        if (verify.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;

        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Save encrypted file");
        saveChooser.setInitialFileName(source.getName() + ".pqf");
        File destination = saveChooser.showSaveDialog(stage);
        if (destination == null) return;

        setBusy(true, "Encrypting for recipient…");
        Task<Boolean> operation = new Task<>() {
            @Override
            protected Boolean call() throws Exception {
                FileCrypto.encrypt(source.toPath(), destination.toPath(), recipientPublicKey);
                FileSignature.sign(destination.toPath(), currentAccount.signingKeys().getPrivate());
                return recordTransfer("ENCRYPTED", destination, recipientPublicKey);
            }
        };
        operation.setOnSucceeded(event -> {
            refreshHistory();
            finishOperation(destination, "Encrypted file ready", operation.getValue());
        });
        operation.setOnFailed(event -> failOperation(operation.getException()));
        executor.execute(operation);
    }

    private void importReceivedFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose the .pqf file you received");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PQFS encrypted files", "*.pqf"));
        File selected = chooser.showOpenDialog(stage);
        if (selected == null) return;
        Path source = selected.toPath();
        setBusy(true, "Adding file to your inbox…");
        Task<Path> operation = new Task<>() {
            @Override protected Path call() throws Exception {
                Path inboxFolder = inboxPath();
                Files.createDirectories(inboxFolder);
                Path destination = unusedInboxPath(inboxFolder, source.getFileName().toString());
                Files.copy(source, destination);
                return destination;
            }
        };
        operation.setOnSucceeded(event -> {
            refreshInbox();
            setBusy(false, "Added to inbox: " + operation.getValue().getFileName());
        });
        operation.setOnFailed(event -> failOperation(operation.getException()));
        executor.execute(operation);
    }

    private void sendEncryptedFile() {
        String host = recipientAddress.getText().trim();
        if (host.isEmpty()) {
            showMessage(Alert.AlertType.INFORMATION, "Recipient address needed", "Enter the recipient's local IP address first.");
            return;
        }
        final int port;
        try {
            port = parsePort(sendPortField.getText());
        } catch (IllegalArgumentException e) {
            showMessage(Alert.AlertType.ERROR, "Port is not valid", e.getMessage());
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose the encrypted file to send");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Encrypted PQFS files", "*.pqf"));
        File encrypted = chooser.showOpenDialog(stage);
        if (encrypted == null) return;

        setBusy(true, "Sending encrypted file to " + host + "…");
        Task<Void> task = new Task<>() {
            @Override protected Void call() throws Exception {
                NetworkFileTransfer.send(encrypted.toPath(), host, port);
                return null;
            }
        };
        task.setOnSucceeded(event -> setBusy(false, "File sent: " + encrypted.getName()));
        task.setOnFailed(event -> failOperation(task.getException()));
        executor.execute(task);
    }

    private void toggleReceiving() {
        if (receiveTask != null) {
            stopReceiving();
            return;
        }
        final int port;
        try {
            port = parsePort(receivePortField.getText());
        } catch (IllegalArgumentException e) {
            showMessage(Alert.AlertType.ERROR, "Port is not valid", e.getMessage());
            return;
        }

        final ServerSocket server;
        try {
            server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(port));
            server.setSoTimeout(1000);
        } catch (IOException e) {
            showMessage(Alert.AlertType.ERROR, "Could not start receiving", readableError(e));
            return;
        }
        receivingServer = server;
        Path accountInbox = inboxPath();
        Task<Path> task = new Task<>() {
            @Override protected Path call() throws Exception {
                try (server) {
                    while (!isCancelled()) {
                        try {
                            Socket client = server.accept();
                            return NetworkFileTransfer.receive(client, accountInbox);
                        } catch (SocketTimeoutException ignored) {
                            // Check periodically whether the user asked to stop listening.
                        }
                    }
                    throw new InterruptedException("Receiving stopped.");
                }
            }
        };
        receiveTask = task;
        receiveButton.setText("Stop receiving");
        receivePortField.setDisable(true);
        logoutButton.setDisable(true);
        String localAddress;
        try {
            localAddress = InetAddress.getLocalHost().getHostAddress();
        } catch (IOException e) {
            localAddress = "this computer's local IP address";
        }
        networkStatus.setText("Waiting for one file at " + localAddress + ":" + port
                + ". Give this address and port to the sender.");
        task.setOnSucceeded(event -> {
            if (receiveTask != task) return;
            finishListening(task);
            refreshInbox();
            networkStatus.setText("Received " + task.getValue().getFileName() + ". It is now in your inbox.");
        });
        task.setOnFailed(event -> {
            if (receiveTask != task) return;
            finishListening(task);
            networkStatus.setText("Receive failed: " + readableError(task.getException()));
        });
        task.setOnCancelled(event -> {
            if (receiveTask == task) finishListening(task);
        });
        executor.execute(task);
    }

    private void stopReceiving() {
        Task<Path> task = receiveTask;
        ServerSocket server = receivingServer;
        receiveTask = null;
        receivingServer = null;
        if (task != null) task.cancel(true);
        if (server != null) {
            try { server.close(); } catch (IOException ignored) { }
        }
        receiveButton.setText("Start receiving");
        receivePortField.setDisable(false);
        logoutButton.setDisable(false);
        networkStatus.setText("Stopped listening.");
    }

    private void finishListening(Task<Path> task) {
        if (receiveTask != task) return;
        receiveTask = null;
        receivingServer = null;
        receiveButton.setText("Start receiving");
        receivePortField.setDisable(false);
        logoutButton.setDisable(false);
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value.trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Enter a port number from 1 to 65535, for example 45821.");
        }
    }

    private void decryptReceivedFile() {
        Path source = inbox.getSelectionModel().getSelectedItem();
        if (source == null) {
            showMessage(Alert.AlertType.INFORMATION, "Choose a file", "First add a received .pqf file to your inbox, then select it.");
            return;
        }

        final boolean signed;
        final java.security.PublicKey senderSigningKey;
        final long encryptedContainerLength;
        try {
            signed = FileSignature.hasSignature(source);
            if (signed) {
                FileChooser keyChooser = new FileChooser();
                keyChooser.setTitle("Choose the sender's ML-DSA verification key");
                keyChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PQFS signature keys", "*.pqsigpub"));
                File signingKeyFile = keyChooser.showOpenDialog(stage);
                if (signingKeyFile == null) return;
                senderSigningKey = SigningPublicKeyFile.read(signingKeyFile.toPath());
                String fingerprint = SigningPublicKeyFile.fingerprint(senderSigningKey);
                Alert verify = new Alert(Alert.AlertType.CONFIRMATION);
                verify.initOwner(stage);
                verify.setTitle("Verify sender's signature key");
                verify.setHeaderText("Compare this fingerprint with the sender over a trusted channel");
                verify.setContentText(fingerprint + "\n\nContinue only if it matches the sender's fingerprint.");
                if (verify.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
            } else {
                senderSigningKey = null;
                Alert warning = new Alert(Alert.AlertType.CONFIRMATION);
                warning.initOwner(stage);
                warning.setTitle("Unsigned file");
                warning.setHeaderText("This older file has no sender signature");
                warning.setContentText("The encrypted contents can still be checked, but the sender's identity cannot be verified. Continue anyway?");
                if (warning.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
            }
            encryptedContainerLength = FileSignature.encryptedContainerLength(source);
        } catch (Exception e) {
            showMessage(Alert.AlertType.ERROR, "Signature key or file could not be checked", readableError(e));
            return;
        }

        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Save decrypted file");
        saveChooser.setInitialFileName(decryptedName(source.getFileName().toString()));
        File destination = saveChooser.showSaveDialog(stage);
        if (destination == null) return;

        setBusy(true, "Decrypting file…");
        Task<Boolean> operation = new Task<>() {
            @Override
            protected Boolean call() throws Exception {
                if (signed) FileSignature.verify(source, senderSigningKey);
                FileCrypto.decrypt(source, destination.toPath(), currentAccount.keys().getPrivate(), encryptedContainerLength);
                return recordTransfer("DECRYPTED", destination, currentAccount.keys().getPublic());
            }
        };
        operation.setOnSucceeded(event -> {
            refreshHistory();
            finishOperation(destination, "Decrypted file ready", operation.getValue());
        });
        operation.setOnFailed(event -> failOperation(operation.getException()));
        operation.setOnCancelled(event -> setBusy(false, "Operation cancelled."));
        executor.execute(operation);
    }

    private void exportPublicKey() {
        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Save your public key to share");
        saveChooser.setInitialFileName("my-recipient-key.pqpub");
        File destination = saveChooser.showSaveDialog(stage);
        if (destination == null) return;

        setBusy(true, "Exporting your public key…");
        Task<String> operation = new Task<>() {
            @Override
            protected String call() throws Exception {
                PublicKeyFile.write(destination.toPath(), currentAccount.keys().getPublic());
                return PublicKeyFile.fingerprint(currentAccount.keys().getPublic());
            }
        };
        operation.setOnSucceeded(event -> {
            setBusy(false, "Public key exported.");
            showMessage(Alert.AlertType.INFORMATION, "Public key ready",
                    "Share this .pqpub file with the sender:\n" + destination.getAbsolutePath()
                            + "\n\nFingerprint (the sender should compare this with you):\n" + operation.getValue());
        });
        operation.setOnFailed(event -> failOperation(operation.getException()));
        executor.execute(operation);
    }

    private void exportSigningPublicKey() {
        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Save your ML-DSA signature public key to share");
        saveChooser.setInitialFileName("my-signature-key.pqsigpub");
        File destination = saveChooser.showSaveDialog(stage);
        if (destination == null) return;

        setBusy(true, "Exporting your signature verification key…");
        Task<String> operation = new Task<>() {
            @Override protected String call() throws Exception {
                SigningPublicKeyFile.write(destination.toPath(), currentAccount.signingKeys().getPublic());
                return SigningPublicKeyFile.fingerprint(currentAccount.signingKeys().getPublic());
            }
        };
        operation.setOnSucceeded(event -> {
            setBusy(false, "Signature public key exported.");
            showMessage(Alert.AlertType.INFORMATION, "Signature verification key ready",
                    "Share this .pqsigpub file with people who receive your files:\n" + destination.getAbsolutePath()
                            + "\n\nFingerprint (the recipient should compare this with you):\n" + operation.getValue());
        });
        operation.setOnFailed(event -> failOperation(operation.getException()));
        executor.execute(operation);
    }

    private static Path legacyKeyPath() {
        return Path.of(System.getProperty("user.home"), ".pq-file-share", "recipient.pqky");
    }

    private static String decryptedName(String fileName) {
        return fileName.toLowerCase().endsWith(".pqf")
                ? fileName.substring(0, fileName.length() - 4)
                : fileName + ".decrypted";
    }

    private static String readableError(Throwable error) {
        if (error == null) return "An unexpected error occurred.";
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message != null && message.contains("Could not unlock the key store")) {
                return "The key-store password was incorrect, or the key file is damaged.";
            }
            if (message != null && message.contains("Could not decrypt the file")) {
                return "This file could not be authenticated. It may be damaged or encrypted for a different recipient.";
            }
        }
        Throwable cause = error;
        while (cause.getCause() != null) cause = cause.getCause();
        String message = cause.getMessage();
        return message == null ? cause.getClass().getSimpleName() : message;
    }

    private void setBusy(boolean busy, String message) {
        this.busy = busy;
        encryptButton.setDisable(busy);
        decryptButton.setDisable(busy || inbox == null || inbox.getSelectionModel().getSelectedItem() == null);
        exportKeyButton.setDisable(busy);
        exportSigningKeyButton.setDisable(busy);
        importButton.setDisable(busy);
        sendFileButton.setDisable(busy);
        recipientAddress.setDisable(busy);
        sendPortField.setDisable(busy);
        receiveButton.setDisable(busy && receiveTask == null);
        receivePortField.setDisable(busy || receiveTask != null);
        logoutButton.setDisable(busy || receiveTask != null);
        progress.setVisible(busy);
        status.setText(message);
    }

    private boolean recordTransfer(String direction, File destination, java.security.PublicKey key) {
        try {
            TransferHistoryRepository.record(currentAccount.id(), direction, destination.getName(), destination.getAbsolutePath(),
                    PublicKeyFile.fingerprint(key));
            return true;
        } catch (Exception ignored) {
            // The output file is already complete; a history problem must not present it as a failed crypto operation.
            return false;
        }
    }

    private void refreshHistory() {
        try {
            history.getItems().setAll(TransferHistoryRepository.recentSummaries(currentAccount.id(), 6));
        } catch (SQLException e) {
            status.setText("Local history is unavailable.");
        }
    }

    private Path inboxPath() {
        String keyFileName = currentAccount.keyStorePath().getFileName().toString();
        String inboxName = keyFileName.endsWith(".pqky")
                ? keyFileName.substring(0, keyFileName.length() - 5) + ".inbox"
                : keyFileName + ".inbox";
        return currentAccount.keyStorePath().resolveSibling(inboxName);
    }

    private static Path unusedInboxPath(Path folder, String fileName) throws IOException {
        String base = fileName;
        String extension = "";
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            base = fileName.substring(0, dot);
            extension = fileName.substring(dot);
        }
        Path candidate = folder.resolve(fileName);
        int copyNumber = 1;
        while (Files.exists(candidate)) {
            candidate = folder.resolve(base + " (" + copyNumber++ + ")" + extension);
        }
        return candidate;
    }

    private void refreshInbox() {
        try {
            Path folder = inboxPath();
            Files.createDirectories(folder);
            try (var files = Files.list(folder)) {
                inbox.getItems().setAll(files.filter(Files::isRegularFile)
                        .filter(file -> file.getFileName().toString().toLowerCase().endsWith(".pqf"))
                        .sorted((left, right) -> left.getFileName().toString().compareToIgnoreCase(right.getFileName().toString()))
                        .toList());
            }
            setBusy(false, inbox.getItems().isEmpty() ? "Inbox is empty. Add a received .pqf file to begin." : "Ready");
        } catch (IOException e) {
            status.setText("Could not open your inbox folder.");
        }
        decryptButton.setDisable(busy || inbox.getSelectionModel().getSelectedItem() == null);
    }

    private void finishOperation(File destination, String heading, boolean historySaved) {
        setBusy(false, "Finished: " + destination.getName());
        String message = "Saved the result to:\n" + destination.getAbsolutePath();
        if (heading.equals("Encrypted file ready")) {
            message += "\n\nThe recipient also needs your .pqsigpub file and should compare its fingerprint with you.";
        }
        if (!historySaved) message += "\n\nThe file is ready, but it could not be added to local history.";
        showMessage(Alert.AlertType.INFORMATION, heading, message);
    }

    private void failOperation(Throwable error) {
        setBusy(false, "Could not complete the file operation.");
        showMessage(Alert.AlertType.ERROR, "File operation failed", readableError(error));
    }

    private void showMessage(Alert.AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.initOwner(stage);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    @Override
    public void stop() {
        executor.shutdownNow();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
