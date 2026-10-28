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
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
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
        primaryStage.setMinWidth(680);
        primaryStage.setMinHeight(600);
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
        signIn.setDefaultButton(true);
        signIn.getStyleClass().add("primary-button");
        create.getStyleClass().add("secondary-button");
        username.getStyleClass().add("input-field");
        password.getStyleClass().add("input-field");
        confirmation.getStyleClass().add("input-field");
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
        VBox fields = new VBox(12, username, password, confirmation, actions);
        VBox.setMargin(actions, new Insets(8, 0, 0, 0));
        signIn.setOnAction(event -> runAccountAction(false, username, password, confirmation, loginProgress, loginStatus, signIn, create));
        create.setOnAction(event -> runAccountAction(true, username, password, confirmation, loginProgress, loginStatus, signIn, create));

        Label eyebrow = new Label("PRIVATE FILE TRANSFER");
        eyebrow.getStyleClass().add("eyebrow");
        Label title = new Label("Secure File Share");
        title.getStyleClass().add("page-title");
        Label intro = new Label("A private, simple way to send files. Sign in or create an account to get started.");
        intro.setWrapText(true);
        intro.getStyleClass().add("intro-copy");
        VBox card = new VBox(18, eyebrow, title, intro, fields,
                new HBox(10, loginProgress, loginStatus));
        card.getStyleClass().add("surface");
        card.setPadding(new Insets(42));
        card.setMaxWidth(520);
        StackPane root = new StackPane(card);
        root.setAlignment(Pos.CENTER);
        root.setPadding(new Insets(28));
        root.getStyleClass().add("app-background");
        stage.setScene(createScene(root, 1000, 700));
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
        eyebrow.getStyleClass().add("eyebrow");
        Label title = new Label("Secure File Share");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("Prepare encrypted files, share them over your local network, and decrypt files sent to you.");
        subtitle.setWrapText(true);
        subtitle.getStyleClass().add("intro-copy");

        encryptButton = new Button("Encrypt a file for someone");
        encryptButton.setMaxWidth(Double.MAX_VALUE);
        encryptButton.setMinHeight(48);
        encryptButton.getStyleClass().add("primary-button");
        encryptButton.setOnAction(event -> encryptForRecipient());

        decryptButton = new Button("Decrypt selected inbox file");
        decryptButton.setMaxWidth(Double.MAX_VALUE);
        decryptButton.setMinHeight(48);
        decryptButton.getStyleClass().add("primary-button");
        decryptButton.setOnAction(event -> decryptReceivedFile());

        exportKeyButton = new Button("Export my public key");
        exportKeyButton.setMaxWidth(Double.MAX_VALUE);
        exportKeyButton.setMinHeight(44);
        exportKeyButton.getStyleClass().add("secondary-button");
        exportKeyButton.setOnAction(event -> exportPublicKey());

        importButton = new Button("Import encrypted file");
        importButton.setMaxWidth(Double.MAX_VALUE);
        importButton.setMinHeight(44);
        importButton.getStyleClass().add("secondary-button");
        importButton.setOnAction(event -> importReceivedFile());

        recipientAddress = new TextField();
        recipientAddress.setPromptText("Example: 192.168.1.10");
        sendPortField = new TextField("45821");
        sendPortField.setPromptText("Port");
        sendPortField.setPrefWidth(110);
        recipientAddress.getStyleClass().add("input-field");
        sendPortField.getStyleClass().add("input-field");
        sendFileButton = new Button("Choose .pqf file and send");
        sendFileButton.getStyleClass().add("secondary-button");
        sendFileButton.setOnAction(event -> sendEncryptedFile());
        Label sendTitle = new Label("Send over local network");
        sendTitle.getStyleClass().add("section-title");
        Label sendNote = new Label("Enter the receiving computer’s IP address. Choose an encrypted .pqf file to send.");
        sendNote.setWrapText(true);
        Label addressLabel = new Label("Recipient IP address");
        addressLabel.getStyleClass().add("field-label");
        Label sendPortLabel = new Label("Port");
        sendPortLabel.getStyleClass().add("field-label");
        VBox sendPortControl = new VBox(5, sendPortLabel, sendPortField);
        HBox senderRow = new HBox(10, sendPortControl, sendFileButton);
        senderRow.setAlignment(Pos.BOTTOM_LEFT);

        receivePortField = new TextField("45821");
        receivePortField.setPromptText("Port");
        receivePortField.setPrefWidth(110);
        receivePortField.getStyleClass().add("input-field");
        receiveButton = new Button("Start receiving");
        receiveButton.getStyleClass().add("secondary-button");
        receiveButton.setOnAction(event -> toggleReceiving());
        networkStatus = new Label("Not listening");
        networkStatus.setWrapText(true);
        Label receiveTitle = new Label("Receive over local network");
        receiveTitle.getStyleClass().add("section-title");
        Label receiveNote = new Label("Start listening first, then share your displayed address and port with the sender.");
        receiveNote.setWrapText(true);
        Label portLabel = new Label("Receive port");
        portLabel.getStyleClass().add("field-label");
        VBox receivePortControl = new VBox(5, portLabel, receivePortField);
        HBox receiverRow = new HBox(10, receivePortControl, receiveButton);
        receiverRow.setAlignment(Pos.BOTTOM_LEFT);
        networkStatus.getStyleClass().add("status-pill");
        VBox sendPanel = new VBox(12, sendTitle, sendNote, addressLabel, recipientAddress, senderRow);
        sendPanel.getStyleClass().add("subpanel");
        VBox receivePanel = new VBox(12, receiveTitle, receiveNote, receiverRow, networkStatus);
        receivePanel.getStyleClass().add("subpanel");

        Label inboxTitle = new Label("Your inbox");
        inboxTitle.getStyleClass().add("section-title");
        Label inboxNote = new Label("Import a .pqf file, select it, then decrypt it to a location you choose.");
        inboxNote.setWrapText(true);
        inbox = new ListView<>();
        inbox.setPlaceholder(new Label("Your inbox is empty"));
        inbox.setPrefHeight(210);
        inbox.setMinHeight(140);
        inbox.setMaxHeight(260);
        inbox.getStyleClass().add("file-list");
        inbox.setCellFactory(list -> new ListCell<>() {
            @Override protected void updateItem(Path item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : item.getFileName().toString());
            }
        });
        inbox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) ->
                decryptButton.setDisable(busy || newValue == null));
        decryptButton.setMaxWidth(Double.MAX_VALUE);
        VBox inboxPanel = new VBox(12, inboxTitle, inboxNote, importButton, inbox, decryptButton);
        inboxPanel.getStyleClass().add("panel");
        Label keyNote = new Label("File protection: ML-KEM-768 establishes a shared secret, HKDF-SHA-256 derives a key, and AES-256-GCM encrypts and authenticates the file. LAN transfer sends encrypted .pqf packages. Compare public-key fingerprints through a trusted, independent channel.");
        keyNote.setWrapText(true);
        keyNote.getStyleClass().add("security-note");

        progress = new ProgressIndicator();
        progress.setMaxSize(22, 22);
        progress.setVisible(false);
        status = new Label("Ready");
        status.getStyleClass().add("status-copy");
        HBox statusRow = new HBox(10, progress, status);
        statusRow.setAlignment(Pos.CENTER_LEFT);

        Label historyTitle = new Label("Recent activity");
        historyTitle.getStyleClass().add("section-title");
        history = new ListView<>();
        history.setPlaceholder(new Label("No files processed yet"));
        history.setPrefHeight(190);
        history.setMinHeight(130);
        history.setMaxHeight(260);
        history.getStyleClass().add("file-list");
        history.setCellFactory(list -> new ListCell<>() {
            private final Label text = new Label();
            { text.setWrapText(true); text.setMaxWidth(Double.MAX_VALUE); setContentDisplay(javafx.scene.control.ContentDisplay.GRAPHIC_ONLY); }
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                text.setText(empty || item == null ? "" : item);
                setGraphic(empty || item == null ? null : text);
            }
        });

        Label accountLabel = new Label("Signed in as " + currentAccount.username());
        logoutButton = new Button("Log out");
        logoutButton.setOnAction(event -> { currentAccount = null; showLoginScreen(); });
        accountLabel.getStyleClass().add("account-label");
        logoutButton.getStyleClass().add("quiet-button");
        HBox accountRow = new HBox(10, accountLabel, logoutButton);
        accountRow.setAlignment(Pos.CENTER_RIGHT);
        HBox.setHgrow(accountLabel, Priority.ALWAYS);
        Label sendActionTitle = new Label("Send a secure file");
        sendActionTitle.getStyleClass().add("section-title");
        Label sendActionNote = new Label("Choose a file and the recipient’s public key, then create an encrypted package.");
        sendActionNote.setWrapText(true);
        sendActionNote.getStyleClass().add("hint-copy");
        Label keyActionTitle = new Label("Share your public key");
        keyActionTitle.getStyleClass().add("section-title");
        Label keyActionNote = new Label("Export your public key so another person can encrypt a file for you.");
        keyActionNote.setWrapText(true);
        keyActionNote.getStyleClass().add("hint-copy");
        VBox sendAction = new VBox(9, sendActionTitle, sendActionNote, encryptButton);
        sendAction.getStyleClass().add("action-card");
        VBox keyAction = new VBox(9, keyActionTitle, keyActionNote, exportKeyButton);
        keyAction.getStyleClass().add("action-card");
        HBox actionRow = new HBox(14, sendAction, keyAction);
        actionRow.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(sendAction, Priority.ALWAYS);
        HBox.setHgrow(keyAction, Priority.ALWAYS);
        VBox transferPanel = new VBox(14, sendPanel, receivePanel, keyNote);
        VBox inboxColumn = new VBox(14, inboxPanel, historyTitle, history, statusRow);
        HBox.setHgrow(transferPanel, Priority.ALWAYS);
        HBox.setHgrow(inboxColumn, Priority.ALWAYS);
        GridPane columns = new GridPane();
        columns.setHgap(18);
        columns.setVgap(14);
        columns.add(transferPanel, 0, 0);
        columns.add(inboxColumn, 1, 0);
        VBox.setVgrow(inbox, Priority.ALWAYS);
        VBox card = new VBox(20, accountRow, eyebrow, title, subtitle, actionRow, columns);
        card.setPadding(new Insets(34));
        card.setMaxWidth(1440);
        card.getStyleClass().add("dashboard-content");
        columns.getColumnConstraints().setAll(new ColumnConstraints(), new ColumnConstraints());
        columns.getColumnConstraints().get(0).setPercentWidth(50);
        columns.getColumnConstraints().get(1).setPercentWidth(50);
        columns.widthProperty().addListener((obs, oldWidth, newWidth) -> {
            boolean wide = newWidth.doubleValue() >= 900;
            columns.getColumnConstraints().clear();
            if (wide) {
                ColumnConstraints left = new ColumnConstraints(); left.setPercentWidth(50);
                ColumnConstraints right = new ColumnConstraints(); right.setPercentWidth(50);
                columns.getColumnConstraints().addAll(left, right);
                GridPane.setConstraints(transferPanel, 0, 0);
                GridPane.setConstraints(inboxColumn, 1, 0);
                columns.setHgap(18);
            } else {
                ColumnConstraints full = new ColumnConstraints(); full.setPercentWidth(100);
                columns.getColumnConstraints().add(full);
                GridPane.setConstraints(transferPanel, 0, 0);
                GridPane.setConstraints(inboxColumn, 0, 1);
                columns.setHgap(0);
            }
        });
        ScrollPane scroll = new ScrollPane(card);
        scroll.setFitToWidth(true);
        scroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scroll.getStyleClass().add("app-scroll");
        StackPane screen = new StackPane(scroll);
        screen.setAlignment(Pos.TOP_CENTER);
        screen.getStyleClass().add("app-background");
        stage.setScene(createScene(screen, 1180, 860));
        refreshHistory();
        refreshInbox();
    }

    private Scene createScene(javafx.scene.Parent root, double width, double height) {
        Scene scene = new Scene(root, width, height);
        var stylesheet = getClass().getResource("/edu/course/pqfileshare/app.css");
        if (stylesheet != null) scene.getStylesheets().add(stylesheet.toExternalForm());
        return scene;
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

        FileChooser saveChooser = new FileChooser();
        saveChooser.setTitle("Save decrypted file");
        saveChooser.setInitialFileName(decryptedName(source.getFileName().toString()));
        File destination = saveChooser.showSaveDialog(stage);
        if (destination == null) return;

        setBusy(true, "Decrypting file…");
        Task<Boolean> operation = new Task<>() {
            @Override
            protected Boolean call() throws Exception {
                FileCrypto.decrypt(source, destination.toPath(), currentAccount.keys().getPrivate());
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
