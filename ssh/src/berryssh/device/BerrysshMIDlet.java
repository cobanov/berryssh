package berryssh.device;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.microedition.io.Connector;
import javax.microedition.io.SocketConnection;
import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.AlertType;
import javax.microedition.lcdui.Choice;
import javax.microedition.lcdui.ChoiceGroup;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;
import javax.microedition.lcdui.List;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;

import berryssh.crypto.EntropyPool;
import berryssh.protocol.Channel;
import berryssh.protocol.Connection;
import berryssh.protocol.HostKey;
import berryssh.protocol.KnownHosts;
import berryssh.protocol.UserAuth;
import berryssh.protocol.Utf8;
import berryssh.terminal.BitmapFont;
import berryssh.terminal.VT320;

/**
 * The application.
 *
 * Everything below this class is plain MIDP and CLDC and touches no RIM API,
 * which is the whole point: code that never reaches a protected API needs no
 * BlackBerry signature, and the authority that issued those no longer exists.
 * That also rules out BlackBerry's own UI framework — these are MIDP screens,
 * which the device draws in its own theme but which are not, and cannot be,
 * the native widgets.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class BerrysshMIDlet extends MIDlet implements CommandListener {

    private static final String FONT = "/fonts/mono8x14.png";
    private static final int CELL_WIDTH = 8;
    private static final int CELL_HEIGHT = 14;

    private static final String NEW_CONNECTION = "New connection...";

    /**
     * Lines kept above the screen. The device measured ~357 MB of free heap and
     * a line is a few hundred bytes, so this is nothing — and a terminal that
     * cannot show what just scrolled past is barely a terminal on 24 rows.
     */
    private static final int SCROLLBACK_LINES = 500;

    // The connection list
    private final Command connect = new Command("Connect", Command.ITEM, 1);
    private final Command newConnection = new Command("New", Command.SCREEN, 2);
    private final Command edit = new Command("Edit", Command.SCREEN, 3);
    private final Command delete = new Command("Delete", Command.SCREEN, 4);
    private final Command quit = new Command("Quit", Command.EXIT, 9);

    // The editor
    private final Command save = new Command("Save", Command.OK, 1);
    private final Command back = new Command("Back", Command.BACK, 2);

    // The password prompt
    private final Command go = new Command("Connect", Command.OK, 1);

    // The host key prompt
    private final Command acceptKey = new Command("Accept", Command.OK, 1);
    private final Command rejectKey = new Command("Reject", Command.CANCEL, 2);

    // The terminal
    private final Command control = new Command("Ctrl", Command.SCREEN, 1);
    private final Command escape = new Command("Esc", Command.SCREEN, 2);
    private final Command pageUp = new Command("Page up", Command.SCREEN, 3);
    private final Command pageDown = new Command("Page down", Command.SCREEN, 4);
    private final Command keys = new Command("Keys", Command.SCREEN, 5);
    private final Command fullScreen = new Command("Full screen", Command.SCREEN, 6);
    private final Command reconnect = new Command("Reconnect", Command.SCREEN, 7);
    private final Command disconnect = new Command("Disconnect", Command.STOP, 8);

    private Display display;
    private List connections;
    private Profile[] profiles = new Profile[0];

    private Form editor;
    private TextField nameField;
    private TextField hostField;
    private TextField portField;
    private TextField userField;
    private TextField passwordField;
    private ChoiceGroup savePasswordChoice;
    private String editingName;

    private TextField promptPassword;
    private Profile pendingProfile;

    private TerminalCanvas canvas;
    private Keyboard keyboard;
    private VT320 terminal;
    private Profile current;

    private final EntropyPool random = new EntropyPool();
    private final RecordStoreHostKeys hostKeys = new RecordStoreHostKeys();
    private final RecordStoreProfiles store = new RecordStoreProfiles();

    private SocketConnection socket;
    private Channel channel;
    private volatile boolean running;
    private boolean fullScreenOn;

    /**
     * How the session thread asks the user something and waits for an answer.
     * The question is raised on one thread and answered on another, and the
     * connection cannot proceed until it is — which is what a confirmation is.
     */
    private final Object promptLock = new Object();
    private Boolean promptAnswer;

    protected void startApp() {
        if (display != null) {
            return;
        }
        display = Display.getDisplay(this);

        // Seeding costs about a tenth of a second and has to happen before any
        // key material is asked for. Doing it here spends it while the user is
        // still choosing a connection.
        new Thread(new Runnable() {
            public void run() {
                random.seed();
            }
        }).start();

        connections = new List("berryssh", Choice.IMPLICIT);
        connections.addCommand(connect);
        connections.addCommand(newConnection);
        connections.addCommand(edit);
        connections.addCommand(delete);
        connections.addCommand(quit);
        connections.setCommandListener(this);
        refreshConnections();
        display.setCurrent(connections);
    }

    protected void pauseApp() {
    }

    protected void destroyApp(boolean unconditional) {
        shutdown();
    }

    private void refreshConnections() {
        try {
            profiles = store.list();
        } catch (IOException e) {
            profiles = new Profile[0];
        }
        connections.deleteAll();
        for (int i = 0; i < profiles.length; i++) {
            connections.append(profiles[i].label(), null);
        }
        connections.append(NEW_CONNECTION, null);
    }

    /** The profile the list is pointing at, or null for the New entry. */
    private Profile selected() {
        int index = connections.getSelectedIndex();
        if (index < 0 || index >= profiles.length) {
            return null;
        }
        return profiles[index];
    }

    public void commandAction(Command command, Displayable from) {
        if (command == quit) {
            shutdown();
            notifyDestroyed();
            return;
        }

        if (from == connections) {
            if (command == List.SELECT_COMMAND || command == connect) {
                Profile profile = selected();
                if (profile == null) {
                    showEditor(null);
                } else {
                    begin(profile);
                }
                return;
            }
            if (command == newConnection) {
                showEditor(null);
                return;
            }
            if (command == edit) {
                showEditor(selected());
                return;
            }
            if (command == delete) {
                Profile profile = selected();
                if (profile != null) {
                    try {
                        store.delete(profile.name());
                    } catch (IOException e) {
                        show("Could not delete: " + e.getMessage(),
                            AlertType.ERROR, connections);
                    }
                    refreshConnections();
                }
                return;
            }
        }

        if (command == save) {
            saveEditor();
            return;
        }
        if (command == back) {
            pendingProfile = null;
            refreshConnections();
            display.setCurrent(connections);
            return;
        }
        if (command == go) {
            Profile p = pendingProfile;
            pendingProfile = null;
            if (p != null) {
                start(new Profile(p.name(), p.host(), p.port(), p.user(),
                    promptPassword.getString(), false));
            }
            return;
        }

        if (command == acceptKey || command == rejectKey) {
            synchronized (promptLock) {
                promptAnswer = (command == acceptKey) ? Boolean.TRUE : Boolean.FALSE;
                promptLock.notifyAll();
            }
            display.setCurrent(canvas);
            return;
        }

        // The keyboard only exists once a session has attached one, and these
        // commands are in the menu from the moment the screen appears.
        if (command == control) {
            if (keyboard != null) {
                keyboard.toggleControl();
                canvas.repaint();
            }
            return;
        }
        if (command == escape) {
            if (keyboard != null) {
                keyboard.sendEscape();
            }
            return;
        }
        if (command == pageUp) {
            canvas.pageUp();
            return;
        }
        if (command == pageDown) {
            canvas.pageDown();
            return;
        }
        if (command == keys) {
            canvas.toggleKeyCodes();
            return;
        }
        if (command == fullScreen) {
            fullScreenOn = !fullScreenOn;
            canvas.setFullScreen(fullScreenOn);
            resizeTerminal();
            return;
        }
        if (command == reconnect) {
            shutdown();
            if (current != null) {
                start(current);
            }
            return;
        }
        if (command == disconnect) {
            shutdown();
            refreshConnections();
            display.setCurrent(connections);
        }
    }

    private void showEditor(Profile profile) {
        editingName = profile == null ? null : profile.name();
        editor = new Form(profile == null ? "New connection" : "Edit connection");

        nameField = new TextField("Name", profile == null ? "" : profile.name(),
            32, TextField.ANY);
        // URL and EMAILADDR put the device into an input mode that does not
        // capitalise the first letter. TextField.ANY does, which made every
        // host and user name start with a capital and need correcting by hand
        // on a keyboard where that is several presses.
        hostField = new TextField("Host", profile == null ? "" : profile.host(),
            64, TextField.URL | TextField.NON_PREDICTIVE);
        portField = new TextField("Port", profile == null ? "22" : "" + profile.port(),
            5, TextField.NUMERIC);
        userField = new TextField("User", profile == null ? "" : profile.user(),
            32, TextField.EMAILADDR | TextField.NON_PREDICTIVE);
        passwordField = new TextField("Password",
            profile == null ? "" : profile.password(), 64, TextField.PASSWORD);
        savePasswordChoice = new ChoiceGroup("", Choice.MULTIPLE,
            new String[] { "Save password (not encrypted)" }, null);
        savePasswordChoice.setSelectedIndex(0, profile != null && profile.savePassword());

        editor.append(nameField);
        editor.append(hostField);
        editor.append(portField);
        editor.append(userField);
        editor.append(passwordField);
        editor.append(savePasswordChoice);
        editor.addCommand(save);
        editor.addCommand(back);
        editor.setCommandListener(this);
        display.setCurrent(editor);
    }

    private void saveEditor() {
        String host = hostField.getString().trim();
        String user = userField.getString().trim();
        if (host.length() == 0 || user.length() == 0) {
            show("A host and a user are needed.", AlertType.WARNING, editor);
            return;
        }
        String name = nameField.getString().trim();
        if (name.length() == 0) {
            name = host;
        }

        Profile profile = new Profile(name, host, parsePort(portField.getString()),
            user, passwordField.getString(), savePasswordChoice.isSelected(0));
        try {
            // Renaming replaces rather than duplicating.
            if (editingName != null && !editingName.equals(name)) {
                store.delete(editingName);
            }
            store.save(profile);
        } catch (IOException e) {
            show("Could not save: " + e.getMessage(), AlertType.ERROR, editor);
            return;
        }
        refreshConnections();
        display.setCurrent(connections);
    }

    /** Connects, asking for the password first when none was saved. */
    private void begin(Profile profile) {
        if (profile.savePassword() && profile.password().length() > 0) {
            start(profile);
            return;
        }
        pendingProfile = profile;
        Form prompt = new Form(profile.user() + "@" + profile.host());
        promptPassword = new TextField("Password", "", 64, TextField.PASSWORD);
        prompt.append(promptPassword);
        prompt.addCommand(go);
        prompt.addCommand(back);
        prompt.setCommandListener(this);
        display.setCurrent(prompt);
    }

    private void start(final Profile profile) {
        current = profile;

        BitmapFont font;
        try {
            font = BitmapFont.load(FONT, CELL_WIDTH, CELL_HEIGHT);
        } catch (IOException e) {
            show("The font atlas is missing: " + e.getMessage(),
                AlertType.ERROR, connections);
            return;
        }

        canvas = new TerminalCanvas(font);
        canvas.addCommand(control);
        canvas.addCommand(escape);
        canvas.addCommand(pageUp);
        canvas.addCommand(pageDown);
        canvas.addCommand(keys);
        canvas.addCommand(fullScreen);
        canvas.addCommand(reconnect);
        canvas.addCommand(disconnect);
        // Quit belongs on this screen too. Reaching it only from the list means
        // a session that will not disconnect cleanly is one you cannot leave.
        canvas.addCommand(quit);
        canvas.setCommandListener(this);
        canvas.setStatus("connecting to " + profile.host() + "...");
        display.setCurrent(canvas);

        // Networking must not run on the event thread: on this platform the
        // first socket open can block for seconds while the radio comes up, and
        // a blocked event thread is a frozen screen.
        running = true;
        new Thread(new Runnable() {
            public void run() {
                runSession(profile);
            }
        }).start();
    }

    private void runSession(Profile profile) {
        String host = profile.host();
        int port = profile.port();
        try {
            random.seed();

            socket = openSocket(host, port);
            InputStream in = socket.openInputStream();
            OutputStream out = socket.openOutputStream();

            Connection connection = new Connection(in, out, random);
            HostKey key = connection.handshake();

            int trust = KnownHosts.check(hostKeys, host, port, key);
            if (trust == KnownHosts.CHANGED) {
                // Not a question. See KnownHosts for why there is no way past
                // this short of forgetting the host deliberately.
                fail(KnownHosts.mismatchWarning(host, port, key));
                return;
            }
            if (trust == KnownHosts.UNKNOWN) {
                // Trust on first use means the user does the trusting. Showing
                // the fingerprint and carrying on regardless is trust without
                // use: a machine in the path on this first connection would be
                // accepted silently, and its key stored — so every later
                // connection to the real server would raise a mismatch and the
                // impostor would be the one that looked legitimate.
                if (!ask("Unknown host", KnownHosts.firstContactPrompt(host, port, key))) {
                    fail("Host key rejected. Nothing was stored.");
                    return;
                }
                KnownHosts.accept(hostKeys, host, port, key);
            }

            UserAuth auth = new UserAuth(connection, profile.user());
            auth.begin();
            auth.queryMethods();
            if (!auth.password(profile.password()).succeeded()) {
                fail("Authentication failed.");
                return;
            }

            final Channel session = Channel.openSession(connection);
            channel = session;

            // The canvas has to be on screen before its size means anything:
            // setCurrent is asynchronous and full-screen mode only applies once
            // it is shown. Asking too early returns a zero height, and the
            // terminal is then told it has no rows.
            canvas.awaitShown(5000);
            int columns = canvas.columns();
            int rows = canvas.rows();
            terminal = new VT320(columns, rows) {
                public void sendData(byte[] b, int offset, int length) throws IOException {
                    session.write(b, offset, length);
                }

                public void beep() {
                }

                public void resize() {
                }
            };
            // The constructor sizes the buffer to the screen, so without this
            // there is no scrollback at all and paging up would show the screen
            // that is already there.
            terminal.setScrollbackBufferSize(SCROLLBACK_LINES);
            keyboard = new Keyboard(terminal);
            canvas.attach(terminal, keyboard);
            canvas.setStatus(profile.user() + "@" + host + "  " + columns + "x" + rows);

            session.requestPty("xterm", columns, rows);
            session.requestShell();

            byte[] buffer = new byte[4096];
            while (running) {
                int n = session.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                // The painter reads this buffer from the event thread while
                // this thread writes it. VT320 publishes a mutex for exactly
                // that, and using it is the difference between a redraw during
                // a scroll and an index off the end of an array being resized.
                synchronized (terminal.getTermBufferMutex()) {
                    terminal.putString(Utf8.decode(buffer, 0, n));
                }
                canvas.repaint();
            }
            canvas.setStatus("disconnected");
        } catch (IOException e) {
            fail(e.getMessage() == null ? e.toString() : e.getMessage());
        } finally {
            closeQuietly();
        }
    }

    /**
     * Opens a socket, trying each transport this device might mean by one.
     *
     * A plain `socket://host:port` is ambiguous on BlackBerry: the OS chooses a
     * transport, and the default is the carrier's. On a handset in this decade
     * that route is gone — BIS was switched off, and MDS needs an enterprise
     * server — so the connection has to say Wi-Fi explicitly. The suffixes are
     * URL parameters rather than an API, so they cost nothing in signing terms.
     */
    private SocketConnection openSocket(String host, int port) throws IOException {
        String address = "socket://" + host + ":" + port;
        String[] transports = {
            ";deviceside=true;interface=wifi",   // direct TCP over Wi-Fi
            ";deviceside=true",                  // direct TCP, whatever interface
            ""                                   // whatever the OS defaults to
        };

        IOException last = null;
        for (int i = 0; i < transports.length; i++) {
            try {
                canvas.setStatus("connecting" + transports[i]);
                SocketConnection open = (SocketConnection)
                    Connector.open(address + transports[i], Connector.READ_WRITE);
                canvas.setStatus("connected" + transports[i]);
                return open;
            } catch (IOException e) {
                last = e;
            }
        }
        throw new IOException("no transport reached " + host + ":" + port
            + " (last error: " + (last == null ? "none" : last.getMessage()) + ")");
    }

    /**
     * Puts a question to the user and blocks until it is answered.
     *
     * Called from the session thread, never the event thread — waiting on the
     * event thread would deadlock against the very screen being waited for.
     */
    private boolean ask(String title, String text) {
        Form prompt = new Form(title);
        prompt.append(text);
        prompt.addCommand(acceptKey);
        prompt.addCommand(rejectKey);
        prompt.setCommandListener(this);

        synchronized (promptLock) {
            promptAnswer = null;
            display.setCurrent(prompt);
            while (promptAnswer == null) {
                try {
                    promptLock.wait();
                } catch (InterruptedException e) {
                    return false;
                }
            }
            return promptAnswer.booleanValue();
        }
    }

    /**
     * Reports a fault, unless we caused it.
     *
     * Disconnecting closes the socket under a reader that is blocked on it, so
     * the read fails by design. Showing that as an error would put a warning in
     * front of a user who just chose to leave.
     */
    private void fail(final String message) {
        if (!running) {
            return;
        }
        canvas.setStatus("");
        show(message, AlertType.ERROR, connections);
    }

    private void show(String message, AlertType type, Displayable next) {
        Alert alert = new Alert("berryssh", message, null, type);
        alert.setTimeout(Alert.FOREVER);
        display.setCurrent(alert, next);
    }

    /**
     * Re-agrees the terminal size after the screen changes shape.
     *
     * Both halves are needed: the emulator has to rewrap its buffer, and the
     * server has to be told, or a full-screen program keeps drawing to the old
     * dimensions and the display tears.
     */
    private void resizeTerminal() {
        if (terminal == null || channel == null) {
            return;
        }
        int columns = canvas.columns();
        int rows = canvas.rows();
        synchronized (terminal.getTermBufferMutex()) {
            terminal.setScreenSize(columns, rows, true);
        }
        try {
            channel.windowChange(columns, rows);
        } catch (IOException e) {
            // The session is already in trouble if this fails; the read loop
            // will surface it with a better message than this could.
        }
        canvas.setStatus(columns + "x" + rows);
    }

    private static int parsePort(String text) {
        try {
            int port = Integer.parseInt(text.trim());
            return port > 0 && port < 65536 ? port : 22;
        } catch (NumberFormatException e) {
            return 22;
        }
    }

    private void shutdown() {
        running = false;
        closeQuietly();
    }

    private void closeQuietly() {
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            // Going anyway.
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            // Going anyway.
        }
        channel = null;
        socket = null;
    }
}
