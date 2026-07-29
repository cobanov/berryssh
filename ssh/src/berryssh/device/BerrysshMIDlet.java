package berryssh.device;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.microedition.io.Connector;
import javax.microedition.io.SocketConnection;
import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.AlertType;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Form;
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
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class BerrysshMIDlet extends MIDlet implements CommandListener {

    private static final String FONT = "/fonts/BVSM8x14.png";
    private static final int CELL_WIDTH = 8;
    private static final int CELL_HEIGHT = 14;

    private final Command connect = new Command("Connect", Command.OK, 1);
    private final Command quit = new Command("Quit", Command.EXIT, 2);
    private final Command control = new Command("Ctrl", Command.SCREEN, 1);
    private final Command escape = new Command("Esc", Command.SCREEN, 2);
    private final Command keys = new Command("Keys", Command.SCREEN, 3);
    private final Command disconnect = new Command("Disconnect", Command.STOP, 4);

    private Display display;
    private Form setup;
    private TextField hostField;
    private TextField portField;
    private TextField userField;
    private TextField passwordField;

    private TerminalCanvas canvas;
    private Keyboard keyboard;
    private VT320 terminal;

    private final EntropyPool random = new EntropyPool();
    private final RecordStoreHostKeys hostKeys = new RecordStoreHostKeys();

    private SocketConnection socket;
    private Channel channel;
    private volatile boolean running;

    protected void startApp() {
        if (display != null) {
            return;
        }
        display = Display.getDisplay(this);

        // Seeding costs about a tenth of a second and needs doing before any
        // key material is asked for. Doing it here rather than at connect time
        // spends it while the user is still typing a hostname.
        new Thread(new Runnable() {
            public void run() {
                random.seed();
            }
        }).start();

        setup = new Form("berryssh");
        hostField = new TextField("Host", "", 64, TextField.URL);
        portField = new TextField("Port", "22", 5, TextField.NUMERIC);
        userField = new TextField("User", "", 32, TextField.ANY);
        passwordField = new TextField("Password", "", 64, TextField.PASSWORD);
        setup.append(hostField);
        setup.append(portField);
        setup.append(userField);
        setup.append(passwordField);
        setup.addCommand(connect);
        setup.addCommand(quit);
        setup.setCommandListener(this);
        display.setCurrent(setup);
    }

    protected void pauseApp() {
    }

    protected void destroyApp(boolean unconditional) {
        shutdown();
    }

    public void commandAction(Command command, Displayable from) {
        if (command == quit) {
            shutdown();
            notifyDestroyed();
            return;
        }
        if (command == connect) {
            startSession();
            return;
        }
        if (command == control) {
            keyboard.toggleControl();
            canvas.repaint();
            return;
        }
        if (command == escape) {
            keyboard.sendEscape();
            return;
        }
        if (command == keys) {
            canvas.toggleKeyCodes();
            return;
        }
        if (command == disconnect) {
            shutdown();
            display.setCurrent(setup);
        }
    }

    private void startSession() {
        final String host = hostField.getString().trim();
        final int port = parsePort(portField.getString());
        final String user = userField.getString().trim();
        final String password = passwordField.getString();

        if (host.length() == 0 || user.length() == 0) {
            show("A host and a user are needed.", AlertType.WARNING, setup);
            return;
        }

        BitmapFont font;
        try {
            font = BitmapFont.load(FONT, CELL_WIDTH, CELL_HEIGHT);
        } catch (IOException e) {
            show("The font atlas is missing: " + e.getMessage(), AlertType.ERROR, setup);
            return;
        }

        canvas = new TerminalCanvas(font);
        canvas.addCommand(control);
        canvas.addCommand(escape);
        canvas.addCommand(keys);
        canvas.addCommand(disconnect);
        canvas.setCommandListener(this);
        canvas.setStatus("connecting to " + host + "...");
        display.setCurrent(canvas);

        // Networking must not run on the event thread: on this platform the
        // first socket open can block for seconds while the radio comes up, and
        // a blocked event thread is a frozen screen.
        running = true;
        new Thread(new Runnable() {
            public void run() {
                runSession(host, port, user, password);
            }
        }).start();
    }

    private void runSession(String host, int port, String user, String password) {
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
                // Trust on first use. The fingerprint is shown in the form
                // ssh-keygen prints so it can actually be compared.
                canvas.setStatus(key.fingerprint());
                KnownHosts.accept(hostKeys, host, port, key);
            }

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();
            auth.queryMethods();
            if (!auth.password(password).succeeded()) {
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
            keyboard = new Keyboard(terminal);
            canvas.attach(terminal, keyboard);
            canvas.setStatus(user + "@" + host + "  " + columns + "x" + rows);

            session.requestPty("xterm", columns, rows);
            session.requestShell();

            byte[] buffer = new byte[4096];
            while (running) {
                int n = session.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                // The device's default encoding is ISO8859_1, so the decode is
                // ours to do. See Utf8.
                terminal.putString(Utf8.decode(buffer, 0, n));
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
     *
     * They are tried in order rather than assumed, because which one a given
     * OS 7 build accepts has not been established on the hardware here. The one
     * that works is reported on the status line, so the first real connection
     * also settles the question.
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

    private void fail(final String message) {
        canvas.setStatus("");
        show(message, AlertType.ERROR, setup);
    }

    private void show(String message, AlertType type, Displayable next) {
        Alert alert = new Alert("berryssh", message, null, type);
        alert.setTimeout(Alert.FOREVER);
        display.setCurrent(alert, next);
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
