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
import javax.microedition.lcdui.TextBox;
import javax.microedition.lcdui.TextField;
import javax.microedition.midlet.MIDlet;

import berryssh.crypto.EntropyPool;
import berryssh.protocol.BridgeAuth;
import berryssh.protocol.Channel;
import berryssh.protocol.Connection;
import berryssh.protocol.HostKey;
import berryssh.protocol.KnownHosts;
import berryssh.protocol.OpenSshKey;
import berryssh.protocol.Transport;
import berryssh.protocol.UserAuth;
import berryssh.protocol.Utf8;
import berryssh.protocol.WebSocket;
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

    private static final String NEW_CONNECTION = "New connection...";

    /**
     * Lines kept above the screen. The device measured ~357 MB of free heap and
     * a line is a few hundred bytes, so this is nothing — and a terminal that
     * cannot show what just scrolled past is barely a terminal on 24 rows.
     */
    private static final int SCROLLBACK_LINES = 500;

    /**
     * How long the goodbye packet gets. Long enough for a write into a socket
     * buffer, short enough that nobody notices it when the connection is
     * already dead.
     */
    private static final int GOODBYE_TIMEOUT_MS = 250;

    // The connection list
    private final Command connect = new Command("Connect", Command.ITEM, 1);
    private final Command newConnection = new Command("New", Command.SCREEN, 2);
    private final Command edit = new Command("Edit", Command.SCREEN, 3);
    private final Command delete = new Command("Delete", Command.SCREEN, 4);
    private final Command forgetKey = new Command("Forget host key", Command.SCREEN, 5);
    private final Command quit = new Command("Quit", Command.EXIT, 9);

    // The editor
    private final Command save = new Command("Save", Command.OK, 1);
    private final Command accept = new Command("OK", Command.OK, 1);
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

    private static final String[] FIELDS = {
        "Name", "Host", "Port", "User", "Password", "Save password",
        "Private key", "Terminal size", "WebSocket path", "Bridge key",
        "Bridge target"
    };

    private static final int FIELD_SAVE_PASSWORD = 5;
    private static final int FIELD_TERMINAL_SIZE = 7;
    private static final int FIELD_WEBSOCKET_PATH = 8;
    private static final int FIELD_BRIDGE_KEY = 9;
    private static final int FIELD_BRIDGE_TARGET = 10;

    private Display display;
    private ListScreen connections;
    private Profile[] profiles = new Profile[0];

    private ListScreen editor;
    private String editingName;
    private String editName = "";
    private String editHost = "";
    private String editPort = "22";
    private String editUser = "";
    private String editPassword = "";
    private boolean editSavePassword;
    private String editKey = "";
    private int editFontSize;
    private String editWsPath = "";
    private String editBridgeKey = "";
    private String editBridgeTarget = "";
    private int editingField = -1;

    private ListScreen targetPicker;
    private String[] offeredTargets = new String[0];

    /**
     * Which catalogue fetch is still wanted.
     *
     * The fetch runs on its own thread and cannot be interrupted out of a
     * socket read, so leaving the field does not stop it — it only stops it
     * mattering. Every fetch takes a number on the way in and checks it before
     * it touches the screen; anything older has been abandoned and finishes
     * quietly. Volatile because the two threads are the event thread and that
     * one.
     */
    private volatile int catalogueRequest;

    private TextBox entry;
    private Profile pendingProfile;

    private TerminalCanvas canvas;
    private Keyboard keyboard;
    private VT320 terminal;
    private Profile current;

    private final EntropyPool random = new EntropyPool();
    private final RecordStoreHostKeys hostKeys = new RecordStoreHostKeys();
    private final RecordStoreProfiles store = new RecordStoreProfiles();

    /**
     * Which session is the live one.
     *
     * Every session takes a number when it starts, and Disconnect, Reconnect
     * and Quit move the number on. A session thread that finds the number is
     * no longer its own has been abandoned: it reports nothing, touches no
     * screen, and closes only what it opened itself.
     *
     * This used to be one boolean shared by every session. Reconnect cleared
     * it and set it again before the old thread had noticed, so the old thread
     * carried on believing it was wanted — it raised its "connection closed"
     * error over the new session and, in its clean-up, closed the new
     * session's socket.
     */
    private volatile int sessionNumber;

    /**
     * What the live session has open, kept so the event thread can close it.
     * All three are set and cleared under {@link #sessionLock}, with the
     * number checked in the same breath, so an abandoned thread cannot leave
     * its own here for the next session to trip over.
     */
    private final Object sessionLock = new Object();
    private Link link;
    private Channel channel;
    private Connection connection;

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
                // What earlier runs gathered goes in first and is not counted:
                // the timing harvest still runs in full. It is there so that a
                // weak harvest on one day is backed by every day before it.
                byte[] kept = RecordStoreSeed.load();
                if (kept != null) {
                    random.addSample(kept);
                }
                random.seed();
                RecordStoreSeed.save(random.exportSeed());
            }
        }).start();

        connections = new ListScreen("berryssh", new ListScreen.Listener() {
            public void selected(int index) {
                open(index);
            }
        });
        connections.setHint("Menu for New, Edit, Delete");
        connections.addCommand(connect);
        connections.addCommand(newConnection);
        connections.addCommand(edit);
        connections.addCommand(delete);
        connections.addCommand(forgetKey);
        connections.addCommand(quit);
        connections.setCommandListener(this);
        refreshConnections();
        display.setCurrent(connections);
    }

    protected void pauseApp() {
    }

    protected void destroyApp(boolean unconditional) {
        shutdown();
        keepSeed();
    }

    /**
     * Saves the pool for the next run, now that it also holds the timing of
     * everything typed in this one.
     */
    private void keepSeed() {
        if (random.isSeeded()) {
            RecordStoreSeed.save(random.exportSeed());
        }
    }

    private void refreshConnections() {
        try {
            profiles = store.list();
        } catch (IOException e) {
            profiles = new Profile[0];
        }
        String[] names = new String[profiles.length + 1];
        String[] details = new String[profiles.length + 1];
        for (int i = 0; i < profiles.length; i++) {
            names[i] = profiles[i].name();
            details[i] = profiles[i].user() + "@" + profiles[i].host()
                + (profiles[i].port() == 22 ? "" : ":" + profiles[i].port());
        }
        names[profiles.length] = NEW_CONNECTION;
        details[profiles.length] = "add a server";
        connections.setRows(names, details);
    }

    /** A row of the connection list was chosen. */
    private void open(int index) {
        if (index >= profiles.length) {
            showEditor(null);
        } else {
            begin(profiles[index]);
        }
    }

    /** The profile the list is pointing at, or null for the New entry. */
    private Profile selected() {
        int index = connections.selectedIndex();
        if (index < 0 || index >= profiles.length) {
            return null;
        }
        return profiles[index];
    }

    public void commandAction(Command command, Displayable from) {
        if (command == quit) {
            shutdown();
            keepSeed();
            notifyDestroyed();
            return;
        }

        if (from == connections) {
            if (command == connect) {
                open(connections.selectedIndex());
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
            if (command == forgetKey) {
                // The way past a changed-key warning, and deliberately a
                // separate act from connecting: the warning refuses to offer
                // "accept anyway", so the only way on is to come here and say
                // the old key is no longer the right one.
                Profile profile = selected();
                if (profile != null) {
                    String identity = profile.hostKeyIdentity();
                    try {
                        hostKeys.forget(identity, profile.port());
                        show("Forgot the key of " + identity + ". The next connection"
                            + " will show its fingerprint and ask again.",
                            AlertType.INFO, connections);
                    } catch (IOException e) {
                        show("Could not forget it: " + e.getMessage(),
                            AlertType.ERROR, connections);
                    }
                }
                return;
            }
        }

        if (command == accept) {
            acceptField();
            return;
        }
        if (command == save) {
            saveEditor();
            return;
        }
        if (command == back) {
            // Out of a field goes back to the editor; out of anything else
            // goes back to the list.
            if (editingField >= 0) {
                editingField = -1;
                // Abandons a catalogue fetch that is still waiting on the
                // bridge. Leaving the field is the answer to it.
                catalogueRequest++;
                display.setCurrent(editor);
                return;
            }
            pendingProfile = null;
            refreshConnections();
            display.setCurrent(connections);
            return;
        }
        if (command == go) {
            Profile p = pendingProfile;
            pendingProfile = null;
            if (p != null) {
                // Every field, not just the ones the password prompt is about.
                // Dropping the WebSocket path here made a bridged connection
                // that had no saved password quietly try a plain socket to the
                // bridge instead, and fail as though the server were down.
                start(new Profile(p.name(), p.host(), p.port(), p.user(),
                    entry.getString(), false, p.privateKey(), p.fontSize(),
                    p.webSocketPath(), p.bridgeKey(), p.bridgeTarget()));
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
        // A fetch left over from the connection edited before this one is
        // answering a question about a bridge that is no longer on screen.
        catalogueRequest++;
        editingName = profile == null ? null : profile.name();
        editName = profile == null ? "" : profile.name();
        editHost = profile == null ? "" : profile.host();
        editPort = profile == null ? "22" : "" + profile.port();
        editUser = profile == null ? "" : profile.user();
        editPassword = profile == null ? "" : profile.password();
        editSavePassword = profile != null && profile.savePassword();
        editKey = profile == null ? "" : profile.privateKey();
        editFontSize = profile == null ? 0 : profile.fontSize();
        editWsPath = profile == null ? "" : profile.webSocketPath();
        editBridgeKey = profile == null ? "" : profile.bridgeKey();
        editBridgeTarget = profile == null ? "" : profile.bridgeTarget();

        if (editor == null) {
            editor = new ListScreen("Connection", new ListScreen.Listener() {
                public void selected(int index) {
                    editField(index);
                }
            });
            editor.setHint("Menu to save or go back");
            editor.addCommand(save);
            editor.addCommand(back);
            editor.addCommand(quit);
            editor.setCommandListener(this);
        }
        refreshEditor();
        display.setCurrent(editor);
    }

    private void refreshEditor() {
        String[] values = {
            editName,
            editHost,
            editPort,
            editUser,
            // Never the password itself, even hidden behind asterisks whose
            // count would give away its length.
            editPassword.length() > 0 ? "set" : "not set",
            editSavePassword ? "yes  (stored unencrypted)" : "no",
            editKey.length() > 0 ? "set" : "not set  (paste id_ed25519)",
            Profile.SIZE_LABELS[editFontSize],
            editWsPath.length() > 0 ? editWsPath : "not used  (plain socket)",
            // Shown as a state rather than a value, like the password: this one
            // is not secret from the server, but it is what stops a stranger
            // using the bridge, and a screen is a public place.
            editBridgeKey.length() > 0 ? "set" : "not set  (bridge asks for none)",
            editBridgeTarget.length() > 0 ? editBridgeTarget : "ask the bridge"
        };
        String[] names = new String[FIELDS.length];
        for (int i = 0; i < FIELDS.length; i++) {
            names[i] = FIELDS[i];
        }
        editor.setRows(names, values);
    }

    /**
     * Opens a field.
     *
     * Two are a choice rather than a value and just change. One asks the bridge
     * what it will reach, when there is enough to ask with. The rest are typed.
     */
    private void editField(int index) {
        if (index == FIELD_SAVE_PASSWORD) {
            editSavePassword = !editSavePassword;
            refreshEditor();
            return;
        }
        if (index == FIELD_TERMINAL_SIZE) {
            editFontSize = (editFontSize + 1) % Profile.SIZE_LABELS.length;
            refreshEditor();
            return;
        }
        if (index == FIELD_BRIDGE_TARGET && canAskBridge()) {
            askBridgeForTargets();
            return;
        }
        openTextBox(index);
    }

    /**
     * Hands a field to TextBox, which is the platform's own full-screen editor.
     * It knows this keyboard, its input modes and its capitalisation rules, and
     * reimplementing that on a canvas would be worse in every way that matters.
     */
    private void openTextBox(int index) {
        editingField = index;
        String value;
        int size;
        int constraints;
        switch (index) {
            case 0: value = editName; size = 32; constraints = TextField.ANY; break;
            // URL and EMAILADDR put the device into an input mode that does not
            // capitalise the first letter. ANY does, which made every host and
            // user name need correcting by hand.
            case 1: value = editHost; size = 64;
                    constraints = TextField.URL | TextField.NON_PREDICTIVE; break;
            case 2: value = editPort; size = 5; constraints = TextField.NUMERIC; break;
            case 3: value = editUser; size = 32;
                    constraints = TextField.EMAILADDR | TextField.NON_PREDICTIVE; break;
            case 4: value = editPassword; size = 64; constraints = TextField.PASSWORD; break;
            case FIELD_WEBSOCKET_PATH: value = editWsPath; size = 128;
                    constraints = TextField.URL | TextField.NON_PREDICTIVE; break;
            // Visible while it is typed, unlike the password. It is a long
            // passphrase going into a phone keyboard, and one typed blind is
            // one that gets a character wrong and cannot be found by looking.
            // NON_PREDICTIVE still matters: without it the device's dictionary
            // would learn the secret and offer it back in other applications.
            case FIELD_BRIDGE_KEY: value = editBridgeKey; size = 128;
                    constraints = TextField.ANY | TextField.NON_PREDICTIVE; break;
            case FIELD_BRIDGE_TARGET: value = editBridgeTarget; size = 64;
                    constraints = TextField.ANY | TextField.NON_PREDICTIVE; break;
            default: value = editKey; size = 2048;
                    constraints = TextField.ANY | TextField.NON_PREDICTIVE; break;
        }

        entry = new TextBox(FIELDS[index], value, size, constraints);
        entry.addCommand(accept);
        entry.addCommand(back);
        entry.setCommandListener(this);
        display.setCurrent(entry);
    }

    private boolean canAskBridge() {
        return editHost.length() > 0 && editWsPath.length() > 0
            && editBridgeKey.length() > 0;
    }

    /**
     * Fetches the bridge's catalogue and offers it as a list.
     *
     * The point of the catalogue is that nobody has to know an address: the
     * bridge names what it will reach and this shows the names. When it cannot
     * be reached the field still has to be usable, so the failure lands on a
     * text box rather than on a dead end — someone who already knows the name
     * should not be stopped by a bridge that is briefly down.
     */
    private void askBridgeForTargets() {
        final String host = editHost;
        final int port = parsePort(editPort);
        final String path = editWsPath;
        final String key = editBridgeKey;

        // Both this and the list it becomes are ways of filling in one field,
        // so Back out of either belongs in the editor rather than at the
        // connection list, which would throw away everything typed so far.
        editingField = FIELD_BRIDGE_TARGET;
        final int generation = ++catalogueRequest;

        Form waiting = new Form("Bridge");
        waiting.append("Asking " + host + " what it will reach...");
        waiting.addCommand(back);
        waiting.setCommandListener(this);
        display.setCurrent(waiting);

        // Off the event thread: opening a socket on this device can block for
        // seconds while the radio comes up, and a blocked event thread is a
        // frozen screen.
        new Thread(new Runnable() {
            public void run() {
                try {
                    String[] names = fetchTargets(host, port, path, key);
                    // Checked after the network, not before it: the seconds
                    // spent waiting are exactly when someone gives up and
                    // presses Back, and answering then would drag them to a
                    // screen they had already left.
                    if (generation != catalogueRequest) {
                        return;
                    }
                    if (names.length == 0) {
                        show("The bridge authenticated but offers no targets."
                            + " Its config has none.", AlertType.WARNING, editor);
                        return;
                    }
                    offerTargets(names);
                } catch (IOException e) {
                    if (generation != catalogueRequest) {
                        return;
                    }
                    show("Could not ask the bridge: " + e.getMessage(),
                        AlertType.WARNING, textBoxFor(FIELD_BRIDGE_TARGET));
                }
            }
        }).start();
    }

    private String[] fetchTargets(String host, int port, String path, String key)
            throws IOException {
        random.seed();
        Link probe = new Link(openSocket(host, port));
        try {
            WebSocket ws = WebSocket.connect(probe.in, probe.out,
                host + ":" + port, path, random);
            return BridgeAuth.authenticate(ws.inputStream(), ws.outputStream(), key);
        } finally {
            // Asked and answered; the session opens its own connection. Leaving
            // this one attached would hold a thread on the bridge for nothing.
            probe.close();
        }
    }

    private void offerTargets(String[] names) {
        offeredTargets = names;
        if (targetPicker == null) {
            targetPicker = new ListScreen("Bridge target", new ListScreen.Listener() {
                public void selected(int index) {
                    if (index >= 0 && index < offeredTargets.length) {
                        editBridgeTarget = offeredTargets[index];
                        editingField = -1;
                        refreshEditor();
                        display.setCurrent(editor);
                    }
                }
            });
            targetPicker.setHint("Menu to go back");
            targetPicker.addCommand(back);
            targetPicker.addCommand(quit);
            targetPicker.setCommandListener(this);
        }
        String[] details = new String[names.length];
        for (int i = 0; i < names.length; i++) {
            // The bridge deliberately does not say where a name goes, so there
            // is nothing truthful to put here but the fact that it will go.
            details[i] = "reachable through the bridge";
        }
        targetPicker.setRows(names, details);
        display.setCurrent(targetPicker);
    }

    /** The text box a field would open, without showing it. */
    private TextBox textBoxFor(int index) {
        editingField = index;
        entry = new TextBox(FIELDS[index], index == FIELD_BRIDGE_TARGET
            ? editBridgeTarget : "", 64,
            TextField.ANY | TextField.NON_PREDICTIVE);
        entry.addCommand(accept);
        entry.addCommand(back);
        entry.setCommandListener(this);
        return entry;
    }

    private void acceptField() {
        String value = entry.getString();
        switch (editingField) {
            case 0: editName = value.trim(); break;
            case 1: editHost = value.trim(); break;
            case 2: editPort = value.trim(); break;
            case 3: editUser = value.trim(); break;
            case 4: editPassword = value; break;
            case FIELD_WEBSOCKET_PATH: editWsPath = value.trim(); break;
            case FIELD_BRIDGE_KEY: editBridgeKey = value.trim(); break;
            case FIELD_BRIDGE_TARGET: editBridgeTarget = value.trim(); break;
            default: editKey = value.trim(); break;
        }
        editingField = -1;
        refreshEditor();
        display.setCurrent(editor);
    }

    private void saveEditor() {
        if (editHost.length() == 0 || editUser.length() == 0) {
            show("A host and a user are needed.", AlertType.WARNING, editor);
            return;
        }
        String name = editName.length() == 0 ? editHost : editName;

        // Checked here rather than at connect time: a key that will not parse
        // should be rejected while the person who pasted it is still looking at
        // it, not three screens later against a server.
        if (editKey.length() > 0) {
            try {
                OpenSshKey.readEd25519Seed(editKey);
            } catch (IOException e) {
                show("That key cannot be read: " + e.getMessage(),
                    AlertType.WARNING, editor);
                return;
            }
        }

        // Caught here rather than at connect time, for the same reason the key
        // is: a setting that cannot work should be refused while the person who
        // typed it is still looking at it.
        if (editBridgeKey.length() > 0 && editWsPath.length() == 0) {
            show("A bridge key needs a WebSocket path — that is how the bridge"
                + " is reached.", AlertType.WARNING, editor);
            return;
        }
        if (editBridgeKey.length() > 0 && editBridgeTarget.length() == 0) {
            show("Choose a bridge target. Open that field and it will ask the"
                + " bridge which ones it has.", AlertType.WARNING, editor);
            return;
        }
        if (editBridgeTarget.length() > 0 && !BridgeAuth.isName(editBridgeTarget)) {
            show("\"" + editBridgeTarget + "\" is not a target name: letters,"
                + " digits, dot, dash and underscore only.", AlertType.WARNING, editor);
            return;
        }

        // Saving replaces the connection of the same name, which is right when
        // that connection is the one being edited and a silent loss when it is
        // another. A name left empty becomes the host, so two logins on one
        // server collided without anyone having typed the same thing twice.
        if (!name.equals(editingName)) {
            for (int i = 0; i < profiles.length; i++) {
                if (name.equals(profiles[i].name())) {
                    show("There is already a connection called \"" + name
                        + "\". Give this one another name.", AlertType.WARNING, editor);
                    return;
                }
            }
        }

        Profile profile = new Profile(name, editHost, parsePort(editPort), editUser,
            editPassword, editSavePassword, editKey, editFontSize, editWsPath,
            editBridgeKey, editBridgeTarget);
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
        if (profile.privateKey().length() > 0
                || (profile.savePassword() && profile.password().length() > 0)) {
            start(profile);
            return;
        }
        pendingProfile = profile;
        entry = new TextBox(profile.user() + "@" + profile.host(), "", 64,
            TextField.PASSWORD);
        entry.addCommand(go);
        entry.addCommand(back);
        entry.setCommandListener(this);
        display.setCurrent(entry);
    }

    private void start(final Profile profile) {
        // Whatever was live is over. Without this a session left running
        // behind an error alert would keep its socket, with nothing left that
        // could close it.
        shutdown();
        current = profile;

        BitmapFont font;
        try {
            font = BitmapFont.load(profile.fontResource(),
                profile.cellWidth(), profile.cellHeight());
        } catch (IOException e) {
            show("The font atlas is missing: " + e.getMessage(),
                AlertType.ERROR, connections);
            return;
        }

        // The emulator and keyboard on screen belong to the session before
        // this one. Until the new session attaches its own, a key pressed here
        // must not be typed into a channel that has been closed.
        terminal = null;
        keyboard = null;

        canvas = new TerminalCanvas(font, random);
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
        final int session;
        synchronized (sessionLock) {
            session = ++sessionNumber;
        }
        new Thread(new Runnable() {
            public void run() {
                runSession(profile, session);
            }
        }).start();
    }

    private boolean isLive(int session) {
        return session == sessionNumber;
    }

    private void runSession(Profile profile, int session) {
        String host = profile.host();
        int port = profile.port();
        Link mine = null;
        try {
            random.seed();

            mine = new Link(openSocket(host, port));
            synchronized (sessionLock) {
                // Disconnect may have been chosen while the socket was still
                // opening, when there was nothing yet for it to close.
                if (!isLive(session)) {
                    return;
                }
                link = mine;
            }
            InputStream in = mine.in;
            OutputStream out = mine.out;

            // When a path is set the socket is only carrying HTTP, and what
            // SSH actually runs on is the WebSocket inside it. Connection
            // cannot tell the difference, which is the point of it taking
            // streams rather than a socket.
            if (profile.usesWebSocket()) {
                status(session, "upgrading to a WebSocket...");
                WebSocket ws = WebSocket.connect(in, out, host + ":" + port,
                    profile.webSocketPath(), random);
                in = ws.inputStream();
                out = ws.outputStream();

                // The bridge decides whether this connection goes anywhere at
                // all, and to which of its machines. Only then is there a
                // stream for SSH — which still cannot tell any of this happened.
                if (profile.authenticatesToBridge()) {
                    status(session, "authenticating to the bridge...");
                    BridgeAuth.authenticate(in, out, profile.bridgeKey());
                    status(session, "opening " + profile.bridgeTarget() + "...");
                    BridgeAuth.open(in, out, profile.bridgeTarget());
                }
            }

            Connection open = new Connection(in, out, random);
            synchronized (sessionLock) {
                if (!isLive(session)) {
                    return;
                }
                connection = open;
            }
            HostKey key = open.handshake();

            // Not the host: through a bridge that is the relay, and every
            // machine behind one would share a record. See Profile.
            String identity = profile.hostKeyIdentity();

            int trust = KnownHosts.check(hostKeys, identity, port, key);
            if (trust == KnownHosts.CHANGED) {
                // Not a question. See KnownHosts for why there is no way past
                // this short of forgetting the host deliberately.
                fail(session, KnownHosts.mismatchWarning(identity, port, key));
                return;
            }
            if (trust == KnownHosts.UNKNOWN) {
                // Trust on first use means the user does the trusting. Showing
                // the fingerprint and carrying on regardless is trust without
                // use: a machine in the path on this first connection would be
                // accepted silently, and its key stored — so every later
                // connection to the real server would raise a mismatch and the
                // impostor would be the one that looked legitimate.
                if (!ask(session, "Unknown host",
                        KnownHosts.firstContactPrompt(identity, port, key))) {
                    fail(session, "Host key rejected. Nothing was stored.");
                    return;
                }
                KnownHosts.accept(hostKeys, identity, port, key);
            }

            status(session, "authenticating...");
            UserAuth auth = new UserAuth(open, profile.user());
            auth.begin();
            UserAuth.Result outcome = auth.authenticate(
                profile.privateKey().length() > 0
                    ? OpenSshKey.readEd25519Seed(profile.privateKey()) : null,
                profile.password());
            if (!outcome.succeeded()) {
                // What the server would have taken is the useful half of a
                // refusal: "publickey" alone means no password will ever work.
                String accepted = outcome.describeMethods();
                fail(session, "Authentication failed."
                    + (accepted.length() > 0 ? " The server accepts: " + accepted + "." : ""));
                return;
            }

            // A banner is where a server says the password expires next week,
            // which environment you have landed on, or whatever notice it is
            // obliged to show before a session opens. Shown after
            // authentication rather than as it arrives, so it does not
            // interrupt a password prompt, and with the canvas as what follows
            // so the session continues behind it.
            String banner = auth.banner();
            if (banner != null && banner.trim().length() > 0 && isLive(session)) {
                show(banner.trim(), AlertType.INFO, canvas);
            }

            final Channel shell = Channel.openSession(open);
            synchronized (sessionLock) {
                if (!isLive(session)) {
                    return;
                }
                channel = shell;
            }

            // The canvas has to be on screen before its size means anything:
            // setCurrent is asynchronous and full-screen mode only applies once
            // it is shown. Asking too early returns a zero height, and the
            // terminal is then told it has no rows.
            canvas.awaitShown(5000);
            int columns = canvas.columns();
            int rows = canvas.rows();
            VT320 screen = new VT320(columns, rows) {
                public void sendData(byte[] b, int offset, int length) throws IOException {
                    shell.write(b, offset, length);
                }

                public void beep() {
                }

                public void resize() {
                }
            };
            // The constructor sizes the buffer to the screen, so without this
            // there is no scrollback at all and paging up would show the screen
            // that is already there.
            screen.setScrollbackBufferSize(SCROLLBACK_LINES);
            synchronized (sessionLock) {
                if (!isLive(session)) {
                    return;
                }
                terminal = screen;
                keyboard = new Keyboard(screen);
                canvas.attach(terminal, keyboard);
            }
            status(session, profile.user() + "@" + host + "  " + columns + "x" + rows);

            shell.requestPty("xterm", columns, rows);
            shell.requestShell();

            byte[] buffer = new byte[4096];
            // Bytes of a character whose rest has not arrived. See
            // Utf8.incompleteTail: a read ends wherever the network ended it.
            int held = 0;
            while (isLive(session)) {
                int n = shell.read(buffer, held, buffer.length - held);
                if (n < 0) {
                    break;
                }
                int have = held + n;
                held = Utf8.incompleteTail(buffer, 0, have);
                // VT320.putString takes the buffer's mutex itself, which is
                // what keeps the painter on the event thread from reading a
                // screen that is halfway through a scroll.
                screen.putString(Utf8.decode(buffer, 0, have - held));
                System.arraycopy(buffer, have - held, buffer, 0, held);
                if (isLive(session)) {
                    canvas.repaint();
                }
            }
            status(session, "disconnected");
        } catch (IOException e) {
            fail(session, e.getMessage() == null ? e.toString() : e.getMessage());
        } catch (RuntimeException e) {
            // A fault in here must not end as a thread that died without a
            // word and a terminal that simply stopped. Saying what it was is
            // also the only way it will ever get reported.
            fail(session, "berryssh failed: " + e);
        } finally {
            if (mine != null) {
                mine.close();
            }
            synchronized (sessionLock) {
                if (isLive(session)) {
                    link = null;
                    channel = null;
                    connection = null;
                }
            }
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
                status("connecting" + transports[i]);
                SocketConnection open = (SocketConnection)
                    Connector.open(address + transports[i], Connector.READ_WRITE);
                status("connected" + transports[i]);
                return open;
            } catch (IOException e) {
                last = e;
            }
        }
        throw new IOException("no transport reached " + host + ":" + port
            + " (last error: " + (last == null ? "none" : last.getMessage()) + ")");
    }

    /**
     * Says what is happening, when there is somewhere to say it.
     *
     * {@link #openSocket} is used from the editor as well as from a session,
     * and there is no terminal to write on while a connection is only being
     * asked what it will reach.
     */
    private void status(String message) {
        if (canvas != null) {
            canvas.setStatus(message);
        }
    }

    /** A session's own progress, which stops mattering once it is abandoned. */
    private void status(int session, String message) {
        if (isLive(session)) {
            canvas.setStatus(message);
        }
    }

    /**
     * Puts a question to the user and blocks until it is answered.
     *
     * Called from the session thread, never the event thread — waiting on the
     * event thread would deadlock against the very screen being waited for.
     */
    private boolean ask(int session, String title, String text) {
        Form prompt = new Form(title);
        prompt.append(text);
        prompt.addCommand(acceptKey);
        prompt.addCommand(rejectKey);
        prompt.setCommandListener(this);

        synchronized (promptLock) {
            promptAnswer = null;
            // An abandoned session has nobody to ask, and shutdown() has
            // already sent the only wake-up it was going to.
            if (!isLive(session)) {
                return false;
            }
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
     * front of a user who just chose to leave — or, after Reconnect, on top of
     * the session that replaced this one.
     */
    private void fail(int session, String message) {
        if (!isLive(session)) {
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
        VT320 screen = terminal;
        Channel shell;
        synchronized (sessionLock) {
            shell = channel;
        }
        if (screen == null || shell == null) {
            return;
        }
        int columns = canvas.columns();
        int rows = canvas.rows();
        synchronized (screen.getTermBufferMutex()) {
            screen.setScreenSize(columns, rows, true);
        }
        try {
            shell.windowChange(columns, rows);
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

    /**
     * Ends the live session, if there is one.
     *
     * Moving the number on is what tells the session thread it has been
     * abandoned; closing its socket is what gets it out of the read it is
     * blocked in to find that out.
     */
    private void shutdown() {
        Link closing;
        Channel leaving;
        Connection goodbye;
        synchronized (sessionLock) {
            sessionNumber++;
            closing = link;
            leaving = channel;
            goodbye = connection;
            link = null;
            channel = null;
            connection = null;
        }
        // A session waiting on the host key question is waiting for an answer
        // that is not coming now. Without this its thread waits for ever.
        synchronized (promptLock) {
            promptAnswer = Boolean.FALSE;
            promptLock.notifyAll();
        }
        sayGoodbye(leaving, goodbye);
        if (closing != null) {
            closing.close();
        }
    }

    /**
     * Closes the channel and sends SSH_MSG_DISCONNECT before the socket is
     * dropped, RFC 4253 section 11.1. Without it the server cannot tell a user
     * who chose to leave from a handset that fell off the network, and logs
     * the second.
     *
     * On its own thread, with a bounded wait, because this runs on the event
     * thread and neither half of a write is guaranteed to return. writePacket
     * takes the send lock, which a rekey can be holding while blocked on a
     * read, and the write itself goes to a socket that may already be gone.
     * Waiting forever on a courtesy would trade a tidy server log for an
     * application that cannot be closed.
     *
     * CLDC's Thread has join() but not join(long), so the bound comes from
     * Object.wait — with a flag, because a thread that finishes before the wait
     * begins would otherwise notify nobody and cost the full timeout.
     */
    private void sayGoodbye(final Channel leaving, final Connection open) {
        if (open == null) {
            return;
        }

        final boolean[] finished = new boolean[1];
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (leaving != null) {
                        leaving.close();
                    }
                    open.transport().writeDisconnect(
                        Transport.DISCONNECT_BY_APPLICATION, "disconnected by the user");
                } catch (Exception e) {
                    // Going anyway. A failure here means the connection was
                    // already gone, which is the case this is trying to be
                    // polite about — reporting it would be absurd.
                }
                synchronized (finished) {
                    finished[0] = true;
                    finished.notifyAll();
                }
            }
        }).start();

        synchronized (finished) {
            if (!finished[0]) {
                try {
                    finished.wait(GOODBYE_TIMEOUT_MS);
                } catch (InterruptedException e) {
                    // Then we leave without it.
                }
            }
        }
    }

    /**
     * A socket and its two streams, which only close together.
     *
     * On this platform closing a connection does not close it while a stream
     * opened from it is still open — the specification says so in as many
     * words — and only the socket was being closed. So a blocked reader was
     * not woken by Disconnect, and every look at a bridge's catalogue left a
     * connection attached to the bridge.
     */
    private static final class Link {
        final SocketConnection socket;
        final InputStream in;
        final OutputStream out;

        Link(SocketConnection socket) throws IOException {
            this.socket = socket;
            InputStream opened = null;
            try {
                opened = socket.openInputStream();
                this.in = opened;
                this.out = socket.openOutputStream();
            } catch (IOException e) {
                try {
                    if (opened != null) {
                        opened.close();
                    }
                    socket.close();
                } catch (IOException ignored) {
                    // The first failure is the one worth reporting.
                }
                throw e;
            }
        }

        /** Never throws: there is nothing to do about a close that failed. */
        void close() {
            try {
                in.close();
            } catch (IOException e) {
                // Going anyway.
            }
            try {
                out.close();
            } catch (IOException e) {
                // Going anyway.
            }
            try {
                socket.close();
            } catch (IOException e) {
                // Going anyway.
            }
        }
    }
}
