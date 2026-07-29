package berryssh.device;

import java.io.IOException;

import berryssh.protocol.SshException;
import berryssh.protocol.Utf8;
import berryssh.protocol.WireReader;
import berryssh.protocol.WireWriter;

/**
 * A saved connection.
 *
 * Deliberately free of MIDP, so that the encoding — the part with rules in it —
 * can be tested on the host. {@link Store} is where the device comes in.
 *
 * Everything is UTF-8 on the way in and out. A host name or a password with a
 * Turkish letter in it is not an edge case for this user, and the device's
 * default encoding would silently mangle both.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Profile {

    /** Where profiles are kept. Implemented over RMS on the device. */
    public interface Store {
        Profile[] list() throws IOException;

        void save(Profile profile) throws IOException;

        void delete(String name) throws IOException;
    }

    /**
     * Records written before the private key and font size existed say 1.
     * Both are read, so adding fields does not throw away what is saved — a
     * connection list that empties itself on upgrade is worse than the feature
     * is worth.
     */
    private static final int FORMAT = 3;
    private static final int FORMAT_WITHOUT_WEBSOCKET = 2;
    private static final int FORMAT_WITHOUT_KEY = 1;

    /** Cell sizes the atlases exist for, and what they give on a 480x360 screen. */
    public static final int[] CELL_WIDTHS = { 8, 6, 6 };
    public static final int[] CELL_HEIGHTS = { 14, 11, 9 };
    public static final String[] SIZE_LABELS = { "8x14 (60 cols)", "6x11 (80 cols)", "6x9 (80 cols)" };

    private final String name;
    private final String host;
    private final int port;
    private final String user;
    private final String password;
    private final boolean savePassword;
    private final String privateKey;
    private final int fontSize;
    private final String webSocketPath;

    public Profile(String name, String host, int port, String user,
                   String password, boolean savePassword) {
        this(name, host, port, user, password, savePassword, "", 0, "");
    }

    public Profile(String name, String host, int port, String user, String password,
                   boolean savePassword, String privateKey, int fontSize) {
        this(name, host, port, user, password, savePassword, privateKey, fontSize, "");
    }

    public Profile(String name, String host, int port, String user, String password,
                   boolean savePassword, String privateKey, int fontSize,
                   String webSocketPath) {
        this.name = name;
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password == null ? "" : password;
        this.savePassword = savePassword;
        this.privateKey = privateKey == null ? "" : privateKey;
        this.fontSize = (fontSize < 0 || fontSize >= CELL_WIDTHS.length) ? 0 : fontSize;
        this.webSocketPath = webSocketPath == null ? "" : webSocketPath;
    }

    public String name() {
        return name;
    }

    public String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public String user() {
        return user;
    }

    /** Empty unless a password was saved. */
    public String password() {
        return password;
    }

    public boolean savePassword() {
        return savePassword;
    }

    /** An OpenSSH private key, as pasted, or empty. */
    public String privateKey() {
        return privateKey;
    }

    /** An index into {@link #CELL_WIDTHS}. */
    public int fontSize() {
        return fontSize;
    }

    public int cellWidth() {
        return CELL_WIDTHS[fontSize];
    }

    public int cellHeight() {
        return CELL_HEIGHTS[fontSize];
    }

    /**
     * The resource to upgrade to a WebSocket at, or empty for a plain socket.
     *
     * When it is set, host and port address the HTTP endpoint rather than the
     * SSH server — the bridge on the far side decides what the frames reach.
     */
    public String webSocketPath() {
        return webSocketPath;
    }

    public boolean usesWebSocket() {
        return webSocketPath.length() > 0;
    }

    public String fontResource() {
        return "/fonts/mono" + cellWidth() + "x" + cellHeight() + ".png";
    }

    /** What the connection list shows: enough to tell two servers apart. */
    public String label() {
        String where = user + "@" + host;
        if (port != 22) {
            where = where + ":" + port;
        }
        return name.length() > 0 ? name + "  (" + where + ")" : where;
    }

    /**
     * Serialises for storage.
     *
     * The password is written only when it was meant to be kept. Storing it and
     * relying on a flag to hide it would leave it on the device for anyone who
     * read the record rather than the field.
     */
    public byte[] encode() {
        WireWriter w = new WireWriter(256);
        w.writeUint32(FORMAT);
        w.writeString(Utf8.encode(name));
        w.writeString(Utf8.encode(host));
        w.writeUint32(port);
        w.writeString(Utf8.encode(user));
        w.writeBoolean(savePassword);
        w.writeString(Utf8.encode(savePassword ? password : ""));
        w.writeString(Utf8.encode(privateKey));
        w.writeUint32(fontSize);
        w.writeString(Utf8.encode(webSocketPath));
        return w.toByteArray();
    }

    public static Profile decode(byte[] record) throws IOException {
        WireReader r = new WireReader(record);
        long format = r.readUint32();
        if (format != FORMAT && format != FORMAT_WITHOUT_WEBSOCKET
                && format != FORMAT_WITHOUT_KEY) {
            // A record from a version that is not one of ours. Refusing it is
            // better than reading its fields in the wrong order.
            throw new SshException("saved connection is in format " + format
                + ", not " + FORMAT_WITHOUT_KEY + " to " + FORMAT);
        }
        String name = Utf8.decode(r.readString());
        String host = Utf8.decode(r.readString());
        int port = (int) r.readUint32();
        String user = Utf8.decode(r.readString());
        boolean savePassword = r.readBoolean();
        String password = Utf8.decode(r.readString());

        String privateKey = "";
        int fontSize = 0;
        String webSocketPath = "";
        if (format >= FORMAT_WITHOUT_WEBSOCKET) {
            privateKey = Utf8.decode(r.readString());
            fontSize = (int) r.readUint32();
        }
        if (format >= FORMAT) {
            webSocketPath = Utf8.decode(r.readString());
        }
        return new Profile(name, host, port, user, password, savePassword,
            privateKey, fontSize, webSocketPath);
    }
}
