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

    private static final int FORMAT = 1;

    private final String name;
    private final String host;
    private final int port;
    private final String user;
    private final String password;
    private final boolean savePassword;

    public Profile(String name, String host, int port, String user,
                   String password, boolean savePassword) {
        this.name = name;
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password == null ? "" : password;
        this.savePassword = savePassword;
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
        return w.toByteArray();
    }

    public static Profile decode(byte[] record) throws IOException {
        WireReader r = new WireReader(record);
        long format = r.readUint32();
        if (format != FORMAT) {
            // A record written by a version that is not this one. Refusing it
            // is better than reading its fields in the wrong order.
            throw new SshException("saved connection is in format " + format
                + ", not " + FORMAT);
        }
        String name = Utf8.decode(r.readString());
        String host = Utf8.decode(r.readString());
        int port = (int) r.readUint32();
        String user = Utf8.decode(r.readString());
        boolean savePassword = r.readBoolean();
        String password = Utf8.decode(r.readString());
        return new Profile(name, host, port, user, password, savePassword);
    }
}
