package berryssh.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import berryssh.crypto.Hmac;

/**
 * Proves knowledge of a shared key to a WebSocket bridge, and asks it which
 * machines it will connect to.
 *
 * A bridge that dialled on request would be a port forward into someone's
 * network for anyone who found the URL. {@link WebSocket} gets the stream
 * there; this decides whether the stream is allowed to go anywhere, and where.
 *
 * <pre>
 *   S-&gt;C   BERRYSSH1 &lt;base64 nonce&gt;
 *   C-&gt;S   AUTH &lt;base64 HMAC-SHA256(key, LABEL || nonce)&gt;
 *   S-&gt;C   OK &lt;name&gt; &lt;name&gt; ...
 *   C-&gt;S   OPEN &lt;name&gt;
 *   S-&gt;C   READY
 *          ... the SSH stream, both directions, from here ...
 * </pre>
 *
 * Three things about that exchange are deliberate:
 *
 * <ul>
 * <li><b>The catalogue comes back with the OK.</b> Nobody has to know an
 * address, let alone type one into a handset: the bridge names what it will
 * reach and the phone offers the names. Without the key there is no
 * catalogue.</li>
 * <li><b>The destination is named after authenticating, not in the URL.</b>
 * One endpoint, nothing to enumerate by guessing paths.</li>
 * <li><b>The nonce is fresh per connection</b>, so a tag captured off the wire
 * cannot be replayed, and the key itself never crosses it.</li>
 * </ul>
 *
 * What this is not: encryption. The line protocol is plaintext and so is the
 * name of the machine being reached. SSH inside it is what keeps the session
 * private, and the host key check is what makes an untrusted bridge tolerable.
 *
 * Free of MIDP so the host tests can drive both ends. Written for -source 1.3:
 * no generics, no enhanced for, no StringBuilder.
 */
public final class BridgeAuth {

    /**
     * Mixed into the signed message so a tag cannot be lifted out of here and
     * replayed at something else that signs a nonce with the same key.
     */
    public static final String LABEL = "berryssh-bridge-v1";

    public static final String GREETING = "BERRYSSH1";

    /** Long enough that a line is a protocol error rather than a memory one. */
    private static final int MAX_LINE = 4096;

    private BridgeAuth() {
    }

    /**
     * Answers the bridge's challenge and returns the names it will connect to.
     *
     * @param key the shared secret, as typed; any length, since it is a
     *            passphrase rather than something generated to fit
     */
    public static String[] authenticate(InputStream in, OutputStream out, String key)
            throws IOException {
        String greeting = readLine(in);
        if (!greeting.startsWith(GREETING + " ")) {
            // Most likely an ordinary WebSocket-to-TCP proxy, which starts
            // piping immediately and has no idea it was asked a question. Say
            // so, because the fix is to clear the bridge key rather than to
            // correct it.
            throw new SshException("this is not an authenticating bridge"
                + " (it opened with \"" + summarise(greeting) + "\")");
        }

        byte[] nonce = Base64.decode(greeting.substring(GREETING.length() + 1).trim());
        if (nonce.length < 16) {
            throw new SshException("the bridge sent a " + nonce.length + " byte challenge");
        }

        byte[] label = Ascii.toBytes(LABEL);
        byte[] message = new byte[label.length + nonce.length];
        System.arraycopy(label, 0, message, 0, label.length);
        System.arraycopy(nonce, 0, message, label.length, nonce.length);

        byte[] tag = Hmac.compute(Utf8.encode(key), message);
        writeLine(out, "AUTH " + Base64.encode(tag));

        String reply = readLine(in);
        if (!reply.equals("OK") && !reply.startsWith("OK ")) {
            throw new SshException(explain(reply, "the bridge refused the key"));
        }
        return words(reply.length() > 2 ? reply.substring(3) : "");
    }

    /**
     * Asks for one of the names {@link #authenticate} returned. On return the
     * streams carry the far side's bytes and nothing else.
     */
    public static void open(InputStream in, OutputStream out, String target)
            throws IOException {
        if (!isName(target)) {
            // Refused here rather than sent: a name with a space in it would
            // arrive as two words and open something that was never asked for.
            throw new SshException("\"" + target + "\" is not a usable target name");
        }
        writeLine(out, "OPEN " + target);

        String reply = readLine(in);
        if (!reply.equals("READY")) {
            throw new SshException(explain(reply, "the bridge would not open " + target));
        }
    }

    /**
     * The names a bridge may use: what survives an ASCII line protocol without
     * needing quoting, and what someone can retype from a phone.
     */
    public static boolean isName(String name) {
        if (name == null || name.length() == 0 || name.length() > 64) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** Splits on runs of spaces, dropping empties. */
    static String[] words(String line) {
        Vector found = new Vector();
        int at = 0;
        while (at < line.length()) {
            while (at < line.length() && line.charAt(at) == ' ') {
                at++;
            }
            int start = at;
            while (at < line.length() && line.charAt(at) != ' ') {
                at++;
            }
            if (at > start) {
                found.addElement(line.substring(start, at));
            }
        }
        String[] result = new String[found.size()];
        found.copyInto(result);
        return result;
    }

    /**
     * Reads one line. Unbuffered, and it matters here more than anywhere: after
     * READY the very next byte belongs to SSH, and a reader that had pulled
     * ahead would have eaten the start of the server's version string. See
     * {@link Lines}.
     */
    private static String readLine(InputStream in) throws IOException {
        return Lines.read(in, MAX_LINE, "bridge");
    }

    private static void writeLine(OutputStream out, String line) throws IOException {
        out.write(Ascii.toBytes(line + "\r\n"));
        out.flush();
    }

    /** Carries the bridge's own words through when it sent any. */
    private static String explain(String reply, String fallback) {
        if (reply.startsWith("ERR ")) {
            return fallback + ": " + summarise(reply.substring(4));
        }
        return fallback;
    }

    /** Keeps a hostile or confused far side from filling the screen. */
    private static String summarise(String text) {
        String trimmed = text.trim();
        if (trimmed.length() > 80) {
            trimmed = trimmed.substring(0, 80) + "...";
        }
        StringBuffer safe = new StringBuffer(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            safe.append(c < 0x20 || c > 0x7e ? '?' : c);
        }
        return safe.toString();
    }
}
