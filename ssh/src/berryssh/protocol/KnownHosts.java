package berryssh.protocol;

import java.io.IOException;

/**
 * Whether the host key we were shown is the one we saw last time.
 *
 * Verifying the signature (see {@link KeyExchange}) proves the server holds the
 * private half of the key it presented. It says nothing at all about whether
 * that server is the one the user meant to reach — anyone in the path can
 * present a key they hold. This is the half that answers that, and without it
 * the handshake protects against a passive eavesdropper only.
 *
 * The policy lives here and the storage lives behind {@link Store}, because RMS
 * exists only on the device: splitting them means the decision that matters can
 * be tested on the host, where getting it wrong is cheap to find.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class KnownHosts {

    /** No key on record for this host: the user has to be asked. */
    public static final int UNKNOWN = 0;

    /** The key matches what was stored. Carry on. */
    public static final int MATCHED = 1;

    /** A different key. Refuse; do not offer to continue. */
    public static final int CHANGED = 2;

    /** Where host keys are kept. Implemented over RMS on the device. */
    public interface Store {
        /** The stored key blob for this host, or null. */
        byte[] lookup(String host, int port) throws IOException;

        void store(String host, int port, byte[] blob) throws IOException;
    }

    private KnownHosts() {
    }

    public static int check(Store store, String host, int port, HostKey key) throws IOException {
        byte[] known = store.lookup(host, port);
        if (known == null) {
            return UNKNOWN;
        }
        return equalBytes(known, key.blob()) ? MATCHED : CHANGED;
    }

    /** Records a key the user accepted. */
    public static void accept(Store store, String host, int port, HostKey key) throws IOException {
        store.store(host, port, key.blob());
    }

    /**
     * What to show a user who has never seen this host.
     *
     * The fingerprint is the SHA-256 base64 form, which is exactly what
     * `ssh-keygen -lf` prints on the server — a fingerprint in a format nothing
     * else produces is one nobody can actually check against anything.
     */
    public static String firstContactPrompt(String host, int port, HostKey key) {
        return "The authenticity of " + host + ":" + port + " cannot be established.\n"
            + "ED25519 key fingerprint is " + key.fingerprint() + ".\n"
            + "Compare it against `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`"
            + " on the server before accepting.";
    }

    /**
     * What to show when the key has changed.
     *
     * Deliberately not a question. A mismatch is either an attack or an
     * administrative change the user knows about, and in both cases the right
     * move is to stop and go and find out — an "accept anyway" button turns the
     * one moment this check exists for into a button press.
     */
    public static String mismatchWarning(String host, int port, HostKey key) {
        return "THE HOST KEY FOR " + host + ":" + port + " HAS CHANGED.\n"
            + "It is now " + key.fingerprint() + ".\n"
            + "Someone may be intercepting this connection. If the server was"
            + " genuinely rebuilt, remove the stored key and connect again.";
    }

    private static boolean equalBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
}
