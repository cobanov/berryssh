package berryssh.protocol;

import java.io.IOException;

/**
 * The outcome of RFC 4253 section 7.1 algorithm negotiation.
 *
 * The rule is one-sided on purpose: the client's list is walked in order and
 * the first name the server also offers wins, so preference is entirely ours
 * and a server cannot talk us down to something we like less by ordering its
 * own list cleverly.
 *
 * Every comparison is String.equals, which is code-point equality. A
 * case-insensitive match would be a bug on the target device, where the locale
 * is Turkish — see {@link Ascii}.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Negotiation {

    private static final String AEAD_CIPHER = "chacha20-poly1305@openssh.com";

    private final String kex;
    private final String hostKey;
    private final String cipherClientToServer;
    private final String cipherServerToClient;
    private final String compressionClientToServer;
    private final String compressionServerToClient;
    private final boolean discardGuessedPacket;

    private Negotiation(String kex, String hostKey,
                        String cipherClientToServer, String cipherServerToClient,
                        String compressionClientToServer, String compressionServerToClient,
                        boolean discardGuessedPacket) {
        this.kex = kex;
        this.hostKey = hostKey;
        this.cipherClientToServer = cipherClientToServer;
        this.cipherServerToClient = cipherServerToClient;
        this.compressionClientToServer = compressionClientToServer;
        this.compressionServerToClient = compressionServerToClient;
        this.discardGuessedPacket = discardGuessedPacket;
    }

    public static Negotiation between(KexInit client, KexInit server) throws IOException {
        String kex = choose("key exchange", client.kexAlgorithms(), server.kexAlgorithms());
        String hostKey = choose("host key", client.hostKeyAlgorithms(), server.hostKeyAlgorithms());
        String cipherOut = choose("cipher client to server",
            client.ciphersClientToServer(), server.ciphersClientToServer());
        String cipherIn = choose("cipher server to client",
            client.ciphersServerToClient(), server.ciphersServerToClient());
        String compressOut = choose("compression client to server",
            client.compressionClientToServer(), server.compressionClientToServer());
        String compressIn = choose("compression server to client",
            client.compressionServerToClient(), server.compressionServerToClient());

        // The MAC lists are negotiated by the RFC but cannot matter here: the
        // only cipher offered is an AEAD, which carries its own tag. If this
        // ever fails, a non-AEAD cipher reached the offer list and the packet
        // layer would silently stop authenticating anything.
        if (!AEAD_CIPHER.equals(cipherOut) || !AEAD_CIPHER.equals(cipherIn)) {
            throw new SshException("negotiated a cipher with no AEAD: "
                + cipherOut + " / " + cipherIn);
        }

        // RFC 4253 section 7.1: a guessed first packet that turns out not to
        // match the negotiated algorithms has to be read and thrown away, or
        // every packet after it is interpreted one message out of step.
        boolean discard = server.firstKexPacketFollows()
            && (server.kexAlgorithms().length == 0
                || server.hostKeyAlgorithms().length == 0
                || !server.kexAlgorithms()[0].equals(kex)
                || !server.hostKeyAlgorithms()[0].equals(hostKey));

        return new Negotiation(kex, hostKey, cipherOut, cipherIn,
            compressOut, compressIn, discard);
    }

    private static String choose(String category, String[] ours, String[] theirs)
            throws IOException {
        for (int i = 0; i < ours.length; i++) {
            for (int j = 0; j < theirs.length; j++) {
                if (ours[i].equals(theirs[j])) {
                    return ours[i];
                }
            }
        }
        throw new SshException("no " + category + " in common; we offer "
            + join(ours) + ", the server offers " + join(theirs));
    }

    private static String join(String[] names) {
        if (names.length == 0) {
            return "(nothing)";
        }
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < names.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(names[i]);
        }
        return sb.toString();
    }

    public String kex() {
        return kex;
    }

    public String hostKey() {
        return hostKey;
    }

    public String cipherClientToServer() {
        return cipherClientToServer;
    }

    public String cipherServerToClient() {
        return cipherServerToClient;
    }

    public String compressionClientToServer() {
        return compressionClientToServer;
    }

    public String compressionServerToClient() {
        return compressionServerToClient;
    }

    /** True when the server guessed the key exchange wrongly and its next packet is void. */
    public boolean discardGuessedPacket() {
        return discardGuessedPacket;
    }
}
