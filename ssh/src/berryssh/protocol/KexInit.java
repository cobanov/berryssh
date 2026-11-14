package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.EntropyPool;

/**
 * SSH_MSG_KEXINIT, in both directions (RFC 4253 section 7.1).
 *
 * The whole payload is kept rather than just the parsed lists, because both
 * sides' KEXINIT payloads go into the exchange hash byte for byte. Rebuilding
 * one later to hash it would risk re-encoding it differently from what went on
 * the wire, and the failure would show up as a signature that does not verify,
 * with nothing to point at.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class KexInit {

    /**
     * Not algorithms. Each side lists its own marker among the key exchange
     * names to say it implements strict key exchange, and the rule is in force
     * when both have. They cannot be negotiated as a method by accident: the
     * two names differ, so neither list ever contains the other's.
     */
    public static final String STRICT_CLIENT = "kex-strict-c-v00@openssh.com";
    public static final String STRICT_SERVER = "kex-strict-s-v00@openssh.com";

    /**
     * What we offer. Each list is in preference order, and the order is the
     * negotiation: the first entry that the server also names wins.
     *
     * The two curve25519 names are the same algorithm. The @libssh.org one is
     * what the method was called before RFC 8731 standardised it, and servers
     * of the target era answer to that name only.
     */
    public static final String[] KEX_ALGORITHMS = {
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        STRICT_CLIENT
    };

    public static final String[] HOST_KEY_ALGORITHMS = {
        "ssh-ed25519"
    };

    public static final String[] CIPHERS = {
        "chacha20-poly1305@openssh.com"
    };

    /**
     * The MAC lists are sent because RFC 4253 requires the fields, and are then
     * unused: chacha20-poly1305 is an AEAD, so it authenticates the packet
     * itself and RFC 4253's separate MAC does not apply. A name is offered
     * anyway so the negotiation is well defined in every category rather than
     * relying on the server to skip one — and since the only cipher offered is
     * the AEAD, a MAC can never actually come into play. {@link Negotiation}
     * asserts that.
     */
    public static final String[] MACS = {
        "hmac-sha2-256"
    };

    public static final String[] COMPRESSION = {
        "none"
    };

    private static final String[] NO_LANGUAGES = {};

    private static final int COOKIE_LENGTH = 16;

    private final byte[] payload;

    private final String[] kexAlgorithms;
    private final String[] hostKeyAlgorithms;
    private final String[] ciphersClientToServer;
    private final String[] ciphersServerToClient;
    private final String[] compressionClientToServer;
    private final String[] compressionServerToClient;
    private final boolean firstKexPacketFollows;

    private KexInit(byte[] payload, String[] kexAlgorithms, String[] hostKeyAlgorithms,
                    String[] ciphersClientToServer, String[] ciphersServerToClient,
                    String[] compressionClientToServer, String[] compressionServerToClient,
                    boolean firstKexPacketFollows) {
        this.payload = payload;
        this.kexAlgorithms = kexAlgorithms;
        this.hostKeyAlgorithms = hostKeyAlgorithms;
        this.ciphersClientToServer = ciphersClientToServer;
        this.ciphersServerToClient = ciphersServerToClient;
        this.compressionClientToServer = compressionClientToServer;
        this.compressionServerToClient = compressionServerToClient;
        this.firstKexPacketFollows = firstKexPacketFollows;
    }

    /** Builds ours. The cookie is what stops either side alone from steering the exchange hash. */
    public static KexInit client(EntropyPool random) {
        return clientWithCookie(random.nextBytes(COOKIE_LENGTH));
    }

    /**
     * Builds ours with a caller-supplied cookie, so a test can pin the exact
     * bytes. Named awkwardly because that is the only good reason to call it:
     * a predictable cookie lets either side steer the exchange hash.
     */
    public static KexInit clientWithCookie(byte[] cookie) {
        WireWriter w = new WireWriter(512);
        w.writeByte(Message.KEXINIT);
        w.writeRaw(cookie, 0, COOKIE_LENGTH);
        w.writeNameList(KEX_ALGORITHMS);
        w.writeNameList(HOST_KEY_ALGORITHMS);
        w.writeNameList(CIPHERS);
        w.writeNameList(CIPHERS);
        w.writeNameList(MACS);
        w.writeNameList(MACS);
        w.writeNameList(COMPRESSION);
        w.writeNameList(COMPRESSION);
        w.writeNameList(NO_LANGUAGES);
        w.writeNameList(NO_LANGUAGES);
        w.writeBoolean(false);
        w.writeUint32(0);

        return new KexInit(w.toByteArray(),
            KEX_ALGORITHMS, HOST_KEY_ALGORITHMS, CIPHERS, CIPHERS,
            COMPRESSION, COMPRESSION, false);
    }

    public static KexInit parse(byte[] payload) throws IOException {
        WireReader r = new WireReader(payload);
        int type = r.readByte();
        if (type != Message.KEXINIT) {
            throw new SshException("expected KEXINIT, got " + Message.name(type));
        }
        r.readRaw(COOKIE_LENGTH);

        String[] kex = r.readNameList();
        String[] hostKey = r.readNameList();
        String[] cipherCtoS = r.readNameList();
        String[] cipherStoC = r.readNameList();
        // The MAC lists. An AEAD cipher carries its own tag, so they are read
        // past and never consulted — see MACS.
        r.readNameList();
        r.readNameList();
        String[] compCtoS = r.readNameList();
        String[] compStoC = r.readNameList();
        r.readNameList();
        r.readNameList();
        boolean guessing = r.readBoolean();
        r.readUint32();

        return new KexInit(payload, kex, hostKey, cipherCtoS, cipherStoC,
            compCtoS, compStoC, guessing);
    }

    /** The payload exactly as it went on the wire, for the exchange hash. */
    public byte[] payload() {
        return payload;
    }

    public String[] kexAlgorithms() {
        return kexAlgorithms;
    }

    public String[] hostKeyAlgorithms() {
        return hostKeyAlgorithms;
    }

    public String[] ciphersClientToServer() {
        return ciphersClientToServer;
    }

    public String[] ciphersServerToClient() {
        return ciphersServerToClient;
    }

    public String[] compressionClientToServer() {
        return compressionClientToServer;
    }

    public String[] compressionServerToClient() {
        return compressionServerToClient;
    }

    public boolean firstKexPacketFollows() {
        return firstKexPacketFollows;
    }

    /** Whether the server's KEXINIT asks for strict key exchange. */
    public boolean offersStrictKex() {
        for (int i = 0; i < kexAlgorithms.length; i++) {
            if (STRICT_SERVER.equals(kexAlgorithms[i])) {
                return true;
            }
        }
        return false;
    }
}
