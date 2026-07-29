package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.EntropyPool;
import berryssh.crypto.SHA256;
import berryssh.crypto.X25519;

/**
 * curve25519-sha256 key exchange (RFC 8731) and the key derivation that
 * follows it (RFC 4253 section 7.2).
 *
 * The exchange hash is the load-bearing part. Both sides compute it over the
 * same eight fields — the identification strings, both KEXINIT payloads, the
 * host key, both ephemeral public keys and the shared secret — and the server
 * signs it. If our reconstruction differs from the server's by a single byte,
 * the signature does not verify and there is nothing in the failure to say
 * which field was wrong. That is why the payloads are kept verbatim from the
 * wire rather than rebuilt: see {@link KexInit}.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class KeyExchange {

    private KeyExchange() {
    }

    /**
     * The material the rest of the connection is built from.
     *
     * The shared secret is kept because rekeying derives from it, and the
     * exchange hash because the first one becomes the session identifier and is
     * then signed during user authentication.
     */
    public static final class Result {

        private final byte[] exchangeHash;
        private final byte[] sharedSecret;
        private final HostKey hostKey;

        Result(byte[] exchangeHash, byte[] sharedSecret, HostKey hostKey) {
            this.exchangeHash = exchangeHash;
            this.sharedSecret = sharedSecret;
            this.hostKey = hostKey;
        }

        public byte[] exchangeHash() {
            return exchangeHash;
        }

        public HostKey hostKey() {
            return hostKey;
        }

        /** See {@link KeyExchange#deriveKey}. */
        public byte[] deriveKey(char label, byte[] sessionId, int length) {
            return KeyExchange.deriveKey(sharedSecret, exchangeHash, label, sessionId, length);
        }
    }

    /**
     * RFC 4253 section 7.2. The label is one of 'A' to 'F': initialisation
     * vectors, encryption keys and MAC keys, client to server then server to
     * client.
     *
     * One hash is 32 bytes and chacha20-poly1305 wants 64 per direction, so the
     * extension applies: each further block hashes everything produced so far,
     * which is why the blocks cannot be computed independently of one another.
     */
    public static byte[] deriveKey(byte[] sharedSecret, byte[] exchangeHash,
                                   char label, byte[] sessionId, int length) {
        byte[] secret = mpint(sharedSecret);

        SHA256 h = new SHA256();
        h.update(secret);
        h.update(exchangeHash);
        h.update(new byte[] { (byte) label });
        h.update(sessionId);
        byte[] block = h.digest();

        byte[] key = new byte[length];
        int filled = copy(block, key, 0);
        while (filled < length) {
            h = new SHA256();
            h.update(secret);
            h.update(exchangeHash);
            h.update(key, 0, filled);
            block = h.digest();
            filled += copy(block, key, filled);
        }
        return key;
    }

    private static int copy(byte[] block, byte[] key, int at) {
        int take = key.length - at;
        if (take > block.length) {
            take = block.length;
        }
        System.arraycopy(block, 0, key, at, take);
        return take;
    }

    /**
     * Runs the exchange over an established transport, after KEXINIT has been
     * traded in both directions.
     *
     * On return the server has proved it holds the private half of the host key
     * it presented. Whether that key is the right one is a separate question,
     * and the caller must still ask it.
     */
    public static Result run(Transport transport, KexInit client, KexInit server,
                             EntropyPool random) throws IOException {
        byte[] privateKey = random.nextBytes(X25519.KEY_LENGTH);
        X25519.clamp(privateKey);
        byte[] clientPublic = X25519.scalarMultBase(privateKey);

        WireWriter init = new WireWriter(64);
        init.writeByte(Message.KEX_ECDH_INIT);
        init.writeString(clientPublic);
        transport.writePacket(init.toByteArray());

        byte[] payload = transport.readMessage();
        WireReader r = new WireReader(payload);
        int type = r.readByte();
        if (type != Message.KEX_ECDH_REPLY) {
            throw new SshException("expected KEX_ECDH_REPLY, got " + Message.name(type));
        }
        byte[] hostKeyBlob = r.readString();
        byte[] serverPublic = r.readString();
        byte[] signature = r.readString();

        if (serverPublic.length != X25519.KEY_LENGTH) {
            throw new SshException("server ephemeral key is "
                + serverPublic.length + " bytes, not 32");
        }

        byte[] shared = X25519.scalarMult(privateKey, serverPublic);
        // RFC 7748 section 6.1: an all-zero result means the peer sent a
        // low-order point, which forces the shared secret regardless of our
        // private key. It is an attack, not an unlucky exchange.
        if (X25519.isAllZero(shared)) {
            throw new SshException("server sent a low-order point; the shared secret would be forced");
        }

        HostKey hostKey = HostKey.parse(hostKeyBlob);

        byte[] exchangeHash = exchangeHash(
            transport.clientVersion(), transport.serverVersion(),
            client.payload(), server.payload(),
            hostKeyBlob, clientPublic, serverPublic, shared);

        if (!hostKey.verify(exchangeHash, signature)) {
            throw new SshException("the server's signature over the exchange hash does not verify");
        }

        return new Result(exchangeHash, shared, hostKey);
    }

    /** RFC 8731 section 3. The field order is the agreement; nothing here is arbitrary. */
    public static byte[] exchangeHash(String clientVersion, String serverVersion,
                                      byte[] clientKexInit, byte[] serverKexInit,
                                      byte[] hostKeyBlob, byte[] clientPublic,
                                      byte[] serverPublic, byte[] sharedSecret) {
        WireWriter w = new WireWriter(1024);
        w.writeAsciiString(clientVersion);
        w.writeAsciiString(serverVersion);
        w.writeString(clientKexInit);
        w.writeString(serverKexInit);
        w.writeString(hostKeyBlob);
        w.writeString(clientPublic);
        w.writeString(serverPublic);
        w.writeMpint(sharedSecret);
        return SHA256.hash(w.toByteArray());
    }

    /**
     * The shared secret as it appears inside a hash: an mpint, not 32 raw
     * bytes. A secret whose leading byte happens to be below 0x80 encodes
     * shorter, and one at or above it gains a zero byte — so roughly half of
     * all exchanges would fail if this were treated as fixed-width.
     */
    private static byte[] mpint(byte[] magnitude) {
        WireWriter w = new WireWriter(magnitude.length + 8);
        w.writeMpint(magnitude);
        return w.toByteArray();
    }
}
