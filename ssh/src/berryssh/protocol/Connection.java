package berryssh.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import berryssh.crypto.EntropyPool;

/**
 * An SSH connection, from the version exchange through to an encrypted channel.
 *
 * Deliberately built on java.io streams rather than anything from MIDP, so the
 * whole protocol stack runs unchanged on the host against a socket and on the
 * device against `Connector.open("socket://host:port")`. That is what lets the
 * handshake be tested against a real OpenSSH server without a device in the
 * loop.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Connection implements Transport.RekeyHandler {

    private final Transport transport;
    private final EntropyPool random;

    private byte[] sessionId;
    private HostKey hostKey;

    public Connection(InputStream in, OutputStream out, EntropyPool random) {
        this.transport = new Transport(in, out);
        this.random = random;
    }

    public Transport transport() {
        return transport;
    }

    /**
     * The exchange hash of the first key exchange. It never changes afterwards,
     * even across a rekey, which is what makes it usable as the thing a user
     * authentication signature is bound to.
     */
    public byte[] sessionId() {
        return sessionId;
    }

    public HostKey hostKey() {
        return hostKey;
    }

    /**
     * Runs the handshake to the point where both directions are encrypted.
     *
     * The host key is returned rather than trusted. The signature check inside
     * the key exchange proves the server holds the private half of the key it
     * presented; it says nothing about whether that is the server the user
     * meant to reach. The caller has to answer that separately, and until it
     * does, this connection is protected against a passive eavesdropper only.
     */
    public HostKey handshake() throws IOException {
        transport.exchangeVersions();

        KexInit ours = KexInit.client(random);
        transport.writePacket(ours.payload());
        KexInit theirs = KexInit.parse(expect(transport.readMessage(), Message.KEXINIT));

        Negotiation negotiated = Negotiation.between(ours, theirs);
        if (negotiated.discardGuessedPacket()) {
            // The server guessed the key exchange wrongly. Its next packet is
            // void, and reading past it would leave everything after one
            // message out of step.
            transport.readMessage();
        }

        KeyExchange.Result result = KeyExchange.run(transport, ours, theirs, random);
        hostKey = result.hostKey();
        sessionId = result.exchangeHash();

        // NEWKEYS is directional and the two halves are not simultaneous: our
        // packets become encrypted after we send ours, the server's after it
        // sends its own. Enabling either early reads or writes a packet with a
        // cipher the far end is not using yet.
        WireWriter newKeys = new WireWriter(8);
        newKeys.writeByte(Message.NEWKEYS);
        transport.writePacket(newKeys.toByteArray());
        transport.encryptOutgoing(new PacketCipher(
            result.deriveKey('C', sessionId, PacketCipher.KEY_LENGTH)));

        expect(transport.readMessage(), Message.NEWKEYS);
        transport.decryptIncoming(new PacketCipher(
            result.deriveKey('D', sessionId, PacketCipher.KEY_LENGTH)));

        // Only now. Registered any earlier — in the constructor, as it was —
        // the server's opening KEXINIT is itself mistaken for a rekey request
        // and the initial handshake never completes.
        transport.setRekeyHandler(this);

        return hostKey;
    }

    /**
     * Runs the key exchange again, at the server's request.
     *
     * The session identifier deliberately does not change. RFC 4253 fixes it to
     * the first exchange hash for the life of the connection, and it is what
     * the user authentication signature was bound to — replacing it would
     * retroactively invalidate the thing that proved who we are.
     *
     * The send lock is held throughout. Between our NEWKEYS and the server's,
     * the two directions are on different keys, and a keystroke that slipped
     * out in the middle would be encrypted under keys the server had already
     * retired.
     */
    public void rekey(byte[] serverKexInit) throws IOException {
        synchronized (transport.sendLock()) {
            KexInit ours = KexInit.client(random);
            transport.writePacket(ours.payload());
            KexInit theirs = KexInit.parse(serverKexInit);

            Negotiation negotiated = Negotiation.between(ours, theirs);
            if (negotiated.discardGuessedPacket()) {
                transport.readMessage();
            }

            KeyExchange.Result result = KeyExchange.run(transport, ours, theirs, random);

            // The host key must still be the one already trusted. A server that
            // presents a different one mid-session is not the server we
            // authenticated to.
            if (!sameBytes(hostKey.blob(), result.hostKey().blob())) {
                throw new SshException("the host key changed during a rekey");
            }

            WireWriter newKeys = new WireWriter(8);
            newKeys.writeByte(Message.NEWKEYS);
            transport.writePacket(newKeys.toByteArray());
            transport.encryptOutgoing(new PacketCipher(
                result.deriveKey('C', sessionId, PacketCipher.KEY_LENGTH)));

            expect(transport.readMessage(), Message.NEWKEYS);
            transport.decryptIncoming(new PacketCipher(
                result.deriveKey('D', sessionId, PacketCipher.KEY_LENGTH)));
        }
    }

    private static boolean sameBytes(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Asks the server to start a service, and waits for it to agree.
     * RFC 4253 section 10.
     */
    public void requestService(String service) throws IOException {
        WireWriter w = new WireWriter(32);
        w.writeByte(Message.SERVICE_REQUEST);
        w.writeAsciiString(service);
        transport.writePacket(w.toByteArray());

        byte[] reply = expect(transport.readMessage(), Message.SERVICE_ACCEPT);
        WireReader r = new WireReader(reply);
        r.readByte();
        String accepted = r.readAsciiString();
        if (!service.equals(accepted)) {
            throw new SshException("asked for service " + service + ", got " + accepted);
        }
    }

    static byte[] expect(byte[] payload, int type) throws IOException {
        int actual = payload[0] & 0xff;
        if (actual != type) {
            throw new SshException("expected " + Message.name(type)
                + ", got " + Message.name(actual));
        }
        return payload;
    }
}
