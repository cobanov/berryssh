package berryssh.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

/**
 * The RFC 4253 transport layer: the version exchange, and the binary packet
 * protocol that frames everything above it.
 *
 * This class deliberately knows nothing about MIDP. It is driven through plain
 * java.io streams so the whole framing layer can be exercised on the host
 * against a pair of byte arrays, with no device and no server involved.
 *
 * The packets are still in the clear here. Once the key exchange has run,
 * chacha20-poly1305 replaces both the padding rules and the length field's
 * encoding, because that cipher encrypts the length separately — so this is a
 * seam the cipher work will reopen, not a finished layer.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Transport {

    public static final String SOFTWARE_VERSION = "berryssh_0.1";

    private static final String IDENTIFICATION = "SSH-2.0-" + SOFTWARE_VERSION;

    /** RFC 4253 section 4.2: the identification line including CR LF is at most 255 bytes. */
    private static final int MAX_VERSION_LINE = 255;

    /** A server may precede its identification with banner text; it may not do so forever. */
    private static final int MAX_BANNER_LINES = 1024;

    /**
     * RFC 4253 requires 35000 bytes to be accepted. The bound is generous
     * rather than tight because it exists to stop a hostile length field from
     * turning into an allocation, not to constrain a real server.
     */
    private static final int MAX_PACKET = 256 * 1024;

    /** Smallest legal packet, counting the length field itself. */
    private static final int MIN_PACKET = 16;

    private static final int LENGTH_FIELD = 4;

    private final InputStream in;
    private final OutputStream out;

    /**
     * Padding only has to be unpredictable enough to satisfy RFC 4253's SHOULD.
     * It is not key material: before the key exchange it travels in the clear
     * with nothing to hide, and afterwards the AEAD covers it. Generating a
     * private key needs a real entropy source, which this is not.
     */
    private final Random paddingSource = new Random(System.currentTimeMillis());

    /**
     * Eight until a cipher is negotiated. RFC 4253 sets the alignment to the
     * cipher's block size, or 8 for a stream cipher and for the null cipher.
     */
    private int blockSize = 8;

    /**
     * Null until NEWKEYS. The two directions are separate because NEWKEYS is
     * itself directional: our packets become encrypted when we send ours, and
     * the server's when it sends its own, and those are not the same moment.
     */
    private PacketCipher outgoing;
    private PacketCipher incoming;

    private String clientVersion;
    private String serverVersion;
    private long sendSequence;
    private long receiveSequence;

    public Transport(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    /** The client's identification line, without CR LF, as it feeds the exchange hash. */
    public String clientVersion() {
        return clientVersion;
    }

    /** The server's identification line, without CR LF, as it feeds the exchange hash. */
    public String serverVersion() {
        return serverVersion;
    }

    public long sendSequence() {
        return sendSequence;
    }

    public long receiveSequence() {
        return receiveSequence;
    }

    /** Takes effect from the next packet we send. Call it straight after sending NEWKEYS. */
    public void encryptOutgoing(PacketCipher cipher) {
        this.outgoing = cipher;
    }

    /** Takes effect from the next packet we read. Call it straight after reading NEWKEYS. */
    public void decryptIncoming(PacketCipher cipher) {
        this.incoming = cipher;
    }

    /**
     * Sends our identification line and reads the peer's.
     *
     * Both strings are kept because the key exchange hashes them: getting them
     * back by reconstruction later would risk a mismatch over CR LF or over a
     * banner line, and the hash would fail with nothing to point at.
     */
    public void exchangeVersions() throws IOException {
        clientVersion = IDENTIFICATION;
        out.write(Ascii.toBytes(clientVersion));
        out.write('\r');
        out.write('\n');
        out.flush();

        // RFC 4253 section 4.2 lets a server send any number of other lines
        // first. Everything before the SSH- line is banner text and is dropped.
        String line = null;
        for (int i = 0; i < MAX_BANNER_LINES; i++) {
            line = readLine();
            if (line.startsWith("SSH-")) {
                break;
            }
            line = null;
        }
        if (line == null) {
            throw new SshException("no identification string after " + MAX_BANNER_LINES + " lines");
        }

        // "1.99" means a server that also speaks 2.0.
        if (!line.startsWith("SSH-2.0-") && !line.startsWith("SSH-1.99-")) {
            throw new SshException("unsupported protocol version: " + line);
        }
        serverVersion = line;
    }

    /**
     * Frames a payload and writes it.
     *
     * RFC 4253 section 6: the length field, the padding-length byte, the
     * payload and the padding together come to a multiple of the block size,
     * with at least 4 bytes of padding and at least 16 bytes in total.
     */
    public void writePacket(byte[] payload) throws IOException {
        byte[] body = pad(payload);
        if (outgoing == null) {
            byte[] packet = new byte[4 + body.length];
            packet[0] = (byte) (body.length >>> 24);
            packet[1] = (byte) (body.length >>> 16);
            packet[2] = (byte) (body.length >>> 8);
            packet[3] = (byte) body.length;
            System.arraycopy(body, 0, packet, 4, body.length);
            out.write(packet, 0, packet.length);
        } else {
            byte[] sealed = outgoing.seal(sendSequence, body);
            out.write(sealed, 0, sealed.length);
        }
        out.flush();
        sendSequence = (sendSequence + 1) & 0xffffffffL;
    }

    /**
     * Builds the padding-length byte, the payload and the padding.
     *
     * The alignment rule changes once the AEAD is in play. RFC 4253 counts the
     * length field towards the block multiple; chacha20-poly1305 encrypts that
     * field separately with its own key, so it is not part of the aligned run
     * and is excluded here. Getting this wrong yields packets a server rejects
     * as corrupt with no indication that padding is what it is objecting to.
     */
    private byte[] pad(byte[] payload) {
        int aligned = 1 + payload.length + (outgoing == null ? LENGTH_FIELD : 0);
        int padLength = blockSize - (aligned % blockSize);
        if (padLength < 4) {
            padLength += blockSize;
        }
        // RFC 4253's 16-byte floor exists so a block cipher always gets a whole
        // block. It does not apply to the AEAD, and OpenSSH does not apply it
        // there either — padding to 16 anyway would put eight wasted bytes on
        // every keystroke, on a link where that is the expensive direction.
        while (outgoing == null
                && LENGTH_FIELD + 1 + payload.length + padLength < MIN_PACKET) {
            padLength += blockSize;
        }

        byte[] body = new byte[1 + payload.length + padLength];
        body[0] = (byte) padLength;
        System.arraycopy(payload, 0, body, 1, payload.length);
        fillRandom(body, 1 + payload.length, padLength);
        return body;
    }

    /** Reads one packet and returns its payload. */
    public byte[] readPacket() throws IOException {
        byte[] header = new byte[LENGTH_FIELD];
        readFully(header, 0, LENGTH_FIELD);

        long packetLength;
        if (incoming == null) {
            packetLength = ((long) (header[0] & 0xff) << 24)
                         | ((long) (header[1] & 0xff) << 16)
                         | ((long) (header[2] & 0xff) << 8)
                         | (long) (header[3] & 0xff);
        } else {
            // Decrypted, but not yet authenticated — the tag covers this field
            // and has not been checked. It is only trusted enough to decide how
            // many bytes to read, and it is bounded before anything is
            // allocated on the strength of it.
            packetLength = incoming.peekLength(receiveSequence, header);
        }

        // The floor differs with the cipher for the same reason the padding
        // does: under the AEAD the smallest legal body is one block holding the
        // padding-length byte, a message type and four bytes of padding, and a
        // real server sends exactly that for a one-byte message.
        int alignment = incoming == null ? LENGTH_FIELD : 0;
        int minimum = incoming == null ? MIN_PACKET - LENGTH_FIELD : blockSize;
        if (packetLength < minimum) {
            throw new SshException("packet of " + packetLength + " bytes is below the minimum");
        }
        if (packetLength > MAX_PACKET) {
            throw new SshException("packet of " + packetLength + " bytes is implausible");
        }
        if ((packetLength + alignment) % blockSize != 0) {
            throw new SshException("packet is not a whole number of " + blockSize + "-byte blocks");
        }

        byte[] body;
        if (incoming == null) {
            body = new byte[(int) packetLength];
            readFully(body, 0, body.length);
        } else {
            byte[] encrypted = new byte[(int) packetLength];
            readFully(encrypted, 0, encrypted.length);
            byte[] tag = new byte[PacketCipher.TAG_LENGTH];
            readFully(tag, 0, tag.length);
            body = incoming.open(receiveSequence, header, encrypted, tag);
        }

        int padLength = body[0] & 0xff;
        if (padLength < 4 || padLength > body.length - 1) {
            throw new SshException("padding of " + padLength + " bytes does not fit the packet");
        }

        byte[] payload = new byte[body.length - padLength - 1];
        System.arraycopy(body, 1, payload, 0, payload.length);
        receiveSequence = (receiveSequence + 1) & 0xffffffffL;
        return payload;
    }

    /**
     * Reads the next packet that carries something the caller should act on.
     *
     * IGNORE and DEBUG may arrive at any point, including in the middle of the
     * key exchange, and are the peer's business rather than ours. Handling them
     * here rather than at each call site means a server that sends one cannot
     * put every state machine above this out of step — which is a fault that
     * would present as an unrelated message-type error somewhere else entirely.
     *
     * DISCONNECT is turned into the exception it is. The server's own reason is
     * far more useful than the read failure that would otherwise follow.
     */
    public byte[] readMessage() throws IOException {
        for (;;) {
            byte[] payload = readPacket();
            if (payload.length == 0) {
                throw new SshException("empty packet");
            }
            int type = payload[0] & 0xff;
            if (type == Message.IGNORE || type == Message.DEBUG) {
                continue;
            }
            if (type == Message.DISCONNECT) {
                throw disconnectReason(payload);
            }
            return payload;
        }
    }

    /** Tells the peer why we are going, then leaves. RFC 4253 section 11.1. */
    public void writeDisconnect(int reasonCode, String description) throws IOException {
        WireWriter w = new WireWriter(64 + description.length());
        w.writeByte(Message.DISCONNECT);
        w.writeUint32(reasonCode);
        w.writeAsciiString(description);
        w.writeAsciiString("");
        writePacket(w.toByteArray());
    }

    private static SshException disconnectReason(byte[] payload) {
        try {
            WireReader r = new WireReader(payload);
            r.readByte();
            long code = r.readUint32();
            String description = r.readAsciiString();
            return new SshException("server disconnected (" + code + "): " + description);
        } catch (IOException e) {
            return new SshException("server disconnected, with an unreadable reason");
        }
    }

    /**
     * Reads one CR-LF-terminated line, a byte at a time.
     *
     * Reading ahead in blocks would swallow the first packet, and CLDC has no
     * BufferedInputStream to push the excess back into. The 255-byte cap counts
     * only what is kept, which is marginally more tolerant than the RFC — worth
     * it to not reject a server over its line ending.
     */
    private String readLine() throws IOException {
        byte[] line = new byte[MAX_VERSION_LINE];
        int n = 0;
        for (;;) {
            int c = in.read();
            if (c < 0) {
                throw new SshException("connection closed during the version exchange");
            }
            if (c == '\n') {
                break;
            }
            if (n == line.length) {
                throw new SshException("version line longer than " + MAX_VERSION_LINE + " bytes");
            }
            line[n++] = (byte) c;
        }
        if (n > 0 && line[n - 1] == '\r') {
            n--;
        }
        return Ascii.fromBytes(line, 0, n);
    }

    private void readFully(byte[] b, int offset, int length) throws IOException {
        while (length > 0) {
            int n = in.read(b, offset, length);
            if (n < 0) {
                throw new SshException("connection closed mid-packet");
            }
            offset += n;
            length -= n;
        }
    }

    /** CLDC's Random has no nextBytes, so the words are unpacked by hand. */
    private void fillRandom(byte[] b, int offset, int length) {
        while (length > 0) {
            int word = paddingSource.nextInt();
            int take = length < 4 ? length : 4;
            for (int i = 0; i < take; i++) {
                b[offset + i] = (byte) (word >>> (8 * i));
            }
            offset += take;
            length -= take;
        }
    }
}
