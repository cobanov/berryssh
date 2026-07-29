package berryssh.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import berryssh.crypto.EntropyPool;

/**
 * An RFC 6455 client, so SSH can cross a network whose only entrance speaks
 * HTTP.
 *
 * The handset cannot run a VPN and there is no raw TCP route into the network
 * behind Cloudflare — but a WebSocket is a TCP stream wearing an HTTP
 * handshake, and a bridge on the far side turns it back into a socket. What
 * comes out of here is an InputStream and an OutputStream, which is all
 * {@link Connection} ever wanted, so nothing above this changes.
 *
 * <b>Plain ws://, deliberately.</b> The device cannot negotiate TLS 1.2, so the
 * outer layer is unencrypted, and it costs nothing: SSH is already end to end
 * encrypted and the relay carries ciphertext it cannot read. What makes an
 * untrusted relay acceptable is the host key check, which is unaffected.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class WebSocket {

    private static final int OPCODE_CONTINUATION = 0x0;
    private static final int OPCODE_BINARY = 0x2;
    private static final int OPCODE_CLOSE = 0x8;
    private static final int OPCODE_PING = 0x9;
    private static final int OPCODE_PONG = 0xa;

    private static final int MASK_LENGTH = 4;

    private final InputStream in;
    private final OutputStream out;
    private final EntropyPool random;

    private final Input reader = new Input();
    private final Output writer = new Output();

    private byte[] pending = new byte[0];
    private int pendingAt;
    private boolean closed;

    private WebSocket(InputStream in, OutputStream out, EntropyPool random) {
        this.in = in;
        this.out = out;
        this.random = random;
    }

    /**
     * Performs the upgrade over an already-open connection and returns the
     * WebSocket carried on it.
     *
     * @param host the Host header, which a reverse proxy routes on
     * @param path the resource, which the bridge maps to a destination
     */
    public static WebSocket connect(InputStream in, OutputStream out, String host,
                                    String path, EntropyPool random) throws IOException {
        WebSocket socket = new WebSocket(in, out, random);
        socket.handshake(host, path);
        return socket;
    }

    public InputStream inputStream() {
        return reader;
    }

    public OutputStream outputStream() {
        return writer;
    }

    private void handshake(String host, String path) throws IOException {
        byte[] nonce = random.nextBytes(16);
        StringBuffer request = new StringBuffer(256);
        request.append("GET ").append(path).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(host).append("\r\n");
        request.append("Upgrade: websocket\r\n");
        request.append("Connection: Upgrade\r\n");
        request.append("Sec-WebSocket-Key: ").append(Base64.encode(nonce)).append("\r\n");
        request.append("Sec-WebSocket-Version: 13\r\n");
        request.append("\r\n");
        out.write(Ascii.toBytes(request.toString()));
        out.flush();

        String status = readLine();
        // "HTTP/1.1 101 Switching Protocols". Anything else is a proxy telling
        // us something, and its text is worth more than a generic failure.
        if (status.indexOf(" 101") < 0) {
            throw new SshException("the bridge refused the upgrade: " + status);
        }

        boolean upgraded = false;
        for (;;) {
            String header = readLine();
            if (header.length() == 0) {
                break;
            }
            // Compared by hand rather than with equalsIgnoreCase: the device's
            // locale is Turkish, where case folding is lossy. Header names are
            // ASCII, so a byte-wise fold over A-Z is both correct and total.
            if (startsWithFolded(header, "upgrade:")
                    && indexOfFolded(header, "websocket") >= 0) {
                upgraded = true;
            }
        }
        if (!upgraded) {
            throw new SshException("the bridge answered 101 without upgrading");
        }

        // Sec-WebSocket-Accept is not checked. Verifying it needs SHA-1, which
        // this project has no other use for, and it is not what protects this
        // connection — it exists to stop a confused intermediary being talked
        // into forwarding frames. The host key check is the real defence, and
        // it is unaffected by anything a relay does.
    }

    /** The most a header line may be before the far side is not a bridge. */
    private static final int MAX_HEADER = 8192;

    /** See {@link Lines} for why this cannot read ahead. */
    private String readLine() throws IOException {
        return Lines.read(in, MAX_HEADER, "bridge");
    }

    /** Sends one binary frame, masked as a client must. */
    private synchronized void sendFrame(int opcode, byte[] data, int offset, int length)
            throws IOException {
        byte[] header = new byte[14];
        int at = 0;
        header[at++] = (byte) (0x80 | opcode);          // FIN, never fragmented

        // The mask bit is not optional for a client. A server that receives an
        // unmasked frame is required to fail the connection.
        if (length < 126) {
            header[at++] = (byte) (0x80 | length);
        } else if (length < 65536) {
            header[at++] = (byte) (0x80 | 126);
            header[at++] = (byte) (length >>> 8);
            header[at++] = (byte) length;
        } else {
            header[at++] = (byte) (0x80 | 127);
            for (int i = 56; i >= 0; i -= 8) {
                header[at++] = (byte) (((long) length) >>> i);
            }
        }

        byte[] mask = random.nextBytes(MASK_LENGTH);
        System.arraycopy(mask, 0, header, at, MASK_LENGTH);
        at += MASK_LENGTH;

        byte[] masked = new byte[length];
        for (int i = 0; i < length; i++) {
            masked[i] = (byte) (data[offset + i] ^ mask[i % MASK_LENGTH]);
        }

        out.write(header, 0, at);
        out.write(masked, 0, length);
        out.flush();
    }

    /**
     * Reads frames until one carries data, answering the control frames rather
     * than passing them up. A ping left unanswered is a connection an
     * intermediary will eventually drop.
     */
    private void receive() throws IOException {
        for (;;) {
            int first = in.read();
            if (first < 0) {
                closed = true;
                return;
            }
            int second = readByte();
            int opcode = first & 0x0f;
            boolean masked = (second & 0x80) != 0;

            long length = second & 0x7f;
            if (length == 126) {
                length = (readByte() << 8) | readByte();
            } else if (length == 127) {
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | readByte();
                }
            }
            if (length > 1024L * 1024L) {
                throw new SshException("the bridge sent a " + length + " byte frame");
            }

            byte[] mask = null;
            if (masked) {
                // A server should not mask, but unmasking correctly costs
                // nothing and refusing would be a compatibility problem
                // rather than a safety one.
                mask = new byte[MASK_LENGTH];
                readFully(mask, 0, MASK_LENGTH);
            }

            byte[] payload = new byte[(int) length];
            readFully(payload, 0, payload.length);
            if (mask != null) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] = (byte) (payload[i] ^ mask[i % MASK_LENGTH]);
                }
            }

            if (opcode == OPCODE_CLOSE) {
                closed = true;
                return;
            }
            if (opcode == OPCODE_PING) {
                sendFrame(OPCODE_PONG, payload, 0, payload.length);
                continue;
            }
            if (opcode == OPCODE_PONG) {
                continue;
            }
            if (opcode == OPCODE_BINARY || opcode == OPCODE_CONTINUATION) {
                if (payload.length > 0) {
                    append(payload);
                    return;
                }
                continue;
            }
            throw new SshException("the bridge sent opcode " + opcode);
        }
    }

    private void append(byte[] data) {
        int left = pending.length - pendingAt;
        byte[] combined = new byte[left + data.length];
        System.arraycopy(pending, pendingAt, combined, 0, left);
        System.arraycopy(data, 0, combined, left, data.length);
        pending = combined;
        pendingAt = 0;
    }

    private int readByte() throws IOException {
        int c = in.read();
        if (c < 0) {
            throw new SshException("the bridge closed mid-frame");
        }
        return c;
    }

    private void readFully(byte[] b, int offset, int length) throws IOException {
        Lines.readFully(in, b, offset, length, "bridge");
    }

    /** The bytes the far side sent, with the framing taken off. */
    private final class Input extends InputStream {
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xff);
        }

        public int read(byte[] b, int offset, int length) throws IOException {
            while (pendingAt == pending.length) {
                if (closed) {
                    return -1;
                }
                receive();
            }
            int take = pending.length - pendingAt;
            if (take > length) {
                take = length;
            }
            System.arraycopy(pending, pendingAt, b, offset, take);
            pendingAt += take;
            return take;
        }
    }

    /** Whatever is written becomes one binary frame. */
    private final class Output extends OutputStream {
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        public void write(byte[] b, int offset, int length) throws IOException {
            if (length > 0) {
                sendFrame(OPCODE_BINARY, b, offset, length);
            }
        }
    }

    private static boolean startsWithFolded(String s, String lowerPrefix) {
        if (s.length() < lowerPrefix.length()) {
            return false;
        }
        for (int i = 0; i < lowerPrefix.length(); i++) {
            if (fold(s.charAt(i)) != lowerPrefix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static int indexOfFolded(String s, String lower) {
        for (int i = 0; i + lower.length() <= s.length(); i++) {
            boolean hit = true;
            for (int j = 0; j < lower.length(); j++) {
                if (fold(s.charAt(i + j)) != lower.charAt(j)) {
                    hit = false;
                    break;
                }
            }
            if (hit) {
                return i;
            }
        }
        return -1;
    }

    /** ASCII-only lower-casing, which String.toLowerCase is not on this device. */
    private static char fold(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
    }
}
