package berryssh.protocol;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reading a line, and filling a buffer, from a stream that must not be read
 * ahead of.
 *
 * <b>The unbuffered part is the whole point, and it is why these are here
 * rather than replaced by something from the library.</b> In all three places
 * that read a line — the SSH version exchange, the WebSocket upgrade, and the
 * bridge handshake — the very next byte after the line belongs to a different
 * layer. A reader that pulled ahead in blocks would swallow the start of it,
 * and CLDC 1.1 has no {@code BufferedInputStream} to push the excess back
 * into. So every one of them reads a byte at a time, and that constraint is
 * stated once here instead of being rediscovered three times.
 *
 * There were three copies of the line reader and two of the fill, differing
 * only in their limits and the wording of their errors. Both of those are
 * parameters.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
final class Lines {

    private Lines() {
    }

    /**
     * Reads up to a newline, dropping a trailing carriage return.
     *
     * @param max  the most that will be kept before the peer is treated as
     *             hostile rather than merely verbose
     * @param what what to call the far side in an error, so the message says
     *             which layer gave up
     */
    static String read(InputStream in, int max, String what) throws IOException {
        StringBuffer line = new StringBuffer(64);
        for (;;) {
            int c = in.read();
            if (c < 0) {
                throw new SshException(line.length() == 0
                    ? "the " + what + " closed without answering"
                    : "the " + what + " closed mid-line");
            }
            if (c == '\n') {
                return line.toString();
            }
            if (c != '\r') {
                line.append((char) c);
            }
            if (line.length() > max) {
                throw new SshException("the " + what + " sent a line longer than "
                    + max + " bytes");
            }
        }
    }

    /** Reads exactly {@code length} bytes, or fails saying who stopped. */
    static void readFully(InputStream in, byte[] b, int offset, int length, String what)
            throws IOException {
        while (length > 0) {
            int n = in.read(b, offset, length);
            if (n < 0) {
                throw new SshException("the " + what + " closed mid-packet");
            }
            offset += n;
            length -= n;
        }
    }
}
