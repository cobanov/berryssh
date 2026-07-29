package berryssh.protocol;

import java.io.IOException;

/**
 * Reader for the SSH wire types of RFC 4251 section 5.
 *
 * Every read is bounds-checked against the end of the packet. The data is
 * attacker-controlled up until the host key is verified, so a length field is
 * never trusted far enough to allocate against before it has been compared with
 * what is actually left.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class WireReader {

    private final byte[] buf;
    private final int end;
    private int pos;

    public WireReader(byte[] data) {
        this(data, 0, data.length);
    }

    public WireReader(byte[] data, int offset, int length) {
        this.buf = data;
        this.pos = offset;
        this.end = offset + length;
    }

    public int remaining() {
        return end - pos;
    }

    /** Returns 0..255, not a sign-extended byte. */
    public int readByte() throws IOException {
        need(1);
        return buf[pos++] & 0xff;
    }

    public boolean readBoolean() throws IOException {
        return readByte() != 0;
    }

    /** Returns 0..2^32-1: a uint32 does not fit in a Java int without a sign trap. */
    public long readUint32() throws IOException {
        need(4);
        return ((long) (buf[pos++] & 0xff) << 24)
             | ((long) (buf[pos++] & 0xff) << 16)
             | ((long) (buf[pos++] & 0xff) << 8)
             | (long) (buf[pos++] & 0xff);
    }

    public long readUint64() throws IOException {
        need(8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (buf[pos++] & 0xff);
        }
        return v;
    }

    /** Reads bytes with no length prefix. */
    public byte[] readRaw(int length) throws IOException {
        need(length);
        byte[] out = new byte[length];
        System.arraycopy(buf, pos, out, 0, length);
        pos += length;
        return out;
    }

    public byte[] readString() throws IOException {
        long length = readUint32();
        // Compared before allocating: the length is the peer's to choose.
        if (length > remaining()) {
            throw new SshException("string of " + length + " bytes overruns the packet");
        }
        return readRaw((int) length);
    }

    public String readAsciiString() throws IOException {
        return Ascii.fromBytes(readString());
    }

    /**
     * An mpint, returned as an unsigned big-endian magnitude with the sign byte
     * and any leading zeroes removed. SSH carries no negative values, so one
     * arriving is a protocol error rather than something to represent.
     */
    public byte[] readMpint() throws IOException {
        byte[] v = readString();
        if (v.length == 0) {
            return new byte[0];
        }
        if ((v[0] & 0x80) != 0) {
            throw new SshException("negative mpint");
        }
        int start = 0;
        while (start < v.length && v[start] == 0) {
            start++;
        }
        byte[] magnitude = new byte[v.length - start];
        System.arraycopy(v, start, magnitude, 0, magnitude.length);
        return magnitude;
    }

    /**
     * A name-list. The names come back as Strings built by {@link Ascii}, so a
     * later comparison with String.equals is byte equality — see the note there
     * on why a case-insensitive match would be a bug on this device.
     */
    public String[] readNameList() throws IOException {
        byte[] b = readString();
        if (b.length == 0) {
            return new String[0];
        }
        int count = 1;
        for (int i = 0; i < b.length; i++) {
            if (b[i] == ',') {
                count++;
            }
        }
        String[] names = new String[count];
        int n = 0;
        int start = 0;
        for (int i = 0; i <= b.length; i++) {
            if (i == b.length || b[i] == ',') {
                names[n++] = Ascii.fromBytes(b, start, i - start);
                start = i + 1;
            }
        }
        return names;
    }

    private void need(int n) throws IOException {
        if (n < 0 || end - pos < n) {
            throw new SshException("packet ended mid-field");
        }
    }
}
