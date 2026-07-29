package berryssh.protocol;

/**
 * Writer for the SSH wire types of RFC 4251 section 5.
 *
 * Everything SSH sends is built out of these six types, so the encoding rules
 * live in one place rather than being open-coded per message. The buffer grows
 * on demand: packet sizes are not known ahead of time and CLDC has no
 * ByteArrayOutputStream variant that would hand back the backing array without
 * a copy.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class WireWriter {

    private byte[] buf;
    private int pos;

    public WireWriter() {
        this(256);
    }

    public WireWriter(int capacity) {
        buf = new byte[capacity < 16 ? 16 : capacity];
    }

    public int length() {
        return pos;
    }

    public byte[] toByteArray() {
        byte[] out = new byte[pos];
        System.arraycopy(buf, 0, out, 0, pos);
        return out;
    }

    public void writeByte(int b) {
        ensure(1);
        buf[pos++] = (byte) b;
    }

    /** RFC 4251: a sender must use 1 for true, not merely a non-zero byte. */
    public void writeBoolean(boolean v) {
        writeByte(v ? 1 : 0);
    }

    /** Takes a long so that the full unsigned range survives the call unambiguously. */
    public void writeUint32(long v) {
        ensure(4);
        buf[pos++] = (byte) (v >>> 24);
        buf[pos++] = (byte) (v >>> 16);
        buf[pos++] = (byte) (v >>> 8);
        buf[pos++] = (byte) v;
    }

    // writeUint64 went with the matching reader. RFC 4251 defines the type and
    // nothing this client sends or receives uses it, so the pair existed to
    // make the wire-type set look complete and were exercised only by the test
    // that proved they were symmetrical with each other.

    /** Appends bytes with no length prefix. */
    public void writeRaw(byte[] b) {
        writeRaw(b, 0, b.length);
    }

    public void writeRaw(byte[] b, int offset, int length) {
        ensure(length);
        System.arraycopy(b, offset, buf, pos, length);
        pos += length;
    }

    /** An SSH string is a length prefix and arbitrary binary, not text. */
    public void writeString(byte[] s) {
        writeString(s, 0, s.length);
    }

    public void writeString(byte[] s, int offset, int length) {
        writeUint32(length);
        writeRaw(s, offset, length);
    }

    /**
     * A string holding an ASCII name — a service, an algorithm, a channel type.
     * Named for the encoding on purpose: usernames and passwords are UTF-8 by
     * RFC 4252 and must not come through here.
     */
    public void writeAsciiString(String s) {
        writeString(Ascii.toBytes(s));
    }

    /**
     * An mpint, from an unsigned big-endian magnitude.
     *
     * RFC 4251 stores these in two's complement at minimum length: leading zero
     * bytes are dropped, and a zero byte goes in front when the top bit is set
     * so the value stays positive. Zero is the empty string. SSH never carries a
     * negative one, so only the non-negative case is encoded.
     */
    public void writeMpint(byte[] magnitude) {
        int start = 0;
        while (start < magnitude.length && magnitude[start] == 0) {
            start++;
        }
        int length = magnitude.length - start;
        if (length == 0) {
            writeUint32(0);
            return;
        }
        boolean signByte = (magnitude[start] & 0x80) != 0;
        writeUint32(signByte ? length + 1 : length);
        if (signByte) {
            writeByte(0);
        }
        writeRaw(magnitude, start, length);
    }

    /** A name-list: comma-separated ASCII names, carried inside a string. */
    public void writeNameList(String[] names) {
        int total = 0;
        for (int i = 0; i < names.length; i++) {
            if (i > 0) {
                total++;
            }
            total += names[i].length();
        }
        writeUint32(total);
        for (int i = 0; i < names.length; i++) {
            if (i > 0) {
                writeByte(',');
            }
            writeRaw(Ascii.toBytes(names[i]));
        }
    }

    private void ensure(int extra) {
        if (pos + extra <= buf.length) {
            return;
        }
        int size = buf.length * 2;
        while (size < pos + extra) {
            size *= 2;
        }
        byte[] bigger = new byte[size];
        System.arraycopy(buf, 0, bigger, 0, pos);
        buf = bigger;
    }
}
