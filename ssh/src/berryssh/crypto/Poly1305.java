package berryssh.crypto;

/**
 * RFC 8439 Poly1305 one-time authenticator.
 *
 * The accumulator is held as five 26-bit limbs in longs, which keeps every
 * intermediate product inside a signed 64-bit value. CLDC 1.1 has no
 * BigInteger, and a limb representation is faster here anyway.
 *
 * Written for -source 1.3.
 */
public final class Poly1305 {

    public static final int TAG_LENGTH = 16;

    private final int r0, r1, r2, r3, r4;
    private final int s1, s2, s3, s4;
    private final int pad0, pad1, pad2, pad3;

    private long h0, h1, h2, h3, h4;
    private final byte[] buffer = new byte[16];
    private int bufferLength;

    /** @param key 32 bytes: 16-byte clamped r followed by 16-byte s. */
    public Poly1305(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
        int t0 = littleEndian(key, 0);
        int t1 = littleEndian(key, 4);
        int t2 = littleEndian(key, 8);
        int t3 = littleEndian(key, 12);

        // Clamp r and split into 26-bit limbs.
        r0 = t0 & 0x3ffffff;
        r1 = ((t0 >>> 26) | (t1 << 6)) & 0x3ffff03;
        r2 = ((t1 >>> 20) | (t2 << 12)) & 0x3ffc0ff;
        r3 = ((t2 >>> 14) | (t3 << 18)) & 0x3f03fff;
        r4 = (t3 >>> 8) & 0x00fffff;

        // Pre-multiplied by 5 for the reduction step.
        s1 = r1 * 5;
        s2 = r2 * 5;
        s3 = r3 * 5;
        s4 = r4 * 5;

        pad0 = littleEndian(key, 16);
        pad1 = littleEndian(key, 20);
        pad2 = littleEndian(key, 24);
        pad3 = littleEndian(key, 28);
    }

    public void update(byte[] input, int offset, int length) {
        while (length > 0) {
            int take = 16 - bufferLength;
            if (take > length) {
                take = length;
            }
            System.arraycopy(input, offset, buffer, bufferLength, take);
            bufferLength += take;
            offset += take;
            length -= take;
            if (bufferLength == 16) {
                processBlock(buffer, 0, false);
                bufferLength = 0;
            }
        }
    }

    /** Zero-pads the current position up to a 16-byte boundary, per the AEAD construction. */
    public void padToBlock() {
        if (bufferLength != 0) {
            for (int i = bufferLength; i < 16; i++) {
                buffer[i] = 0;
            }
            processBlock(buffer, 0, false);
            bufferLength = 0;
        }
    }

    public byte[] finish() {
        if (bufferLength > 0) {
            buffer[bufferLength] = 1;
            for (int i = bufferLength + 1; i < 16; i++) {
                buffer[i] = 0;
            }
            processBlock(buffer, 0, true);
        }

        // Carry propagate.
        long c;
        c = h1 >>> 26; h1 &= 0x3ffffff; h2 += c;
        c = h2 >>> 26; h2 &= 0x3ffffff; h3 += c;
        c = h3 >>> 26; h3 &= 0x3ffffff; h4 += c;
        c = h4 >>> 26; h4 &= 0x3ffffff; h0 += c * 5;
        c = h0 >>> 26; h0 &= 0x3ffffff; h1 += c;

        // Compute h + -p and pick it if there was no borrow.
        long g0 = h0 + 5;      c = g0 >>> 26; g0 &= 0x3ffffff;
        long g1 = h1 + c;      c = g1 >>> 26; g1 &= 0x3ffffff;
        long g2 = h2 + c;      c = g2 >>> 26; g2 &= 0x3ffffff;
        long g3 = h3 + c;      c = g3 >>> 26; g3 &= 0x3ffffff;
        long g4 = h4 + c - (1L << 26);

        long mask = (g4 >>> 63) - 1;   // all ones when g4 >= 0, i.e. h >= p
        h0 = (h0 & ~mask) | (g0 & mask);
        h1 = (h1 & ~mask) | (g1 & mask);
        h2 = (h2 & ~mask) | (g2 & mask);
        h3 = (h3 & ~mask) | (g3 & mask);
        h4 = (h4 & ~mask) | (g4 & mask);

        // Reassemble into four 32-bit words and add s.
        long f0 = ((h0) | (h1 << 26)) & 0xffffffffL;
        long f1 = ((h1 >>> 6) | (h2 << 20)) & 0xffffffffL;
        long f2 = ((h2 >>> 12) | (h3 << 14)) & 0xffffffffL;
        long f3 = ((h3 >>> 18) | (h4 << 8)) & 0xffffffffL;

        byte[] tag = new byte[TAG_LENGTH];
        long acc = f0 + (pad0 & 0xffffffffL);
        writeLittleEndian(tag, 0, (int) acc);
        acc = f1 + (pad1 & 0xffffffffL) + (acc >>> 32);
        writeLittleEndian(tag, 4, (int) acc);
        acc = f2 + (pad2 & 0xffffffffL) + (acc >>> 32);
        writeLittleEndian(tag, 8, (int) acc);
        acc = f3 + (pad3 & 0xffffffffL) + (acc >>> 32);
        writeLittleEndian(tag, 12, (int) acc);
        return tag;
    }

    private void processBlock(byte[] in, int off, boolean partial) {
        int t0 = littleEndian(in, off);
        int t1 = littleEndian(in, off + 4);
        int t2 = littleEndian(in, off + 8);
        int t3 = littleEndian(in, off + 12);

        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >>> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >>> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >>> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >>> 8) & 0x3ffffff;
        if (!partial) {
            // The high bit is the 2^128 term of a full block; a final short
            // block already carries its own 0x01 terminator in the buffer.
            h4 += 1 << 24;
        }

        long d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        long d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        long d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        long d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        long d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        long c = d0 >>> 26; h0 = d0 & 0x3ffffff;
        d1 += c; c = d1 >>> 26; h1 = d1 & 0x3ffffff;
        d2 += c; c = d2 >>> 26; h2 = d2 & 0x3ffffff;
        d3 += c; c = d3 >>> 26; h3 = d3 & 0x3ffffff;
        d4 += c; c = d4 >>> 26; h4 = d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >>> 26; h0 &= 0x3ffffff;
        h1 += c;
    }

    private static int littleEndian(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
             | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static void writeLittleEndian(byte[] out, int off, int v) {
        out[off] = (byte) v;
        out[off + 1] = (byte) (v >>> 8);
        out[off + 2] = (byte) (v >>> 16);
        out[off + 3] = (byte) (v >>> 24);
    }
}
