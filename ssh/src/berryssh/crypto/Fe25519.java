package berryssh.crypto;

/**
 * Arithmetic in the field GF(2^255 - 19), shared by X25519 and Ed25519.
 *
 * A field element is ten {@code int} limbs in radix 2^25.5 — alternating 26 and
 * 25 bits — so that a product of two limbs stays well inside a signed 64-bit
 * value and several such products can be accumulated before carrying. This is
 * the representation and reduction schedule used by djb's ref10, which is in
 * the public domain.
 *
 * CLDC 1.1 has no BigInteger, so this is the whole of the arithmetic layer.
 * Written for -source 1.3.
 *
 * Every operation here runs in time independent of its inputs: no branches on
 * secret data, and no data-dependent memory access.
 */
final class Fe25519 {

    static final int LIMBS = 10;

    private Fe25519() {
    }

    static int[] create() {
        return new int[LIMBS];
    }

    static int[] one() {
        int[] h = new int[LIMBS];
        h[0] = 1;
        return h;
    }

    static void copy(int[] h, int[] f) {
        System.arraycopy(f, 0, h, 0, LIMBS);
    }

    static void add(int[] h, int[] f, int[] g) {
        for (int i = 0; i < LIMBS; i++) {
            h[i] = f[i] + g[i];
        }
    }

    static void sub(int[] h, int[] f, int[] g) {
        for (int i = 0; i < LIMBS; i++) {
            h[i] = f[i] - g[i];
        }
    }

    /**
     * Conditionally exchanges f and g. {@code b} must be 0 or 1; the swap is
     * driven by an arithmetic mask rather than a branch so the ladder does not
     * leak scalar bits through timing.
     */
    static void cswap(int[] f, int[] g, int b) {
        int mask = -b;
        for (int i = 0; i < LIMBS; i++) {
            int x = (f[i] ^ g[i]) & mask;
            f[i] ^= x;
            g[i] ^= x;
        }
    }

    static void mul(int[] h, int[] f, int[] g) {
        int f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
        int f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
        int g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
        int g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];

        // 2^255 = 19 mod p, so limbs that wrap past the top come back scaled by 19.
        int g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
        int g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8;
        int g9_19 = 19 * g9;
        // Odd limbs carry an extra factor of two from the 25.5-bit radix.
        int f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

        long h0 = f0 * (long) g0 + f1_2 * (long) g9_19 + f2 * (long) g8_19
                + f3_2 * (long) g7_19 + f4 * (long) g6_19 + f5_2 * (long) g5_19
                + f6 * (long) g4_19 + f7_2 * (long) g3_19 + f8 * (long) g2_19
                + f9_2 * (long) g1_19;
        long h1 = f0 * (long) g1 + f1 * (long) g0 + f2 * (long) g9_19
                + f3 * (long) g8_19 + f4 * (long) g7_19 + f5 * (long) g6_19
                + f6 * (long) g5_19 + f7 * (long) g4_19 + f8 * (long) g3_19
                + f9 * (long) g2_19;
        long h2 = f0 * (long) g2 + f1_2 * (long) g1 + f2 * (long) g0
                + f3_2 * (long) g9_19 + f4 * (long) g8_19 + f5_2 * (long) g7_19
                + f6 * (long) g6_19 + f7_2 * (long) g5_19 + f8 * (long) g4_19
                + f9_2 * (long) g3_19;
        long h3 = f0 * (long) g3 + f1 * (long) g2 + f2 * (long) g1
                + f3 * (long) g0 + f4 * (long) g9_19 + f5 * (long) g8_19
                + f6 * (long) g7_19 + f7 * (long) g6_19 + f8 * (long) g5_19
                + f9 * (long) g4_19;
        long h4 = f0 * (long) g4 + f1_2 * (long) g3 + f2 * (long) g2
                + f3_2 * (long) g1 + f4 * (long) g0 + f5_2 * (long) g9_19
                + f6 * (long) g8_19 + f7_2 * (long) g7_19 + f8 * (long) g6_19
                + f9_2 * (long) g5_19;
        long h5 = f0 * (long) g5 + f1 * (long) g4 + f2 * (long) g3
                + f3 * (long) g2 + f4 * (long) g1 + f5 * (long) g0
                + f6 * (long) g9_19 + f7 * (long) g8_19 + f8 * (long) g7_19
                + f9 * (long) g6_19;
        long h6 = f0 * (long) g6 + f1_2 * (long) g5 + f2 * (long) g4
                + f3_2 * (long) g3 + f4 * (long) g2 + f5_2 * (long) g1
                + f6 * (long) g0 + f7_2 * (long) g9_19 + f8 * (long) g8_19
                + f9_2 * (long) g7_19;
        long h7 = f0 * (long) g7 + f1 * (long) g6 + f2 * (long) g5
                + f3 * (long) g4 + f4 * (long) g3 + f5 * (long) g2
                + f6 * (long) g1 + f7 * (long) g0 + f8 * (long) g9_19
                + f9 * (long) g8_19;
        long h8 = f0 * (long) g8 + f1_2 * (long) g7 + f2 * (long) g6
                + f3_2 * (long) g5 + f4 * (long) g4 + f5_2 * (long) g3
                + f6 * (long) g2 + f7_2 * (long) g1 + f8 * (long) g0
                + f9_2 * (long) g9_19;
        long h9 = f0 * (long) g9 + f1 * (long) g8 + f2 * (long) g7
                + f3 * (long) g6 + f4 * (long) g5 + f5 * (long) g4
                + f6 * (long) g3 + f7 * (long) g2 + f8 * (long) g1
                + f9 * (long) g0;

        carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    static void sq(int[] h, int[] f) {
        mul(h, f, f);
    }

    /** Multiplies by the Montgomery ladder constant (a-2)/4 = 121665. */
    static void mul121666(int[] h, int[] f) {
        long h0 = f[0] * 121666L, h1 = f[1] * 121666L, h2 = f[2] * 121666L;
        long h3 = f[3] * 121666L, h4 = f[4] * 121666L, h5 = f[5] * 121666L;
        long h6 = f[6] * 121666L, h7 = f[7] * 121666L, h8 = f[8] * 121666L;
        long h9 = f[9] * 121666L;
        carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    /**
     * Propagates carries back into the 26/25-bit limb layout. The even-then-odd
     * ordering keeps every intermediate inside 64 bits.
     */
    private static void carry(int[] h, long h0, long h1, long h2, long h3, long h4,
                              long h5, long h6, long h7, long h8, long h9) {
        long c;
        c = (h0 + (1L << 25)) >> 26; h1 += c; h0 -= c << 26;
        c = (h4 + (1L << 25)) >> 26; h5 += c; h4 -= c << 26;
        c = (h1 + (1L << 24)) >> 25; h2 += c; h1 -= c << 25;
        c = (h5 + (1L << 24)) >> 25; h6 += c; h5 -= c << 25;
        c = (h2 + (1L << 25)) >> 26; h3 += c; h2 -= c << 26;
        c = (h6 + (1L << 25)) >> 26; h7 += c; h6 -= c << 26;
        c = (h3 + (1L << 24)) >> 25; h4 += c; h3 -= c << 25;
        c = (h7 + (1L << 24)) >> 25; h8 += c; h7 -= c << 25;
        c = (h4 + (1L << 25)) >> 26; h5 += c; h4 -= c << 26;
        c = (h8 + (1L << 25)) >> 26; h9 += c; h8 -= c << 26;
        c = (h9 + (1L << 24)) >> 25; h0 += c * 19; h9 -= c << 25;
        c = (h0 + (1L << 25)) >> 26; h1 += c; h0 -= c << 26;

        h[0] = (int) h0; h[1] = (int) h1; h[2] = (int) h2; h[3] = (int) h3;
        h[4] = (int) h4; h[5] = (int) h5; h[6] = (int) h6; h[7] = (int) h7;
        h[8] = (int) h8; h[9] = (int) h9;
    }

    /** Computes f^(p-2), which is the inverse for every non-zero f. */
    static void invert(int[] out, int[] z) {
        int[] t0 = create(), t1 = create(), t2 = create(), t3 = create();
        int i;

        sq(t0, z);                                   // z^2
        sq(t1, t0); sq(t1, t1);                      // z^8
        mul(t1, z, t1);                              // z^9
        mul(t0, t0, t1);                             // z^11
        sq(t2, t0);                                  // z^22
        mul(t1, t1, t2);                             // z^31 = z^(2^5 - 1)

        sq(t2, t1);
        for (i = 1; i < 5; i++) { sq(t2, t2); }
        mul(t1, t2, t1);                             // z^(2^10 - 1)

        sq(t2, t1);
        for (i = 1; i < 10; i++) { sq(t2, t2); }
        mul(t2, t2, t1);                             // z^(2^20 - 1)

        sq(t3, t2);
        for (i = 1; i < 20; i++) { sq(t3, t3); }
        mul(t2, t3, t2);                             // z^(2^40 - 1)

        sq(t2, t2);
        for (i = 1; i < 10; i++) { sq(t2, t2); }
        mul(t1, t2, t1);                             // z^(2^50 - 1)

        sq(t2, t1);
        for (i = 1; i < 50; i++) { sq(t2, t2); }
        mul(t2, t2, t1);                             // z^(2^100 - 1)

        sq(t3, t2);
        for (i = 1; i < 100; i++) { sq(t3, t3); }
        mul(t2, t3, t2);                             // z^(2^200 - 1)

        sq(t2, t2);
        for (i = 1; i < 50; i++) { sq(t2, t2); }
        mul(t1, t2, t1);                             // z^(2^250 - 1)

        sq(t1, t1);
        for (i = 1; i < 5; i++) { sq(t1, t1); }
        mul(out, t1, t0);                            // z^(2^255 - 21) = z^(p-2)
    }

    /** Loads a 32-byte little-endian value. The top bit is ignored, per RFC 7748. */
    static void fromBytes(int[] h, byte[] s, int off) {
        long h0 = load4(s, off);
        long h1 = load3(s, off + 4) << 6;
        long h2 = load3(s, off + 7) << 5;
        long h3 = load3(s, off + 10) << 3;
        long h4 = load3(s, off + 13) << 2;
        long h5 = load4(s, off + 16);
        long h6 = load3(s, off + 20) << 7;
        long h7 = load3(s, off + 23) << 5;
        long h8 = load3(s, off + 26) << 4;
        long h9 = (load3(s, off + 29) & 8388607L) << 2;
        carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    /** Fully reduces mod p and writes 32 little-endian bytes. */
    static void toBytes(byte[] s, int off, int[] h) {
        int h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        int h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
        int q, c;

        // Decide whether the value is >= p, then add that many multiples of 19.
        q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;

        c = h0 >> 26; h1 += c; h0 -= c << 26;
        c = h1 >> 25; h2 += c; h1 -= c << 25;
        c = h2 >> 26; h3 += c; h2 -= c << 26;
        c = h3 >> 25; h4 += c; h3 -= c << 25;
        c = h4 >> 26; h5 += c; h4 -= c << 26;
        c = h5 >> 25; h6 += c; h5 -= c << 25;
        c = h6 >> 26; h7 += c; h6 -= c << 26;
        c = h7 >> 25; h8 += c; h7 -= c << 25;
        c = h8 >> 26; h9 += c; h8 -= c << 26;
        c = h9 >> 25;            h9 -= c << 25;   // the final carry is discarded: that is the reduction

        s[off]      = (byte) h0;
        s[off + 1]  = (byte) (h0 >> 8);
        s[off + 2]  = (byte) (h0 >> 16);
        s[off + 3]  = (byte) ((h0 >> 24) | (h1 << 2));
        s[off + 4]  = (byte) (h1 >> 6);
        s[off + 5]  = (byte) (h1 >> 14);
        s[off + 6]  = (byte) ((h1 >> 22) | (h2 << 3));
        s[off + 7]  = (byte) (h2 >> 5);
        s[off + 8]  = (byte) (h2 >> 13);
        s[off + 9]  = (byte) ((h2 >> 21) | (h3 << 5));
        s[off + 10] = (byte) (h3 >> 3);
        s[off + 11] = (byte) (h3 >> 11);
        s[off + 12] = (byte) ((h3 >> 19) | (h4 << 6));
        s[off + 13] = (byte) (h4 >> 2);
        s[off + 14] = (byte) (h4 >> 10);
        s[off + 15] = (byte) (h4 >> 18);
        s[off + 16] = (byte) h5;
        s[off + 17] = (byte) (h5 >> 8);
        s[off + 18] = (byte) (h5 >> 16);
        s[off + 19] = (byte) ((h5 >> 24) | (h6 << 1));
        s[off + 20] = (byte) (h6 >> 7);
        s[off + 21] = (byte) (h6 >> 15);
        s[off + 22] = (byte) ((h6 >> 23) | (h7 << 3));
        s[off + 23] = (byte) (h7 >> 5);
        s[off + 24] = (byte) (h7 >> 13);
        s[off + 25] = (byte) ((h7 >> 21) | (h8 << 4));
        s[off + 26] = (byte) (h8 >> 4);
        s[off + 27] = (byte) (h8 >> 12);
        s[off + 28] = (byte) ((h8 >> 20) | (h9 << 6));
        s[off + 29] = (byte) (h9 >> 2);
        s[off + 30] = (byte) (h9 >> 10);
        s[off + 31] = (byte) (h9 >> 18);
    }

    /** True if every limb is zero once fully reduced. Constant time. */
    static boolean isZero(int[] f) {
        byte[] s = new byte[32];
        toBytes(s, 0, f);
        int acc = 0;
        for (int i = 0; i < 32; i++) {
            acc |= s[i];
        }
        return acc == 0;
    }

    private static long load3(byte[] s, int off) {
        return (s[off] & 0xffL) | ((s[off + 1] & 0xffL) << 8) | ((s[off + 2] & 0xffL) << 16);
    }

    private static long load4(byte[] s, int off) {
        return (s[off] & 0xffL) | ((s[off + 1] & 0xffL) << 8)
             | ((s[off + 2] & 0xffL) << 16) | ((s[off + 3] & 0xffL) << 24);
    }
}
