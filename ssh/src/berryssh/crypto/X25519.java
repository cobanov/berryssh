package berryssh.crypto;

/**
 * RFC 7748 X25519 scalar multiplication, for the {@code curve25519-sha256} key
 * exchange.
 *
 * Uses the Montgomery ladder, which touches both branches of every scalar bit
 * and swaps with an arithmetic mask, so its running time does not depend on the
 * private key.
 *
 * Written for -source 1.3; see {@link Fe25519} for why the field arithmetic is
 * hand-rolled.
 */
public final class X25519 {

    public static final int KEY_LENGTH = 32;

    /** The base point u = 9. */
    private static final byte[] BASE_POINT = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    private X25519() {
    }

    /**
     * Clamps a 32-byte scalar in place, per RFC 7748 §5: clears the three low
     * bits so it is a multiple of the cofactor, clears the top bit, and sets
     * bit 254 so the ladder always runs the same number of meaningful steps.
     */
    public static void clamp(byte[] scalar) {
        scalar[0] &= (byte) 248;
        scalar[31] &= (byte) 127;
        scalar[31] |= (byte) 64;
    }

    /** Derives the public key for a private scalar. The scalar is not modified. */
    public static byte[] scalarMultBase(byte[] scalar) {
        return scalarMult(scalar, BASE_POINT, 0);
    }

    public static byte[] scalarMult(byte[] scalar, byte[] point) {
        return scalarMult(scalar, point, 0);
    }

    /**
     * Computes scalar * point. The caller's scalar is copied before clamping,
     * so a private key can be reused across calls.
     */
    public static byte[] scalarMult(byte[] scalar, byte[] point, int pointOffset) {
        if (scalar.length != KEY_LENGTH) {
            throw new IllegalArgumentException("scalar must be 32 bytes");
        }

        byte[] e = new byte[KEY_LENGTH];
        System.arraycopy(scalar, 0, e, 0, KEY_LENGTH);
        clamp(e);

        int[] x1 = Fe25519.create();
        Fe25519.fromBytes(x1, point, pointOffset);

        int[] x2 = Fe25519.one();
        int[] z2 = Fe25519.create();
        int[] x3 = Fe25519.create();
        int[] z3 = Fe25519.one();
        Fe25519.copy(x3, x1);

        int[] a = Fe25519.create(), b = Fe25519.create();
        int[] c = Fe25519.create(), d = Fe25519.create();
        int[] da = Fe25519.create(), cb = Fe25519.create();
        int[] t = Fe25519.create();

        int swap = 0;
        for (int pos = 254; pos >= 0; pos--) {
            int bit = (e[pos >>> 3] >>> (pos & 7)) & 1;
            swap ^= bit;
            Fe25519.cswap(x2, x3, swap);
            Fe25519.cswap(z2, z3, swap);
            swap = bit;

            Fe25519.sub(a, x2, z2);
            Fe25519.add(b, x2, z2);
            Fe25519.sub(c, x3, z3);
            Fe25519.add(d, x3, z3);

            Fe25519.mul(da, d, a);
            Fe25519.mul(cb, c, b);

            Fe25519.add(t, da, cb);
            Fe25519.sq(x3, t);
            Fe25519.sub(t, da, cb);
            Fe25519.sq(z3, t);
            Fe25519.mul(z3, x1, z3);

            Fe25519.sq(c, a);          // a^2
            Fe25519.sq(d, b);          // b^2
            Fe25519.mul(x2, c, d);
            Fe25519.sub(t, d, c);      // b^2 - a^2
            Fe25519.mul121666(a, t);
            Fe25519.add(a, a, c);
            Fe25519.mul(z2, t, a);
        }

        Fe25519.cswap(x2, x3, swap);
        Fe25519.cswap(z2, z3, swap);

        Fe25519.invert(z2, z2);
        Fe25519.mul(x2, x2, z2);

        byte[] out = new byte[KEY_LENGTH];
        Fe25519.toBytes(out, 0, x2);
        return out;
    }

    /**
     * True if the shared secret is all zeroes, which happens when the peer
     * sends a low-order point. RFC 8731 §3 requires the connection to fail in
     * that case rather than proceeding with a known secret.
     */
    public static boolean isAllZero(byte[] sharedSecret) {
        int acc = 0;
        for (int i = 0; i < sharedSecret.length; i++) {
            acc |= sharedSecret[i];
        }
        return acc == 0;
    }
}
