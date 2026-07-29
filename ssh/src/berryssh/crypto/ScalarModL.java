package berryssh.crypto;

/**
 * Arithmetic modulo L, the order of the Ed25519 base point.
 *
 * L = 2^252 + 27742317777372353535851937790883648493. Signing needs two
 * operations there: reducing a 64-byte hash into a scalar, and computing
 * (k*a + r) mod L. Verification needed neither, which is why this arrives with
 * signing rather than with the curve.
 *
 * The reduction is bitwise long division — shift a bit in, conditionally
 * subtract L — rather than the packed 21-bit limb arithmetic the reference
 * implementations use. That is perhaps fifty times slower and it is the right
 * trade here: it runs once per signature, which is once per connection, and
 * unlike the limb version it can be read and checked by eye. There is no
 * BigInteger in CLDC to fall back on if the clever version were wrong.
 *
 * Everything is little-endian, as Ed25519 is throughout.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class ScalarModL {

    /** L in 32-bit little-endian limbs. */
    private static final int[] L = {
        0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
        0x00000000, 0x00000000, 0x00000000, 0x10000000
    };

    private static final int LIMBS = 8;

    public static final int LENGTH = 32;

    private ScalarModL() {
    }

    /**
     * Reduces a little-endian value of any length modulo L.
     *
     * Bits go in from the top; the running remainder stays below L, so after
     * doubling it is below 2L and a single conditional subtraction restores the
     * invariant. That bound is why eight limbs are always enough.
     */
    public static byte[] reduce(byte[] value, int length) {
        int[] r = new int[LIMBS];
        for (int bit = length * 8 - 1; bit >= 0; bit--) {
            int in = (value[bit >> 3] >>> (bit & 7)) & 1;
            shiftInBit(r, in);
            if (compare(r, L) >= 0) {
                subtract(r, L);
            }
        }
        return toBytes(r);
    }

    public static byte[] reduce(byte[] value) {
        return reduce(value, value.length);
    }

    /**
     * (a * b + c) mod L, the value of S in an Ed25519 signature.
     *
     * The product is computed at full width and reduced once at the end rather
     * than reduced as it goes, which keeps the two steps independent of one
     * another and separately checkable.
     */
    public static byte[] mulAdd(byte[] a, byte[] b, byte[] c) {
        byte[] product = multiply(a, b);
        byte[] sum = add(product, c);
        return reduce(sum, sum.length);
    }

    /** Schoolbook multiplication of little-endian byte arrays. */
    static byte[] multiply(byte[] a, byte[] b) {
        int[] acc = new int[a.length + b.length];
        for (int i = 0; i < a.length; i++) {
            int ai = a[i] & 0xff;
            if (ai == 0) {
                continue;
            }
            int carry = 0;
            for (int j = 0; j < b.length; j++) {
                // At most 255*255 + 255 + 255, so an int is never close to full.
                int t = acc[i + j] + ai * (b[j] & 0xff) + carry;
                acc[i + j] = t & 0xff;
                carry = t >>> 8;
            }
            int at = i + b.length;
            while (carry != 0) {
                int t = acc[at] + carry;
                acc[at] = t & 0xff;
                carry = t >>> 8;
                at++;
            }
        }
        byte[] out = new byte[acc.length];
        for (int i = 0; i < acc.length; i++) {
            out[i] = (byte) acc[i];
        }
        return out;
    }

    /** Little-endian addition, widened by one byte so nothing is lost. */
    static byte[] add(byte[] a, byte[] b) {
        int length = (a.length > b.length ? a.length : b.length) + 1;
        byte[] out = new byte[length];
        int carry = 0;
        for (int i = 0; i < length; i++) {
            int t = carry;
            if (i < a.length) {
                t += a[i] & 0xff;
            }
            if (i < b.length) {
                t += b[i] & 0xff;
            }
            out[i] = (byte) t;
            carry = t >>> 8;
        }
        return out;
    }

    private static void shiftInBit(int[] r, int in) {
        int carry = in;
        for (int i = 0; i < LIMBS; i++) {
            int next = r[i] >>> 31;
            r[i] = (r[i] << 1) | carry;
            carry = next;
        }
    }

    /** Unsigned comparison, most significant limb first. */
    private static int compare(int[] a, int[] b) {
        for (int i = LIMBS - 1; i >= 0; i--) {
            long x = a[i] & 0xffffffffL;
            long y = b[i] & 0xffffffffL;
            if (x < y) {
                return -1;
            }
            if (x > y) {
                return 1;
            }
        }
        return 0;
    }

    private static void subtract(int[] a, int[] b) {
        long borrow = 0;
        for (int i = 0; i < LIMBS; i++) {
            long t = (a[i] & 0xffffffffL) - (b[i] & 0xffffffffL) - borrow;
            a[i] = (int) t;
            borrow = (t >> 32) & 1;
        }
    }

    private static byte[] toBytes(int[] r) {
        byte[] out = new byte[LENGTH];
        for (int i = 0; i < LIMBS; i++) {
            out[4 * i] = (byte) r[i];
            out[4 * i + 1] = (byte) (r[i] >>> 8);
            out[4 * i + 2] = (byte) (r[i] >>> 16);
            out[4 * i + 3] = (byte) (r[i] >>> 24);
        }
        return out;
    }
}
