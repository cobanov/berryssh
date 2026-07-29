package berryssh.crypto;

/**
 * Comparing byte arrays, once, in the way that is safe for all of them.
 *
 * There were four of these: two that exited at the first difference and two
 * that did not, and nothing at a call site to say which one it had reached
 * for. That was survivable only because the early-exit pair happened to
 * compare host keys, which are public — but the next thing that needs
 * comparing might be an authentication tag or a derived key, and picking the
 * wrong one of four would look exactly like picking the right one.
 *
 * So there is one, and it is the careful one. The cost is a few nanoseconds on
 * comparisons that did not need the care.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Bytes {

    private Bytes() {
    }

    /**
     * Equality, without letting the time taken say where two arrays first
     * differ.
     *
     * A comparison that stops at the first wrong byte tells an attacker how
     * much of a forged tag was right, which is enough to build the rest of it
     * one byte at a time.
     *
     * The length is not secret and is compared first: it is visible on the
     * wire in every case this is used for, and two arrays of different lengths
     * have nothing to compare byte by byte anyway.
     */
    public static boolean equal(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }
        return difference == 0;
    }
}
