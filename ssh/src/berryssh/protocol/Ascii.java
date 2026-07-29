package berryssh.protocol;

/**
 * US-ASCII conversion, done by hand.
 *
 * Neither direction can be left to the platform here. The device's default
 * encoding is ISO8859_1, so {@code new String(byte[])} is not portable, and its
 * locale is Turkish, where {@code "I".toLowerCase()} is {@code "i-dotless"} —
 * an algorithm name run through a case fold would stop matching with no error
 * anywhere. Protocol names are US-ASCII by RFC 4251, so they are converted a
 * byte at a time and compared with String.equals, which is code-point equality
 * and carries no locale.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Ascii {

    private Ascii() {
    }

    /** Truncates to the low 8 bits; callers pass names that are ASCII by specification. */
    public static byte[] toBytes(String s) {
        byte[] b = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            b[i] = (byte) s.charAt(i);
        }
        return b;
    }

    public static String fromBytes(byte[] b) {
        return fromBytes(b, 0, b.length);
    }

    public static String fromBytes(byte[] b, int offset, int length) {
        char[] c = new char[length];
        for (int i = 0; i < length; i++) {
            c[i] = (char) (b[offset + i] & 0xff);
        }
        return new String(c);
    }
}
