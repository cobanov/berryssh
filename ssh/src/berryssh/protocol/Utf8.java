package berryssh.protocol;

/**
 * UTF-8, done by hand.
 *
 * RFC 4252 says usernames and passwords go on the wire as UTF-8, and the
 * device's default encoding is ISO8859_1 — so `String.getBytes()` would send
 * something else entirely and the platform offers no way to ask for UTF-8 that
 * is dependable across CLDC implementations.
 *
 * This is not a theoretical concern for the intended user. A Turkish password
 * containing ç, ğ, ı, ö, ş or ü encodes to one byte per character under
 * ISO8859_1 and two under UTF-8; the server would compare the wrong bytes and
 * report nothing more than a failed login.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Utf8 {

    private Utf8() {
    }

    public static byte[] encode(String s) {
        int length = 0;
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c < 0x80) {
                length += 1;
            } else if (c < 0x800) {
                length += 2;
            } else if (isHighSurrogate(c) && i + 1 < s.length()
                    && isLowSurrogate(s.charAt(i + 1))) {
                length += 4;
                i++;
            } else {
                length += 3;
            }
        }

        byte[] out = new byte[length];
        int at = 0;
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c < 0x80) {
                out[at++] = (byte) c;
            } else if (c < 0x800) {
                out[at++] = (byte) (0xc0 | (c >> 6));
                out[at++] = (byte) (0x80 | (c & 0x3f));
            } else if (isHighSurrogate(c) && i + 1 < s.length()
                    && isLowSurrogate(s.charAt(i + 1))) {
                // A code point above the basic plane is two chars in Java and
                // one four-byte sequence here.
                int codePoint = 0x10000 + ((c - 0xd800) << 10) + (s.charAt(i + 1) - 0xdc00);
                i++;
                out[at++] = (byte) (0xf0 | (codePoint >> 18));
                out[at++] = (byte) (0x80 | ((codePoint >> 12) & 0x3f));
                out[at++] = (byte) (0x80 | ((codePoint >> 6) & 0x3f));
                out[at++] = (byte) (0x80 | (codePoint & 0x3f));
            } else {
                out[at++] = (byte) (0xe0 | (c >> 12));
                out[at++] = (byte) (0x80 | ((c >> 6) & 0x3f));
                out[at++] = (byte) (0x80 | (c & 0x3f));
            }
        }
        return out;
    }

    /**
     * Decodes, substituting U+FFFD for anything malformed.
     *
     * Replacing rather than throwing is deliberate: this decodes server banners
     * and terminal output, where one bad byte should cost one character and not
     * the session.
     */
    public static String decode(byte[] b, int offset, int length) {
        char[] out = new char[length * 2];
        int at = 0;
        int i = offset;
        int end = offset + length;
        while (i < end) {
            int c = b[i++] & 0xff;
            int codePoint;
            int extra;
            if (c < 0x80) {
                out[at++] = (char) c;
                continue;
            } else if ((c & 0xe0) == 0xc0) {
                codePoint = c & 0x1f;
                extra = 1;
            } else if ((c & 0xf0) == 0xe0) {
                codePoint = c & 0x0f;
                extra = 2;
            } else if ((c & 0xf8) == 0xf0) {
                codePoint = c & 0x07;
                extra = 3;
            } else {
                out[at++] = '�';
                continue;
            }

            if (i + extra > end) {
                out[at++] = '�';
                break;
            }
            boolean valid = true;
            for (int j = 0; j < extra; j++) {
                int next = b[i + j] & 0xff;
                if ((next & 0xc0) != 0x80) {
                    valid = false;
                    break;
                }
                codePoint = (codePoint << 6) | (next & 0x3f);
            }
            if (!valid) {
                out[at++] = '�';
                continue;
            }
            i += extra;

            if (codePoint > 0xffff) {
                codePoint -= 0x10000;
                out[at++] = (char) (0xd800 + (codePoint >> 10));
                out[at++] = (char) (0xdc00 + (codePoint & 0x3ff));
            } else {
                out[at++] = (char) codePoint;
            }
        }
        return new String(out, 0, at);
    }

    public static String decode(byte[] b) {
        return decode(b, 0, b.length);
    }

    private static boolean isHighSurrogate(int c) {
        return c >= 0xd800 && c <= 0xdbff;
    }

    private static boolean isLowSurrogate(int c) {
        return c >= 0xdc00 && c <= 0xdfff;
    }
}
