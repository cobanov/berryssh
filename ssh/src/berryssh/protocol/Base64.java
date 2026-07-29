package berryssh.protocol;

import java.io.IOException;

/**
 * RFC 4648 base64.
 *
 * CLDC 1.1 has no encoder, and SSH needs one in the places a human has to read
 * or type a key: the SHA-256 host key fingerprint OpenSSH prints, and the
 * `ssh-ed25519 AAAA...` line from an authorized_keys or known_hosts file.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Base64 {

    private static final String ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private Base64() {
    }

    /** Encodes with '=' padding. */
    public static String encode(byte[] data) {
        return encode(data, true);
    }

    /**
     * Encodes without padding, which is the form OpenSSH prints fingerprints
     * in — `SHA256:` followed by 43 characters and no trailing '='.
     */
    public static String encodeUnpadded(byte[] data) {
        return encode(data, false);
    }

    private static String encode(byte[] data, boolean pad) {
        StringBuffer sb = new StringBuffer((data.length + 2) / 3 * 4);
        int i = 0;
        while (i + 3 <= data.length) {
            int v = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8) | (data[i + 2] & 0xff);
            sb.append(ALPHABET.charAt((v >>> 18) & 0x3f));
            sb.append(ALPHABET.charAt((v >>> 12) & 0x3f));
            sb.append(ALPHABET.charAt((v >>> 6) & 0x3f));
            sb.append(ALPHABET.charAt(v & 0x3f));
            i += 3;
        }
        int left = data.length - i;
        if (left == 1) {
            int v = (data[i] & 0xff) << 16;
            sb.append(ALPHABET.charAt((v >>> 18) & 0x3f));
            sb.append(ALPHABET.charAt((v >>> 12) & 0x3f));
            if (pad) {
                sb.append('=');
                sb.append('=');
            }
        } else if (left == 2) {
            int v = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8);
            sb.append(ALPHABET.charAt((v >>> 18) & 0x3f));
            sb.append(ALPHABET.charAt((v >>> 12) & 0x3f));
            sb.append(ALPHABET.charAt((v >>> 6) & 0x3f));
            if (pad) {
                sb.append('=');
            }
        }
        return sb.toString();
    }

    /** Decodes, tolerating missing padding and embedded whitespace. */
    public static byte[] decode(String text) throws IOException {
        int[] symbols = new int[text.length()];
        int count = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '=' || c == ' ' || c == '\r' || c == '\n' || c == '\t') {
                continue;
            }
            int v = ALPHABET.indexOf(c);
            if (v < 0) {
                throw new SshException("not base64: '" + c + "'");
            }
            symbols[count++] = v;
        }
        if (count % 4 == 1) {
            throw new SshException("base64 of an impossible length");
        }

        byte[] out = new byte[count * 3 / 4];
        int o = 0;
        int i = 0;
        while (count - i >= 4) {
            int v = (symbols[i] << 18) | (symbols[i + 1] << 12) | (symbols[i + 2] << 6) | symbols[i + 3];
            out[o++] = (byte) (v >>> 16);
            out[o++] = (byte) (v >>> 8);
            out[o++] = (byte) v;
            i += 4;
        }
        int left = count - i;
        if (left == 2) {
            int v = (symbols[i] << 18) | (symbols[i + 1] << 12);
            out[o++] = (byte) (v >>> 16);
        } else if (left == 3) {
            int v = (symbols[i] << 18) | (symbols[i + 1] << 12) | (symbols[i + 2] << 6);
            out[o++] = (byte) (v >>> 16);
            out[o++] = (byte) (v >>> 8);
        }
        return out;
    }
}
