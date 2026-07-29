package berryssh.crypto;

/**
 * RFC 2104 HMAC over {@link SHA256}.
 *
 * CLDC 1.1 has no javax.crypto, so this is here for the same reason SHA256 is.
 * The only caller is the bridge handshake, which proves knowledge of a shared
 * key against a nonce it did not choose.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Hmac {

    /** SHA-256's block size, which is what the padding is measured in. */
    private static final int BLOCK_LENGTH = 64;

    private static final byte INNER_PAD = 0x36;
    private static final byte OUTER_PAD = 0x5c;

    private Hmac() {
    }

    /**
     * The tag for {@code message} under {@code key}.
     *
     * A key of any length is accepted, as RFC 2104 requires: one longer than a
     * block is hashed down first, and a shorter one is zero-padded up. That
     * matters here because the key is whatever passphrase a person chose, not
     * something generated to fit.
     */
    public static byte[] compute(byte[] key, byte[] message) {
        byte[] block = new byte[BLOCK_LENGTH];
        if (key.length > BLOCK_LENGTH) {
            byte[] shortened = SHA256.hash(key);
            System.arraycopy(shortened, 0, block, 0, shortened.length);
        } else {
            System.arraycopy(key, 0, block, 0, key.length);
        }

        byte[] inner = new byte[BLOCK_LENGTH];
        byte[] outer = new byte[BLOCK_LENGTH];
        for (int i = 0; i < BLOCK_LENGTH; i++) {
            inner[i] = (byte) (block[i] ^ INNER_PAD);
            outer[i] = (byte) (block[i] ^ OUTER_PAD);
        }

        SHA256 hash = new SHA256();
        hash.update(inner);
        hash.update(message);
        byte[] innerDigest = hash.digest();

        hash.reset();
        hash.update(outer);
        hash.update(innerDigest);
        return hash.digest();
    }

    // A tag comparison used to live here, on the argument that it belonged
    // next to the primitive. Nothing ever called it: the client proves a key
    // by producing a tag, and it is the bridge — which is Python — that has to
    // compare one. Bytes.equal is where the comparison the client does need
    // lives now.
}
