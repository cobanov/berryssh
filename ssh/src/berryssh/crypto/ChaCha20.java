package berryssh.crypto;

/**
 * RFC 8439 ChaCha20 stream cipher.
 *
 * Chosen over AES deliberately: it is pure 32-bit add/xor/rotate with no
 * lookup tables, which is both fast and constant-time in plain Java on the
 * kind of CPU this targets. CLDC 1.1 has no javax.crypto to fall back on.
 *
 * Written for -source 1.3.
 */
public final class ChaCha20 {

    /** "expand 32-byte k" as four little-endian words. */
    private static final int[] SIGMA = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    private final int[] state = new int[16];
    private final int[] block = new int[16];
    private final byte[] keyStream = new byte[64];

    /**
     * @param key   32 bytes
     * @param nonce 12 bytes (RFC 8439 layout: 32-bit counter + 96-bit nonce)
     * @param counter initial block counter
     */
    public ChaCha20(byte[] key, byte[] nonce, int counter) {
        if (key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("nonce must be 12 bytes");
        }
        state[0] = SIGMA[0]; state[1] = SIGMA[1]; state[2] = SIGMA[2]; state[3] = SIGMA[3];
        for (int i = 0; i < 8; i++) {
            state[4 + i] = littleEndian(key, 4 * i);
        }
        state[12] = counter;
        for (int i = 0; i < 3; i++) {
            state[13 + i] = littleEndian(nonce, 4 * i);
        }
    }

    /** XORs {@code length} bytes of key stream into the buffer, in place. */
    public void process(byte[] data, int offset, int length) {
        int produced = 64;
        for (int i = 0; i < length; i++) {
            if (produced == 64) {
                nextKeyStream();
                produced = 0;
            }
            data[offset + i] ^= keyStream[produced++];
        }
    }

    /** Emits the next 64-byte key stream block and advances the counter. */
    private void nextKeyStream() {
        System.arraycopy(state, 0, block, 0, 16);

        for (int i = 0; i < 10; i++) {
            // Column rounds.
            quarterRound(0, 4, 8, 12);
            quarterRound(1, 5, 9, 13);
            quarterRound(2, 6, 10, 14);
            quarterRound(3, 7, 11, 15);
            // Diagonal rounds.
            quarterRound(0, 5, 10, 15);
            quarterRound(1, 6, 11, 12);
            quarterRound(2, 7, 8, 13);
            quarterRound(3, 4, 9, 14);
        }

        for (int i = 0; i < 16; i++) {
            int v = block[i] + state[i];
            keyStream[4 * i] = (byte) v;
            keyStream[4 * i + 1] = (byte) (v >>> 8);
            keyStream[4 * i + 2] = (byte) (v >>> 16);
            keyStream[4 * i + 3] = (byte) (v >>> 24);
        }
        state[12]++;
    }

    private void quarterRound(int a, int b, int c, int d) {
        block[a] += block[b];
        block[d] = rotateLeft(block[d] ^ block[a], 16);
        block[c] += block[d];
        block[b] = rotateLeft(block[b] ^ block[c], 12);
        block[a] += block[b];
        block[d] = rotateLeft(block[d] ^ block[a], 8);
        block[c] += block[d];
        block[b] = rotateLeft(block[b] ^ block[c], 7);
    }

    /** CLDC 1.1 predates Integer.rotateLeft. */
    private static int rotateLeft(int v, int n) {
        return (v << n) | (v >>> (32 - n));
    }

    private static int littleEndian(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
             | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }
}
