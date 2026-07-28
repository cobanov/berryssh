package berryssh.crypto;

/**
 * FIPS 180-4 SHA-256.
 *
 * CLDC 1.1 has no java.security, so the hash is implemented here. Written for
 * -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class SHA256 {

    public static final int DIGEST_LENGTH = 32;
    private static final int BLOCK_LENGTH = 64;

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private final int[] h = new int[8];
    private final int[] w = new int[64];
    private final byte[] buffer = new byte[BLOCK_LENGTH];
    private int bufferLength;
    private long byteCount;

    public SHA256() {
        reset();
    }

    public void reset() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        bufferLength = 0;
        byteCount = 0;
    }

    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    public void update(byte[] input, int offset, int length) {
        byteCount += length;
        while (length > 0) {
            int take = BLOCK_LENGTH - bufferLength;
            if (take > length) {
                take = length;
            }
            System.arraycopy(input, offset, buffer, bufferLength, take);
            bufferLength += take;
            offset += take;
            length -= take;
            if (bufferLength == BLOCK_LENGTH) {
                processBlock(buffer, 0);
                bufferLength = 0;
            }
        }
    }

    /** Appends the big-endian length padding and returns the digest. Resets the state. */
    public byte[] digest() {
        long bitCount = byteCount << 3;

        update(new byte[] { (byte) 0x80 }, 0, 1);
        byte[] zero = new byte[1];
        while (bufferLength != 56) {
            update(zero, 0, 1);
        }

        byte[] tail = new byte[8];
        for (int i = 0; i < 8; i++) {
            tail[i] = (byte) (bitCount >>> (56 - 8 * i));
        }
        // Feed the length directly: update() would fold it into byteCount.
        System.arraycopy(tail, 0, buffer, 56, 8);
        processBlock(buffer, 0);

        byte[] out = new byte[DIGEST_LENGTH];
        for (int i = 0; i < 8; i++) {
            out[4 * i] = (byte) (h[i] >>> 24);
            out[4 * i + 1] = (byte) (h[i] >>> 16);
            out[4 * i + 2] = (byte) (h[i] >>> 8);
            out[4 * i + 3] = (byte) h[i];
        }
        reset();
        return out;
    }

    public static byte[] hash(byte[] input) {
        SHA256 s = new SHA256();
        s.update(input, 0, input.length);
        return s.digest();
    }

    private void processBlock(byte[] block, int offset) {
        for (int i = 0; i < 16; i++) {
            int j = offset + 4 * i;
            w[i] = ((block[j] & 0xff) << 24) | ((block[j + 1] & 0xff) << 16)
                 | ((block[j + 2] & 0xff) << 8) | (block[j + 3] & 0xff);
        }
        for (int i = 16; i < 64; i++) {
            int x = w[i - 15];
            int y = w[i - 2];
            int s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
            int s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        int a = h[0], b = h[1], c = h[2], d = h[3];
        int e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            int s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            int ch = (e & f) ^ (~e & g);
            int t1 = hh + s1 + ch + K[i] + w[i];
            int s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int t2 = s0 + maj;

            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
}
