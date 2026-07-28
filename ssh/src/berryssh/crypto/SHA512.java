package berryssh.crypto;

/**
 * FIPS 180-4 SHA-512.
 *
 * Present because Ed25519 is defined over it (RFC 8032 §5.1); SSH itself uses
 * SHA-256 for the exchange hash. Structurally the same as {@link SHA256} with
 * 64-bit words, 80 rounds, and a 128-bit length field.
 *
 * Written for -source 1.3.
 */
public final class SHA512 {

    public static final int DIGEST_LENGTH = 64;
    private static final int BLOCK_LENGTH = 128;

    private static final long[] K = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    private final long[] h = new long[8];
    private final long[] w = new long[80];
    private final byte[] buffer = new byte[BLOCK_LENGTH];
    private int bufferLength;
    private long byteCount;

    public SHA512() {
        reset();
    }

    public void reset() {
        h[0] = 0x6a09e667f3bcc908L; h[1] = 0xbb67ae8584caa73bL;
        h[2] = 0x3c6ef372fe94f82bL; h[3] = 0xa54ff53a5f1d36f1L;
        h[4] = 0x510e527fade682d1L; h[5] = 0x9b05688c2b3e6c1fL;
        h[6] = 0x1f83d9abfb41bd6bL; h[7] = 0x5be0cd19137e2179L;
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
                processBlock(buffer);
                bufferLength = 0;
            }
        }
    }

    public byte[] digest() {
        long bitCount = byteCount << 3;

        update(new byte[] { (byte) 0x80 }, 0, 1);
        byte[] zero = new byte[1];
        while (bufferLength != 112) {
            update(zero, 0, 1);
        }

        // The length field is 128 bits; the high half is always zero for any
        // input this code will ever see, so only the low 64 bits are written.
        for (int i = 0; i < 8; i++) {
            buffer[112 + i] = 0;
        }
        for (int i = 0; i < 8; i++) {
            buffer[120 + i] = (byte) (bitCount >>> (56 - 8 * i));
        }
        processBlock(buffer);

        byte[] out = new byte[DIGEST_LENGTH];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                out[8 * i + j] = (byte) (h[i] >>> (56 - 8 * j));
            }
        }
        reset();
        return out;
    }

    public static byte[] hash(byte[] input) {
        SHA512 s = new SHA512();
        s.update(input, 0, input.length);
        return s.digest();
    }

    private void processBlock(byte[] block) {
        for (int i = 0; i < 16; i++) {
            long v = 0;
            for (int j = 0; j < 8; j++) {
                v = (v << 8) | (block[8 * i + j] & 0xffL);
            }
            w[i] = v;
        }
        for (int i = 16; i < 80; i++) {
            long x = w[i - 15];
            long y = w[i - 2];
            long s0 = rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >>> 7);
            long s1 = rotateRight(y, 19) ^ rotateRight(y, 61) ^ (y >>> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        long a = h[0], b = h[1], c = h[2], d = h[3];
        long e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 80; i++) {
            long s1 = rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41);
            long ch = (e & f) ^ (~e & g);
            long t1 = hh + s1 + ch + K[i] + w[i];
            long s0 = rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39);
            long maj = (a & b) ^ (a & c) ^ (b & c);
            long t2 = s0 + maj;

            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    /** CLDC 1.1 predates Long.rotateRight. */
    private static long rotateRight(long v, int n) {
        return (v >>> n) | (v << (64 - n));
    }
}
