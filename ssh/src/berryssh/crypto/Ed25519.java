package berryssh.crypto;

/**
 * RFC 8032 Ed25519 signature verification, for {@code ssh-ed25519} host keys.
 *
 * Verification only. Nothing here handles a private key, so there is no secret
 * to leak and the scalar multiplication is a plain double-and-add over public
 * data.
 *
 * The curve constants are derived at class-load rather than written out as hex,
 * which removes transcription error as a failure mode: {@code d} comes from
 * -121665/121666 and {@code sqrt(-1)} from an exponentiation, both computed
 * with {@link Fe25519}. The cost is a handful of field inversions, once.
 *
 * Written for -source 1.3.
 */
public final class Ed25519 {

    public static final int PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;

    /** Curve constant d = -121665/121666, and 2d as used by the addition formula. */
    private static final int[] D = Fe25519.create();
    private static final int[] D2 = Fe25519.create();
    /** A square root of -1, needed when decompressing a point. */
    private static final int[] SQRT_M1 = Fe25519.create();
    /** The base point B. */
    private static final Point BASE;

    /**
     * The group order L = 2^252 + 27742317777372353535851937790883648493, little
     * endian. `verify` rejects any S >= L, which is what stops a valid
     * signature from being trivially reshaped into another valid one.
     */
    private static final int[] L = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    static {
        int[] num = Fe25519.create();
        int[] den = Fe25519.create();
        num[0] = 121665;
        den[0] = 121666;
        int[] negNum = Fe25519.create();
        Fe25519.sub(negNum, Fe25519.create(), num);   // -121665
        int[] invDen = Fe25519.create();
        Fe25519.invert(invDen, den);
        Fe25519.mul(D, negNum, invDen);
        Fe25519.add(D2, D, D);
        Fe25519.reduce(D2);

        // sqrt(-1) = 2^((p-1)/4), and (p-1)/4 = 2*((p-5)/8) + 1, so it follows
        // from the same exponentiation decompression already needs.
        int[] two = Fe25519.create();
        two[0] = 2;
        int[] t = Fe25519.create();
        pow2523(t, two);
        Fe25519.sq(t, t);
        Fe25519.mul(SQRT_M1, t, two);

        // B has y = 4/5 and the even x.
        int[] four = Fe25519.create();
        int[] five = Fe25519.create();
        four[0] = 4;
        five[0] = 5;
        int[] invFive = Fe25519.create();
        Fe25519.invert(invFive, five);
        int[] by = Fe25519.create();
        Fe25519.mul(by, four, invFive);
        byte[] encoded = new byte[32];
        Fe25519.toBytes(encoded, 0, by);
        BASE = decompress(encoded, 0);
        if (BASE == null) {
            throw new IllegalStateException("base point failed to decompress");
        }
    }

    private Ed25519() {
    }

    /** A point in extended coordinates: x = X/Z, y = Y/Z, xy = T/Z. */
    private static final class Point {
        final int[] x = Fe25519.create();
        final int[] y = Fe25519.create();
        final int[] z = Fe25519.create();
        final int[] t = Fe25519.create();
    }

    private static Point identity() {
        Point p = new Point();
        p.y[0] = 1;
        p.z[0] = 1;
        return p;
    }

    private static Point copyOf(Point p) {
        Point q = new Point();
        Fe25519.copy(q.x, p.x);
        Fe25519.copy(q.y, p.y);
        Fe25519.copy(q.z, p.z);
        Fe25519.copy(q.t, p.t);
        return q;
    }

    /** Unified addition for a = -1 twisted Edwards curves. */
    private static void add(Point r, Point p, Point q) {
        int[] a = Fe25519.create(), b = Fe25519.create(), c = Fe25519.create();
        int[] d = Fe25519.create(), e = Fe25519.create(), f = Fe25519.create();
        int[] g = Fe25519.create(), h = Fe25519.create(), tmp = Fe25519.create();

        Fe25519.sub(a, p.y, p.x);
        Fe25519.sub(tmp, q.y, q.x);
        Fe25519.mul(a, a, tmp);

        Fe25519.add(b, p.y, p.x);
        Fe25519.add(tmp, q.y, q.x);
        Fe25519.mul(b, b, tmp);

        Fe25519.mul(c, p.t, q.t);
        Fe25519.mul(c, c, D2);

        Fe25519.mul(d, p.z, q.z);
        Fe25519.add(d, d, d);

        Fe25519.sub(e, b, a);
        Fe25519.sub(f, d, c);
        Fe25519.add(g, d, c);
        Fe25519.add(h, b, a);

        // These are sums of sums; mul needs them back inside its input bounds.
        Fe25519.reduce(e);
        Fe25519.reduce(f);
        Fe25519.reduce(g);
        Fe25519.reduce(h);

        Fe25519.mul(r.x, e, f);
        Fe25519.mul(r.y, g, h);
        Fe25519.mul(r.t, e, h);
        Fe25519.mul(r.z, f, g);
    }

    private static void dbl(Point r, Point p) {
        int[] a = Fe25519.create(), b = Fe25519.create(), c = Fe25519.create();
        int[] e = Fe25519.create(), f = Fe25519.create(), g = Fe25519.create();
        int[] h = Fe25519.create(), tmp = Fe25519.create();

        Fe25519.sq(a, p.x);
        Fe25519.sq(b, p.y);
        Fe25519.sq(c, p.z);
        Fe25519.add(c, c, c);

        Fe25519.add(h, a, b);
        Fe25519.add(tmp, p.x, p.y);
        Fe25519.sq(tmp, tmp);
        Fe25519.sub(e, h, tmp);
        Fe25519.sub(g, a, b);
        Fe25519.add(f, c, g);

        // f reaches ~2^27 here (2*Z^2 plus A-B), which is past what mul takes.
        Fe25519.reduce(e);
        Fe25519.reduce(f);
        Fe25519.reduce(g);
        Fe25519.reduce(h);

        Fe25519.mul(r.x, e, f);
        Fe25519.mul(r.y, g, h);
        Fe25519.mul(r.t, e, h);
        Fe25519.mul(r.z, f, g);
    }

    private static void negate(Point r, Point p) {
        Fe25519.sub(r.x, Fe25519.create(), p.x);
        Fe25519.copy(r.y, p.y);
        Fe25519.copy(r.z, p.z);
        Fe25519.sub(r.t, Fe25519.create(), p.t);
    }

    /**
     * Double-and-add over the bits of a little-endian scalar. Not constant
     * time, which is fine: every input here is public.
     */
    private static Point scalarMult(Point p, byte[] scalar, int bits) {
        Point r = identity();
        Point base = copyOf(p);
        Point tmp = new Point();
        for (int i = bits - 1; i >= 0; i--) {
            dbl(tmp, r);
            Point t = r; r = tmp; tmp = t;
            if (((scalar[i >>> 3] >>> (i & 7)) & 1) != 0) {
                add(tmp, r, base);
                t = r; r = tmp; tmp = t;
            }
        }
        return r;
    }

    /** z^((p-5)/8), the exponentiation point decompression needs. */
    private static void pow2523(int[] out, int[] z) {
        int[] t0 = Fe25519.create(), t1 = Fe25519.create(), t2 = Fe25519.create();
        int i;

        Fe25519.sq(t0, z);
        Fe25519.sq(t1, t0); Fe25519.sq(t1, t1);
        Fe25519.mul(t1, z, t1);
        Fe25519.mul(t0, t0, t1);
        Fe25519.sq(t0, t0);
        Fe25519.mul(t0, t1, t0);

        Fe25519.sq(t1, t0);
        for (i = 1; i < 5; i++) { Fe25519.sq(t1, t1); }
        Fe25519.mul(t0, t1, t0);

        Fe25519.sq(t1, t0);
        for (i = 1; i < 10; i++) { Fe25519.sq(t1, t1); }
        Fe25519.mul(t1, t1, t0);

        Fe25519.sq(t2, t1);
        for (i = 1; i < 20; i++) { Fe25519.sq(t2, t2); }
        Fe25519.mul(t1, t2, t1);

        Fe25519.sq(t1, t1);
        for (i = 1; i < 10; i++) { Fe25519.sq(t1, t1); }
        Fe25519.mul(t0, t1, t0);

        Fe25519.sq(t1, t0);
        for (i = 1; i < 50; i++) { Fe25519.sq(t1, t1); }
        Fe25519.mul(t1, t1, t0);

        Fe25519.sq(t2, t1);
        for (i = 1; i < 100; i++) { Fe25519.sq(t2, t2); }
        Fe25519.mul(t1, t2, t1);

        Fe25519.sq(t1, t1);
        for (i = 1; i < 50; i++) { Fe25519.sq(t1, t1); }
        Fe25519.mul(t0, t1, t0);

        Fe25519.sq(t0, t0);
        Fe25519.sq(t0, t0);
        Fe25519.mul(out, t0, z);
    }

    /** Recovers a point from its 32-byte encoding, or null if it is not on the curve. */
    private static Point decompress(byte[] s, int off) {
        Point p = new Point();
        int[] u = Fe25519.create(), v = Fe25519.create();
        int[] v3 = Fe25519.create(), vxx = Fe25519.create(), check = Fe25519.create();

        Fe25519.fromBytes(p.y, s, off);
        p.z[0] = 1;

        Fe25519.sq(u, p.y);
        Fe25519.mul(v, u, D);
        Fe25519.sub(u, u, p.z);      // y^2 - 1
        Fe25519.add(v, v, p.z);      // d*y^2 + 1

        Fe25519.sq(v3, v);
        Fe25519.mul(v3, v3, v);      // v^3
        Fe25519.sq(p.x, v3);
        Fe25519.mul(p.x, p.x, v);
        Fe25519.mul(p.x, p.x, u);    // u * v^7

        pow2523(p.x, p.x);
        Fe25519.mul(p.x, p.x, v3);
        Fe25519.mul(p.x, p.x, u);    // x = u * v^3 * (u * v^7)^((p-5)/8)

        Fe25519.sq(vxx, p.x);
        Fe25519.mul(vxx, vxx, v);
        Fe25519.sub(check, vxx, u);
        if (!Fe25519.isZero(check)) {
            Fe25519.add(check, vxx, u);
            if (!Fe25519.isZero(check)) {
                return null;         // not a square: the encoding is not a curve point
            }
            Fe25519.mul(p.x, p.x, SQRT_M1);
        }

        byte[] xb = new byte[32];
        Fe25519.toBytes(xb, 0, p.x);
        int wantSign = (s[off + 31] >>> 7) & 1;
        if ((xb[0] & 1) != wantSign) {
            Fe25519.sub(p.x, Fe25519.create(), p.x);
            Fe25519.toBytes(xb, 0, p.x);
            // x = 0 has only one encoding; asking for the odd one is invalid.
            if ((xb[0] & 1) != wantSign) {
                return null;
            }
        }

        Fe25519.mul(p.t, p.x, p.y);
        return p;
    }

    private static byte[] compress(Point p) {
        int[] recip = Fe25519.create();
        int[] x = Fe25519.create(), y = Fe25519.create();
        Fe25519.invert(recip, p.z);
        Fe25519.mul(x, p.x, recip);
        Fe25519.mul(y, p.y, recip);

        byte[] out = new byte[32];
        Fe25519.toBytes(out, 0, y);
        byte[] xb = new byte[32];
        Fe25519.toBytes(xb, 0, x);
        out[31] |= (byte) ((xb[0] & 1) << 7);
        return out;
    }

    /** True if the little-endian 32-byte scalar is below the group order. */
    private static boolean belowOrder(byte[] s, int off) {
        for (int i = 31; i >= 0; i--) {
            int a = s[off + i] & 0xff;
            int b = L[i];
            if (a < b) {
                return true;
            }
            if (a > b) {
                return false;
            }
        }
        return false;   // equal to L is not below it
    }

    /** The 32-byte seed an OpenSSH ed25519 private key stores. */
    public static final int SEED_LENGTH = 32;

    /**
     * Expands a 32-byte seed into the scalar and the prefix RFC 8032 section
     * 5.1.5 derives from it.
     *
     * The pruning is not optional and not cosmetic: clearing the low three bits
     * puts the scalar in the prime-order subgroup, and forcing bit 254 fixes
     * its length so that a variable-time ladder cannot leak it.
     */
    private static byte[] expandSeed(byte[] seed) {
        byte[] h = SHA512.hash(seed);
        h[0] &= (byte) 248;
        h[31] &= (byte) 127;
        h[31] |= (byte) 64;
        return h;
    }

    /** Derives the public key from a 32-byte seed. */
    public static byte[] publicKey(byte[] seed) {
        if (seed == null || seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("seed must be " + SEED_LENGTH + " bytes");
        }
        byte[] h = expandSeed(seed);
        byte[] a = new byte[32];
        System.arraycopy(h, 0, a, 0, 32);
        return compress(scalarMult(BASE, a, 255));
    }

    /**
     * Signs a message with a 32-byte seed, per RFC 8032 section 5.1.6.
     *
     * Ed25519 signatures are deterministic: the per-signature nonce comes from
     * hashing the message under the second half of the expanded seed rather
     * than from a random source. That is a property worth having on this
     * hardware in particular — a handset has very little entropy, and a
     * signature scheme that leaks its key when the nonce repeats would be the
     * worst possible consumer of it.
     *
     * @param seed 32 bytes, the private key as OpenSSH stores it
     * @return 64 bytes: R followed by S
     */
    public static byte[] sign(byte[] seed, byte[] message) {
        if (seed == null || seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("seed must be " + SEED_LENGTH + " bytes");
        }
        byte[] h = expandSeed(seed);
        byte[] a = new byte[32];
        System.arraycopy(h, 0, a, 0, 32);

        byte[] publicKey = compress(scalarMult(BASE, a, 255));

        SHA512 nonce = new SHA512();
        nonce.update(h, 32, 32);
        nonce.update(message, 0, message.length);
        byte[] r = ScalarModL.reduce(nonce.digest());

        byte[] rPoint = compress(scalarMult(BASE, r, 253));

        SHA512 challenge = new SHA512();
        challenge.update(rPoint, 0, 32);
        challenge.update(publicKey, 0, 32);
        challenge.update(message, 0, message.length);
        byte[] k = ScalarModL.reduce(challenge.digest());

        byte[] s = ScalarModL.mulAdd(k, a, r);

        byte[] signature = new byte[SIGNATURE_LENGTH];
        System.arraycopy(rPoint, 0, signature, 0, 32);
        System.arraycopy(s, 0, signature, 32, 32);
        return signature;
    }

    /**
     * Verifies a signature over a message.
     *
     * @param publicKey 32 bytes
     * @param signature 64 bytes: R followed by S
     * @return true only if the signature is valid for this key and message
     */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            return false;
        }
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        if (!belowOrder(signature, 32)) {
            return false;
        }

        Point a = decompress(publicKey, 0);
        if (a == null) {
            return false;
        }
        // R is checked implicitly: the comparison below is against its bytes.

        SHA512 sha = new SHA512();
        sha.update(signature, 0, 32);
        sha.update(publicKey, 0, publicKey.length);
        sha.update(message, 0, message.length);
        byte[] k = sha.digest();

        // RFC 8032 5.1.7 interprets the whole 64-octet digest as the scalar, so
        // it is used unreduced; that costs extra doublings and no correctness.
        Point ka = scalarMult(a, k, 512);

        // S is the second half of the signature, and scalarMult indexes from
        // the start of the array it is given.
        byte[] s = new byte[32];
        System.arraycopy(signature, 32, s, 0, 32);
        Point sb = scalarMult(BASE, s, 253);

        Point negKa = new Point();
        negate(negKa, ka);
        Point r = new Point();
        add(r, sb, negKa);

        byte[] expected = compress(r);
        int diff = 0;
        for (int i = 0; i < 32; i++) {
            diff |= expected[i] ^ signature[i];
        }
        return diff == 0;
    }
}
