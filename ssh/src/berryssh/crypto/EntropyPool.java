package berryssh.crypto;

/**
 * The random source for key material.
 *
 * CLDC 1.1 has no SecureRandom, and java.util.Random is a 48-bit LCG seeded
 * from the clock — an attacker who knows the connection time to within a second
 * has a few thousand candidate seeds, which is not a key. RIM's random is a
 * protected API and therefore unavailable to us by design. So the pool is built
 * from what the platform will actually give up.
 *
 * The construction is a SHA-256 DRBG. Samples are absorbed into a 32-byte
 * state; generation ratchets that state forward before each output block and
 * once more afterwards, so the state left in memory cannot reproduce anything
 * already handed out.
 *
 * The constructors are deterministic on purpose — the platform sampling is a
 * separate call rather than something a constructor does behind the caller's
 * back. That keeps the DRBG itself testable, and it costs nothing, because the
 * platform values are not credited as entropy anyway. Ordinary callers want
 * {@link #seed}.
 *
 * <b>The entropy estimate is a judgement, not a measurement.</b> Each jitter
 * sample is credited 2 bits, deliberately below what the technique is generally
 * thought to yield, because the cost of over-crediting is a predictable private
 * key. {@link #isSeeded} gates key material on {@link #REQUIRED_BITS}, and
 * refusing to generate is the right behaviour when the pool is short — quietly
 * returning weak bytes is the failure nobody would ever notice.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class EntropyPool {

    /** A full-strength key's worth. Nothing is handed out before the pool reaches it. */
    public static final int REQUIRED_BITS = 256;

    /** Credited per jitter sample. See the note above on why this is pessimistic. */
    private static final int BITS_PER_JITTER_SAMPLE = 2;

    /** Credited per keystroke. The user's timing is the best source a handset has. */
    private static final int BITS_PER_KEYSTROKE = 2;

    private static final byte ABSORB = 0x00;
    private static final byte RATCHET = 0x01;
    private static final byte OUTPUT = 0x02;
    private static final byte FINALISE = 0x03;

    private final byte[] state = new byte[SHA256.DIGEST_LENGTH];
    private int bits;

    /** An empty, uncredited pool. */
    public EntropyPool() {
    }

    /**
     * Starts from a seed saved by a previous run, which is credited in full.
     *
     * A handset has very little entropy available the first time it is asked
     * and rather more once it has been used, so a client should keep the 32
     * bytes from {@link #exportSeed} in RMS and hand them back here at startup.
     * That makes the expensive cold start a one-off rather than a per-launch
     * cost. The store is app-private, so a seed that came out of a seeded pool
     * is worth what it was worth when it was written.
     */
    public EntropyPool(byte[] storedSeed) {
        addSample(storedSeed);
        credit(REQUIRED_BITS);
    }

    /** Conservative estimate of the entropy absorbed so far, capped at the requirement. */
    public int seededBits() {
        return bits;
    }

    public boolean isSeeded() {
        return bits >= REQUIRED_BITS;
    }

    /** Absorbs data without crediting it. For values an attacker might guess. */
    public void addSample(byte[] data) {
        SHA256 h = new SHA256();
        h.update(state);
        h.update(new byte[] { ABSORB });
        h.update(data);
        byte[] next = h.digest();
        System.arraycopy(next, 0, state, 0, state.length);
    }

    /**
     * Absorbs what the platform will say about itself. Deliberately uncredited:
     * the clock and the heap sizes are all guessable, so this improves the
     * starting position without being entropy.
     */
    public void addPlatformState() {
        addSample(longToBytes(System.currentTimeMillis()));
        addSample(longToBytes(Runtime.getRuntime().freeMemory()));
        addSample(longToBytes(Runtime.getRuntime().totalMemory()));
        addSample(longToBytes(System.identityHashCode(this)));
        addSample(longToBytes(System.identityHashCode(new Object())));
    }

    /**
     * Absorbs a keystroke and credits it.
     *
     * The unpredictable part is when the key was pressed rather than which key
     * it was, so both go in but the credit is for the timing.
     */
    public void addKeystroke(int keyCode) {
        addSample(longToBytes(System.currentTimeMillis()));
        addSample(longToBytes(keyCode));
        addSample(longToBytes(Runtime.getRuntime().freeMemory()));
        credit(BITS_PER_KEYSTROKE);
    }

    /**
     * Collects timing jitter, blocking for roughly one clock tick per sample.
     *
     * The loop counts how many iterations fit between two millisecond ticks.
     * That count moves with scheduling, interrupts and cache state, and its low
     * bits are the part worth having. CLDC has no nanoTime, so this
     * millisecond-resolution version is the finest measurement available.
     */
    public void harvestJitter(int samples) {
        for (int i = 0; i < samples; i++) {
            long tick = System.currentTimeMillis();
            long count = 0;
            while (System.currentTimeMillis() == tick) {
                count++;
                // Yielding mixes the scheduler into the count rather than
                // leaving it a pure measure of this CPU's speed.
                if ((count & 0xff) == 0) {
                    Thread.yield();
                }
            }
            addSample(longToBytes(count));
            addSample(longToBytes(System.currentTimeMillis()));
            credit(BITS_PER_JITTER_SAMPLE);
        }
    }

    /**
     * Brings the pool up to {@link #REQUIRED_BITS}, blocking while it does.
     *
     * From cold this costs about a tenth of a second, so it belongs at startup
     * rather than at connect time. From a stored seed it returns at once.
     */
    public void seed() {
        addPlatformState();
        while (!isSeeded()) {
            harvestJitter(16);
        }
    }

    /**
     * Returns key material, ratcheting the state so that recovering it
     * afterwards reveals nothing about what was returned.
     *
     * @throws IllegalStateException if the pool has not reached {@link #REQUIRED_BITS}
     */
    public byte[] nextBytes(int length) {
        if (!isSeeded()) {
            throw new IllegalStateException(
                "random source has " + bits + " of " + REQUIRED_BITS + " bits; refusing to generate");
        }
        byte[] out = new byte[length];
        int filled = 0;
        while (filled < length) {
            ratchet(RATCHET);

            SHA256 h = new SHA256();
            h.update(state);
            h.update(new byte[] { OUTPUT });
            byte[] block = h.digest();

            int take = length - filled;
            if (take > block.length) {
                take = block.length;
            }
            System.arraycopy(block, 0, out, filled, take);
            filled += take;
        }
        // Without this the state on the way out still reproduces the last block.
        ratchet(FINALISE);
        return out;
    }

    /**
     * Produces 32 bytes to store for the next run. It costs the pool nothing
     * that an ordinary generation would not, because it is one.
     */
    public byte[] exportSeed() {
        return nextBytes(SHA256.DIGEST_LENGTH);
    }

    private void ratchet(byte tag) {
        SHA256 h = new SHA256();
        h.update(state);
        h.update(new byte[] { tag });
        byte[] next = h.digest();
        System.arraycopy(next, 0, state, 0, state.length);
    }

    private void credit(int n) {
        if (bits < REQUIRED_BITS) {
            bits += n;
            if (bits > REQUIRED_BITS) {
                bits = REQUIRED_BITS;
            }
        }
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (v >>> (8 * i));
        }
        return b;
    }
}
