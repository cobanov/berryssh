package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.Bytes;
import berryssh.crypto.ChaCha20;
import berryssh.crypto.Poly1305;

/**
 * chacha20-poly1305@openssh.com, which is not the RFC 8439 AEAD.
 *
 * The difference that matters is the length field. A packet's length has to be
 * read before the rest of the packet can be, so it cannot be inside the
 * authenticated ciphertext — but leaving it in the clear leaks the size of
 * every keystroke and every window update. OpenSSH's answer is a second key
 * used for nothing else: the length is encrypted on its own with K_1, and the
 * Poly1305 tag then covers both the encrypted length and the encrypted body, so
 * a length an attacker has tampered with still fails authentication.
 *
 * Two other details are easy to get wrong and silent when wrong:
 *
 * The key halves are the other way round from how they read. The first 32 bytes
 * of the 64 are K_2, which encrypts the body; the second 32 are K_1, for the
 * length. Swapping them produces a cipher that is entirely self-consistent and
 * cannot talk to anything.
 *
 * The Poly1305 key is block zero of the body key stream, and the body itself
 * starts at block one. Encrypting the body from block zero would reuse the key
 * stream that produced the authentication key.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class PacketCipher {

    /** 512 bits: two 256-bit keys, per direction. */
    public static final int KEY_LENGTH = 64;

    public static final int TAG_LENGTH = Poly1305.TAG_LENGTH;

    public static final int LENGTH_FIELD_LENGTH = 4;

    /** The cipher is a stream cipher; 8 is what RFC 4253 uses when there is no block. */
    public static final int BLOCK_SIZE = 8;

    private static final int POLY1305_KEY_LENGTH = 32;

    private final byte[] bodyKey;
    private final byte[] lengthKey;

    public PacketCipher(byte[] key) {
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("key must be " + KEY_LENGTH + " bytes");
        }
        bodyKey = new byte[32];
        lengthKey = new byte[32];
        System.arraycopy(key, 0, bodyKey, 0, 32);
        System.arraycopy(key, 32, lengthKey, 0, 32);
    }

    /**
     * Encrypts a packet body and returns the bytes to put on the wire:
     * the encrypted length, the encrypted body, then the tag.
     */
    public byte[] seal(long sequence, byte[] body) {
        byte[] nonce = nonce(sequence);

        byte[] out = new byte[LENGTH_FIELD_LENGTH + body.length + TAG_LENGTH];
        out[0] = (byte) (body.length >>> 24);
        out[1] = (byte) (body.length >>> 16);
        out[2] = (byte) (body.length >>> 8);
        out[3] = (byte) body.length;
        new ChaCha20(lengthKey, nonce, 0).process(out, 0, LENGTH_FIELD_LENGTH);

        System.arraycopy(body, 0, out, LENGTH_FIELD_LENGTH, body.length);
        new ChaCha20(bodyKey, nonce, 1).process(out, LENGTH_FIELD_LENGTH, body.length);

        byte[] tag = authenticate(nonce, out, LENGTH_FIELD_LENGTH + body.length);
        System.arraycopy(tag, 0, out, LENGTH_FIELD_LENGTH + body.length, TAG_LENGTH);
        return out;
    }

    /**
     * Decrypts the length field alone, so the rest of the packet can be read.
     *
     * The value this returns is not yet trustworthy — nothing has been
     * authenticated at this point. It is only safe to use for deciding how many
     * bytes to read, and the caller must bound it before allocating anything.
     */
    public long peekLength(long sequence, byte[] encryptedLength) {
        byte[] plain = new byte[LENGTH_FIELD_LENGTH];
        System.arraycopy(encryptedLength, 0, plain, 0, LENGTH_FIELD_LENGTH);
        new ChaCha20(lengthKey, nonce(sequence), 0).process(plain, 0, LENGTH_FIELD_LENGTH);
        return ((long) (plain[0] & 0xff) << 24)
             | ((long) (plain[1] & 0xff) << 16)
             | ((long) (plain[2] & 0xff) << 8)
             | (long) (plain[3] & 0xff);
    }

    /**
     * Authenticates and then decrypts. In that order, and not the other way:
     * plaintext derived from an unauthenticated packet must never reach the
     * parser above, or the tag is decoration.
     */
    public byte[] open(long sequence, byte[] encryptedLength, byte[] encryptedBody, byte[] tag)
            throws IOException {
        byte[] nonce = nonce(sequence);

        byte[] authenticated = new byte[LENGTH_FIELD_LENGTH + encryptedBody.length];
        System.arraycopy(encryptedLength, 0, authenticated, 0, LENGTH_FIELD_LENGTH);
        System.arraycopy(encryptedBody, 0, authenticated, LENGTH_FIELD_LENGTH, encryptedBody.length);

        byte[] expected = authenticate(nonce, authenticated, authenticated.length);
        if (!Bytes.equal(expected, tag)) {
            throw new SshException("packet authentication failed");
        }

        byte[] body = new byte[encryptedBody.length];
        System.arraycopy(encryptedBody, 0, body, 0, encryptedBody.length);
        new ChaCha20(bodyKey, nonce, 1).process(body, 0, body.length);
        return body;
    }

    /** The Poly1305 key is block zero of the body key stream, freshly per packet. */
    private byte[] authenticate(byte[] nonce, byte[] data, int length) {
        byte[] key = new byte[POLY1305_KEY_LENGTH];
        new ChaCha20(bodyKey, nonce, 0).process(key, 0, POLY1305_KEY_LENGTH);

        Poly1305 mac = new Poly1305(key);
        mac.update(data, 0, length);
        return mac.finish();
    }

    // The tag comparison lives in Bytes, with the other three that used to be
    // scattered. See the note there on why there is only one of them.

    /**
     * The nonce is the sequence number, which is why a packet cannot be
     * replayed or reordered: its number is part of what authenticates it.
     * Four zero bytes then the sequence as a big-endian uint64 gives the same
     * cipher state as OpenSSH's 64-bit-nonce ChaCha20 with a zero high counter.
     */
    private static byte[] nonce(long sequence) {
        byte[] nonce = new byte[12];
        for (int i = 0; i < 8; i++) {
            nonce[4 + i] = (byte) (sequence >>> (56 - 8 * i));
        }
        return nonce;
    }

}
