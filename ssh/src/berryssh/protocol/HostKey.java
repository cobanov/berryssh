package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.Ed25519;
import berryssh.crypto.SHA256;

/**
 * A server's public host key, and the signature check that is the whole
 * security of the handshake.
 *
 * The key exchange proves the server holds the private half of this key. What
 * it cannot prove is that this is the server you meant to reach — that is
 * {@link KnownHosts}, and without it the signature check only rules out a
 * passive eavesdropper, not somebody standing in the middle.
 *
 * Only `ssh-ed25519` is understood. That is the entire supported set rather
 * than a preference: an RSA host key would need a 2048-bit modular
 * exponentiation, which is the cost this project exists to avoid.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class HostKey {

    public static final String ALGORITHM = "ssh-ed25519";

    private final byte[] blob;
    private final byte[] publicKey;

    private HostKey(byte[] blob, byte[] publicKey) {
        this.blob = blob;
        this.publicKey = publicKey;
    }

    /**
     * Parses the key blob as it arrives in the key exchange reply:
     * a name, then the 32 raw bytes of the Ed25519 key.
     */
    public static HostKey parse(byte[] blob) throws IOException {
        WireReader r = new WireReader(blob);
        String algorithm = r.readAsciiString();
        if (!ALGORITHM.equals(algorithm)) {
            throw new SshException("host key is " + algorithm + ", not " + ALGORITHM);
        }
        byte[] key = r.readString();
        if (key.length != Ed25519.PUBLIC_KEY_LENGTH) {
            throw new SshException("ssh-ed25519 host key is " + key.length + " bytes, not 32");
        }
        if (r.remaining() != 0) {
            throw new SshException("host key blob has " + r.remaining() + " trailing bytes");
        }
        return new HostKey(blob, key);
    }

    /** The blob exactly as it arrived. It is hashed into the exchange hash. */
    public byte[] blob() {
        return blob;
    }

    public byte[] publicKey() {
        return publicKey;
    }

    /**
     * Verifies a signature blob — a name and then the 64 signature bytes —
     * over the given message.
     *
     * The algorithm name inside the signature is checked against our own
     * constant rather than against whatever the blob claims, so a server cannot
     * name an algorithm we do not implement and have the check skipped.
     */
    public boolean verify(byte[] message, byte[] signatureBlob) throws IOException {
        WireReader r = new WireReader(signatureBlob);
        String algorithm = r.readAsciiString();
        if (!ALGORITHM.equals(algorithm)) {
            throw new SshException("signature is " + algorithm + ", not " + ALGORITHM);
        }
        byte[] signature = r.readString();
        if (signature.length != Ed25519.SIGNATURE_LENGTH) {
            throw new SshException("ssh-ed25519 signature is " + signature.length + " bytes, not 64");
        }
        return Ed25519.verify(publicKey, message, signature);
    }

    /**
     * The fingerprint in the form OpenSSH prints, so that what the handset
     * shows can be compared character for character with `ssh-keygen -lf` on
     * the server. A fingerprint in a format nobody else produces is a
     * fingerprint nobody will check.
     */
    public String fingerprint() {
        return "SHA256:" + Base64.encodeUnpadded(SHA256.hash(blob));
    }

    /** The `ssh-ed25519 AAAA...` form, as it appears in a known_hosts file. */
    public String toAuthorizedKey() {
        return ALGORITHM + " " + Base64.encode(blob);
    }
}
