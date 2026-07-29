package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.Ed25519;

/**
 * Reads the private key file OpenSSH writes.
 *
 * The realistic way to get a key onto the handset is to paste the contents of
 * `~/.ssh/id_ed25519`, so that is what this understands: the `openssh-key-v1`
 * container, base64 inside PEM markers.
 *
 * Only unencrypted keys. A passphrase-protected one needs bcrypt-pbkdf and AES,
 * neither of which exists here and neither of which is worth adding for this —
 * `ssh-keygen -p` removes a passphrase, and a key file copied onto a phone is
 * already only as safe as the phone. What matters is that it says so rather
 * than failing with something about a bad key.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class OpenSshKey {

    private static final String BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String END = "-----END OPENSSH PRIVATE KEY-----";

    private static final String MAGIC = "openssh-key-v1";

    private OpenSshKey() {
    }

    /**
     * Extracts the 32-byte Ed25519 seed.
     *
     * OpenSSH stores 64 bytes: the seed followed by the public key it derives
     * to. Only the first half is the secret; the second is checked against the
     * key's own public field, which catches a truncated or mangled paste
     * before it turns into a signature nobody can verify.
     */
    public static byte[] readEd25519Seed(String pem) throws IOException {
        int begin = pem.indexOf(BEGIN);
        int end = pem.indexOf(END);
        if (begin < 0 || end < 0 || end < begin) {
            throw new SshException("not an OpenSSH private key");
        }
        byte[] blob = Base64.decode(pem.substring(begin + BEGIN.length(), end));

        byte[] magic = Ascii.toBytes(MAGIC);
        if (blob.length < magic.length + 1) {
            throw new SshException("the key file is too short to be one");
        }
        for (int i = 0; i < magic.length; i++) {
            if (blob[i] != magic[i]) {
                throw new SshException("not an openssh-key-v1 file");
            }
        }

        WireReader r = new WireReader(blob, magic.length + 1, blob.length - magic.length - 1);
        String cipher = r.readAsciiString();
        r.readAsciiString();                    // kdf name
        r.readString();                         // kdf options
        if (!"none".equals(cipher)) {
            throw new SshException("the key is encrypted with " + cipher
                + "; remove the passphrase with `ssh-keygen -p` first");
        }

        long keys = r.readUint32();
        if (keys != 1) {
            throw new SshException("the file holds " + keys + " keys, not one");
        }
        r.readString();                         // the public key, repeated below

        byte[] section = r.readString();
        WireReader p = new WireReader(section);
        long check1 = p.readUint32();
        long check2 = p.readUint32();
        if (check1 != check2) {
            // With no passphrase these are equal by construction; unequal means
            // the file is damaged, or encrypted in a way we did not detect.
            throw new SshException("the key file did not decode cleanly");
        }

        String type = p.readAsciiString();
        if (!HostKey.ALGORITHM.equals(type)) {
            throw new SshException("the key is " + type + ", and only "
                + HostKey.ALGORITHM + " is supported");
        }

        byte[] publicKey = p.readString();
        byte[] secret = p.readString();
        if (publicKey.length != Ed25519.PUBLIC_KEY_LENGTH
                || secret.length != Ed25519.SEED_LENGTH + Ed25519.PUBLIC_KEY_LENGTH) {
            throw new SshException("the key is not the right size for ssh-ed25519");
        }

        byte[] seed = new byte[Ed25519.SEED_LENGTH];
        System.arraycopy(secret, 0, seed, 0, Ed25519.SEED_LENGTH);

        // The stored public half, the repeated one, and the one the seed
        // actually derives to all have to agree. A paste that lost a line
        // decodes to something plausible otherwise, and the failure would
        // surface much later as a signature the server rejects.
        byte[] derived = Ed25519.publicKey(seed);
        for (int i = 0; i < Ed25519.PUBLIC_KEY_LENGTH; i++) {
            if (publicKey[i] != secret[Ed25519.SEED_LENGTH + i] || publicKey[i] != derived[i]) {
                throw new SshException("the key's public and private halves disagree");
            }
        }
        return seed;
    }

    /** The `ssh-ed25519 AAAA...` line to put in an authorized_keys file. */
    public static String authorizedKey(byte[] seed) {
        WireWriter w = new WireWriter(64);
        w.writeAsciiString(HostKey.ALGORITHM);
        w.writeString(Ed25519.publicKey(seed));
        return HostKey.ALGORITHM + " " + Base64.encode(w.toByteArray());
    }
}
