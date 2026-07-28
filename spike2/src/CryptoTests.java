import berryssh.crypto.ChaCha20;
import berryssh.crypto.Poly1305;
import berryssh.crypto.SHA256;
import berryssh.crypto.X25519;

/**
 * Spike 2 test vectors. The crypto sources are compiled against the CLDC 1.1
 * bootclasspath at -source 1.3 (so they are provably device-compatible) but the
 * tests run on the host JVM, which keeps verification off the device entirely.
 *
 * Vectors: FIPS 180-4 (SHA-256), RFC 8439 sections 2.4.2 / 2.5.2 / 2.8.2.
 */
public class CryptoTests {

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        sha256Vectors();
        chacha20Vector();
        poly1305Vector();
        aeadVector();
        x25519Vectors();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void sha256Vectors() {
        check("SHA-256 empty",
            SHA256.hash(new byte[0]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        check("SHA-256 abc",
            SHA256.hash(ascii("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        check("SHA-256 two-block",
            SHA256.hash(ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

        // Exercises the length-padding edge case where the 0x80 lands past byte 56.
        byte[] longInput = new byte[1_000_000];
        for (int i = 0; i < longInput.length; i++) {
            longInput[i] = (byte) 'a';
        }
        check("SHA-256 one million 'a'",
            SHA256.hash(longInput),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        // Streaming in odd-sized chunks must match the one-shot digest.
        SHA256 streaming = new SHA256();
        byte[] msg = ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        for (int i = 0; i < msg.length; i += 7) {
            int n = Math.min(7, msg.length - i);
            streaming.update(msg, i, n);
        }
        check("SHA-256 streaming matches one-shot",
            streaming.digest(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    /** RFC 8439 section 2.4.2. */
    private static void chacha20Vector() {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = hex("000000000000004a00000000");
        byte[] text = ascii("Ladies and Gentlemen of the class of '99: "
                + "If I could offer you only one tip for the future, sunscreen would be it.");

        new ChaCha20(key, nonce, 1).process(text, 0, text.length);
        check("ChaCha20 RFC 8439 2.4.2", text,
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
          + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
          + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
          + "5af90bbf74a35be6b40b8eedf2785e42874d");
    }

    /** RFC 8439 section 2.5.2. */
    private static void poly1305Vector() {
        byte[] key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] msg = ascii("Cryptographic Forum Research Group");

        Poly1305 mac = new Poly1305(key);
        mac.update(msg, 0, msg.length);
        check("Poly1305 RFC 8439 2.5.2", mac.finish(), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /** RFC 8439 section 2.8.2 — the full AEAD construction over its own framing. */
    private static void aeadVector() {
        byte[] key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = hex("070000004041424344454647");
        byte[] aad = hex("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = ascii("Ladies and Gentlemen of the class of '99: "
                + "If I could offer you only one tip for the future, sunscreen would be it.");

        // Block 0 of the key stream is the one-time Poly1305 key.
        byte[] polyKey = new byte[32];
        new ChaCha20(key, nonce, 0).process(polyKey, 0, 32);

        byte[] ciphertext = new byte[plaintext.length];
        System.arraycopy(plaintext, 0, ciphertext, 0, plaintext.length);
        new ChaCha20(key, nonce, 1).process(ciphertext, 0, ciphertext.length);

        check("AEAD ciphertext", ciphertext,
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
          + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
          + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
          + "3ff4def08e4b7a9de576d26586cec64b6116");

        Poly1305 mac = new Poly1305(polyKey);
        mac.update(aad, 0, aad.length);
        mac.padToBlock();
        mac.update(ciphertext, 0, ciphertext.length);
        mac.padToBlock();
        mac.update(lengthsBlock(aad.length, ciphertext.length), 0, 16);
        check("AEAD tag", mac.finish(), "1ae10b594f09e26a7e902ecbd0600691");
    }

    /** RFC 7748 sections 5.2 and 6.1. */
    private static void x25519Vectors() {
        // Section 5.2: raw scalar multiplication.
        check("X25519 RFC 7748 5.2 #1",
            X25519.scalarMult(
                hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        check("X25519 RFC 7748 5.2 #2",
            X25519.scalarMult(
                hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

        // Section 6.1: both sides of a key exchange must land on the same secret.
        byte[] alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        byte[] alicePub = X25519.scalarMultBase(alicePriv);
        byte[] bobPub = X25519.scalarMultBase(bobPriv);
        check("X25519 RFC 7748 6.1 Alice public", alicePub,
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        check("X25519 RFC 7748 6.1 Bob public", bobPub,
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        String expectedShared =
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        check("X25519 RFC 7748 6.1 Alice computes shared",
            X25519.scalarMult(alicePriv, bobPub), expectedShared);
        check("X25519 RFC 7748 6.1 Bob computes shared",
            X25519.scalarMult(bobPriv, alicePub), expectedShared);

        // Section 5.2 iterated: k = u = base, one round.
        byte[] k = hex("0900000000000000000000000000000000000000000000000000000000000000");
        byte[] u = hex("0900000000000000000000000000000000000000000000000000000000000000");
        for (int i = 0; i < 1; i++) {
            byte[] next = X25519.scalarMult(k, u);
            u = k;
            k = next;
        }
        check("X25519 RFC 7748 5.2 iter 1", k,
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        // A low-order point drives the shared secret to zero and must be rejected.
        byte[] lowOrder = hex("0000000000000000000000000000000000000000000000000000000000000000");
        boolean rejected = X25519.isAllZero(X25519.scalarMult(alicePriv, lowOrder));
        if (rejected) {
            passed++;
            System.out.println("  PASS  X25519 all-zero shared secret detected");
        } else {
            failed++;
            System.out.println("  FAIL  X25519 all-zero shared secret detected");
        }
    }

    private static byte[] lengthsBlock(int aadLength, int ciphertextLength) {
        byte[] b = new byte[16];
        writeLong(b, 0, aadLength);
        writeLong(b, 8, ciphertextLength);
        return b;
    }

    private static void writeLong(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (8 * i));
        }
    }

    private static void check(String name, byte[] actual, String expectedHex) {
        String got = toHex(actual);
        if (got.equals(expectedHex)) {
            passed++;
            System.out.println("  PASS  " + name);
        } else {
            failed++;
            System.out.println("  FAIL  " + name);
            System.out.println("        expected " + expectedHex);
            System.out.println("        actual   " + got);
        }
    }

    private static byte[] ascii(String s) {
        byte[] b = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            b[i] = (byte) s.charAt(i);
        }
        return b;
    }

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    private static String toHex(byte[] b) {
        StringBuffer sb = new StringBuffer(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }
}
