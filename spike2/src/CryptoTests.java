import berryssh.crypto.ChaCha20;
import berryssh.crypto.Poly1305;
import berryssh.crypto.SHA256;

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
