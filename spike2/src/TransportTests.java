import berryssh.protocol.Ascii;
import berryssh.protocol.Base64;
import berryssh.protocol.HostKey;
import berryssh.protocol.KexInit;
import berryssh.protocol.KeyExchange;
import berryssh.protocol.PacketCipher;
import berryssh.protocol.Negotiation;
import berryssh.protocol.SshException;
import berryssh.protocol.Transport;
import berryssh.protocol.Utf8;
import berryssh.protocol.WireReader;
import berryssh.protocol.WireWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Locale;

/**
 * Transport-layer vectors: the RFC 4251 section 5 wire types and the RFC 4253
 * section 6 binary packet protocol.
 *
 * As with the crypto, the classes under test are compiled against the CLDC 1.1
 * bootclasspath at -source 1.3 and then exercised here on the host JVM. This
 * file is host-only and so is under no such restriction.
 *
 * Everything runs under a Turkish default locale on purpose. The device's
 * locale is Turkish, and it is the one setting most likely to break protocol
 * code silently — so the suite is run in the condition that would expose it
 * rather than in the one that would hide it.
 */
public class TransportTests {

    private static int passed;
    private static int failed;

    private interface Fallible {
        void run() throws IOException;
    }

    public static void main(String[] args) {
        Locale.setDefault(new Locale("tr", "TR"));

        turkishLocaleIsLive();
        wireTypeVectors();
        wireRoundTrips();
        nameListVectors();
        mpintVectors();
        packetFraming();
        versionExchange();
        malformedInput();
        kexInitEncoding();
        negotiationRules();
        base64Vectors();
        hostKeyVectors();
        exchangeHashVectors();
        packetCipherVectors();
        encryptedFraming();
        utf8Vectors();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * Not a test of our code — a check that the hazard the protocol layer is
     * written to avoid is actually present in this JVM. If this ever stops
     * holding, the locale did not take and the rest of the suite is running
     * under weaker conditions than it claims to.
     */
    private static void turkishLocaleIsLive() {
        checkTrue("Turkish locale is in effect (case folding is lossy)",
            !"I".toLowerCase().equals("i"));
    }

    /** RFC 4251 section 5. */
    private static void wireTypeVectors() {
        WireWriter w = new WireWriter();
        w.writeByte(0x2a);
        check("byte", w.toByteArray(), "2a");

        w = new WireWriter();
        w.writeBoolean(true);
        w.writeBoolean(false);
        check("boolean is 1 and 0", w.toByteArray(), "0100");

        w = new WireWriter();
        w.writeUint32(699921578L);
        check("uint32 699921578", w.toByteArray(), "29b7f4aa");

        w = new WireWriter();
        w.writeUint32(0xffffffffL);
        check("uint32 at the top of its range", w.toByteArray(), "ffffffff");

        w = new WireWriter();
        w.writeUint64(0x0102030405060708L);
        check("uint64", w.toByteArray(), "0102030405060708");

        w = new WireWriter();
        w.writeAsciiString("testing");
        check("string \"testing\"", w.toByteArray(), "0000000774657374696e67");

        w = new WireWriter();
        w.writeString(new byte[0]);
        check("empty string", w.toByteArray(), "00000000");

        // A string is arbitrary binary, not text: NUL and high bytes survive.
        w = new WireWriter();
        w.writeString(hex("00ff0080"));
        check("string carries arbitrary binary", w.toByteArray(), "0000000400ff0080");
    }

    private static void wireRoundTrips() {
        WireWriter w = new WireWriter();
        w.writeByte(0xfe);
        w.writeBoolean(true);
        w.writeUint32(0xdeadbeefL);
        w.writeUint64(0xfedcba9876543210L);
        w.writeAsciiString("ssh-ed25519");
        w.writeString(hex("00112233"));
        w.writeMpint(hex("0080"));
        w.writeNameList(new String[] { "curve25519-sha256", "ext-info-c" });

        try {
            WireReader r = new WireReader(w.toByteArray());
            checkTrue("round trip: byte", r.readByte() == 0xfe);
            checkTrue("round trip: boolean", r.readBoolean());
            checkTrue("round trip: uint32 past the sign bit", r.readUint32() == 0xdeadbeefL);
            checkTrue("round trip: uint64 past the sign bit", r.readUint64() == 0xfedcba9876543210L);
            checkTrue("round trip: ascii string", "ssh-ed25519".equals(r.readAsciiString()));
            check("round trip: string", r.readString(), "00112233");
            check("round trip: mpint drops the sign byte", r.readMpint(), "80");
            String[] names = r.readNameList();
            checkTrue("round trip: name-list",
                names.length == 2
                    && "curve25519-sha256".equals(names[0])
                    && "ext-info-c".equals(names[1]));
            checkTrue("round trip consumed the whole buffer", r.remaining() == 0);
        } catch (IOException e) {
            fail("round trip threw " + e);
        }
    }

    /** RFC 4251 section 5 name-list examples. */
    private static void nameListVectors() {
        WireWriter w = new WireWriter();
        w.writeNameList(new String[0]);
        check("name-list ()", w.toByteArray(), "00000000");

        w = new WireWriter();
        w.writeNameList(new String[] { "zlib" });
        check("name-list (zlib)", w.toByteArray(), "000000047a6c6962");

        w = new WireWriter();
        w.writeNameList(new String[] { "zlib", "none" });
        check("name-list (zlib,none)", w.toByteArray(), "000000097a6c69622c6e6f6e65");

        try {
            checkTrue("empty name-list reads back empty",
                new WireReader(hex("00000000")).readNameList().length == 0);

            // The dotted and dotless I are distinct names and must stay distinct.
            // A case-insensitive match would fold them together under this locale.
            WireWriter mixed = new WireWriter();
            mixed.writeNameList(new String[] { "ID", "id" });
            String[] names = new WireReader(mixed.toByteArray()).readNameList();
            checkTrue("name-list comparison is exact, not case folded",
                "ID".equals(names[0]) && "id".equals(names[1]) && !names[0].equals(names[1]));
        } catch (IOException e) {
            fail("name-list read threw " + e);
        }
    }

    /** RFC 4251 section 5 mpint examples; SSH carries no negative values. */
    private static void mpintVectors() {
        WireWriter w = new WireWriter();
        w.writeMpint(new byte[0]);
        check("mpint 0", w.toByteArray(), "00000000");

        w = new WireWriter();
        w.writeMpint(hex("000000"));
        check("mpint 0 written as leading zeroes", w.toByteArray(), "00000000");

        w = new WireWriter();
        w.writeMpint(hex("09a378f9b2e332a7"));
        check("mpint 0x9a378f9b2e332a7", w.toByteArray(), "0000000809a378f9b2e332a7");

        w = new WireWriter();
        w.writeMpint(hex("80"));
        check("mpint 0x80 gains a sign byte", w.toByteArray(), "000000020080");

        w = new WireWriter();
        w.writeMpint(hex("00000080"));
        check("mpint strips leading zeroes before padding", w.toByteArray(), "000000020080");

        // The shared secret arrives as 32 bytes and is hashed as an mpint, so a
        // secret whose top byte is small must lose it rather than keep it.
        w = new WireWriter();
        w.writeMpint(hex("0011223344556677889900112233445566778899001122334455667788990011"));
        check("mpint of a 32-byte secret with a small top byte",
            w.toByteArray(),
            "0000001f11223344556677889900112233445566778899001122334455667788990011");
    }

    private static void packetFraming() {
        boolean allWellFormed = true;
        boolean allRoundTripped = true;

        // Every payload length across four block widths, so each alignment case
        // and the 16-byte minimum are all hit.
        for (int length = 0; length <= 40; length++) {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) {
                payload[i] = (byte) (i + 1);
            }

            byte[] framed;
            byte[] readBack;
            try {
                ByteArrayOutputStream sink = new ByteArrayOutputStream();
                new Transport(new ByteArrayInputStream(new byte[0]), sink).writePacket(payload);
                framed = sink.toByteArray();

                readBack = new Transport(new ByteArrayInputStream(framed),
                                         new ByteArrayOutputStream()).readPacket();
            } catch (IOException e) {
                fail("framing a " + length + "-byte payload threw " + e);
                return;
            }

            long declared = ((long) (framed[0] & 0xff) << 24) | ((framed[1] & 0xff) << 16)
                          | ((framed[2] & 0xff) << 8) | (framed[3] & 0xff);
            int padLength = framed[4] & 0xff;

            if (framed.length % 8 != 0
                    || framed.length < 16
                    || padLength < 4
                    || declared != framed.length - 4
                    || declared != 1 + length + padLength) {
                allWellFormed = false;
            }
            if (!sameBytes(payload, readBack)) {
                allRoundTripped = false;
            }
        }

        checkTrue("packets of every payload length 0..40 obey the framing rules", allWellFormed);
        checkTrue("packets of every payload length 0..40 round trip", allRoundTripped);
    }

    private static void versionExchange() {
        // A banner, a bare-LF line ending, then a packet immediately behind the
        // identification string — the last part is what catches a reader that
        // buffers ahead and eats the first packet.
        ByteArrayOutputStream framed = new ByteArrayOutputStream();
        try {
            new Transport(new ByteArrayInputStream(new byte[0]), framed)
                .writePacket(Ascii.toBytes("first packet"));
        } catch (IOException e) {
            fail("could not build the trailing packet: " + e);
            return;
        }

        ByteArrayOutputStream server = new ByteArrayOutputStream();
        writeAscii(server, "Unauthorised access is prohibited.\r\n");
        writeAscii(server, "SSH-2.0-OpenSSH_9.6\n");
        byte[] packet = framed.toByteArray();
        server.write(packet, 0, packet.length);

        ByteArrayOutputStream client = new ByteArrayOutputStream();
        Transport t = new Transport(new ByteArrayInputStream(server.toByteArray()), client);
        try {
            t.exchangeVersions();
        } catch (IOException e) {
            fail("version exchange threw " + e);
            return;
        }

        check("client sends its identification with CR LF",
            client.toByteArray(),
            toHex(Ascii.toBytes("SSH-2.0-berryssh_0.1\r\n")));
        checkTrue("banner lines are skipped and CR LF is stripped",
            "SSH-2.0-OpenSSH_9.6".equals(t.serverVersion()));
        checkTrue("client version is kept for the exchange hash",
            "SSH-2.0-berryssh_0.1".equals(t.clientVersion()));

        try {
            checkTrue("the packet behind the identification string survives",
                sameBytes(Ascii.toBytes("first packet"), t.readPacket()));
        } catch (IOException e) {
            fail("reading the packet after the version exchange threw " + e);
        }

        checkTrue("sequence numbers count what was sent and received",
            t.sendSequence() == 0 && t.receiveSequence() == 1);

        checkRejected("a version other than 2.0 is refused",
            () -> transportOver("SSH-1.5-OpenSSH_2.9\r\n").exchangeVersions());
        checkRejected("a closed connection during the exchange is refused",
            () -> transportOver("no identification here\r\n").exchangeVersions());
    }

    private static void malformedInput() {
        // packet_length of 0x00100000, past the cap, before any allocation.
        checkRejected("an implausible packet length is refused",
            () -> transportOver(hex("00100000")).readPacket());
        checkRejected("a packet below the minimum size is refused",
            () -> transportOver(hex("00000004" + "04000000")).readPacket());
        checkRejected("a packet that is not a whole number of blocks is refused",
            () -> transportOver(hex("0000000d" + "040000000000000000000000")).readPacket());
        checkRejected("padding shorter than 4 bytes is refused",
            () -> transportOver(hex("0000000c" + "030000000000000000000000")).readPacket());
        checkRejected("padding larger than the packet is refused",
            () -> transportOver(hex("0000000c" + "ff0000000000000000000000")).readPacket());
        checkRejected("a truncated packet is refused",
            () -> transportOver(hex("0000000c" + "0400")).readPacket());

        checkRejected("a field running past the end is refused",
            () -> new WireReader(hex("000000")).readUint32());
        checkRejected("a string length overrunning the packet is refused",
            () -> new WireReader(hex("7fffffff00")).readString());
        checkRejected("a negative mpint is refused",
            () -> new WireReader(hex("00000002edcc")).readMpint());
    }

    /** The payload is hashed byte for byte during the key exchange, so it is pinned here. */
    private static void kexInitEncoding() {
        byte[] cookie = new byte[16];
        for (int i = 0; i < 16; i++) {
            cookie[i] = (byte) i;
        }
        check("KEXINIT payload",
            KexInit.clientWithCookie(cookie).payload(),
            "14000102030405060708090a0b0c0d0e0f"
                + "0000002e637572766532353531392d7368613235362c"
                + "637572766532353531392d736861323536406c69627373682e6f7267"
                + "0000000b7373682d65643235353139"
                + "0000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d"
                + "0000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d"
                + "0000000d686d61632d736861322d323536"
                + "0000000d686d61632d736861322d323536"
                + "000000046e6f6e65000000046e6f6e65"
                + "0000000000000000"
                + "00"
                + "00000000");

        try {
            KexInit parsed = KexInit.parse(KexInit.clientWithCookie(cookie).payload());
            checkTrue("KEXINIT parses back to the lists it was built from",
                parsed.kexAlgorithms().length == 2
                    && "curve25519-sha256".equals(parsed.kexAlgorithms()[0])
                    && "curve25519-sha256@libssh.org".equals(parsed.kexAlgorithms()[1])
                    && "ssh-ed25519".equals(parsed.hostKeyAlgorithms()[0])
                    && "chacha20-poly1305@openssh.com".equals(parsed.ciphersServerToClient()[0])
                    && "none".equals(parsed.compressionClientToServer()[0])
                    && !parsed.firstKexPacketFollows());
        } catch (IOException e) {
            fail("KEXINIT round trip threw " + e);
        }

        checkRejected("a payload that is not a KEXINIT is refused",
            () -> KexInit.parse(hex("15000102030405060708090a0b0c0d0e0f")));
    }

    private static void negotiationRules() {
        try {
            // Our order decides, not the server's. The server here prefers the
            // libssh name; we prefer the standardised one, so ours wins.
            Negotiation n = Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "curve25519-sha256@libssh.org", "curve25519-sha256" },
                new String[] { "rsa-sha2-512", "ssh-ed25519" },
                new String[] { "aes128-ctr", "chacha20-poly1305@openssh.com" },
                false));
            checkTrue("negotiation follows the client's preference order",
                "curve25519-sha256".equals(n.kex())
                    && "ssh-ed25519".equals(n.hostKey())
                    && "chacha20-poly1305@openssh.com".equals(n.cipherClientToServer())
                    && "chacha20-poly1305@openssh.com".equals(n.cipherServerToClient())
                    && "none".equals(n.compressionServerToClient()));
            checkTrue("nothing is discarded when the server did not guess",
                !n.discardGuessedPacket());

            // A server that guesses correctly: its first preferences match what
            // was negotiated, so the packet it sent ahead is valid.
            Negotiation right = Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "curve25519-sha256" },
                new String[] { "ssh-ed25519" },
                new String[] { "chacha20-poly1305@openssh.com" },
                true));
            checkTrue("a correct guess is kept", !right.discardGuessedPacket());

            // A server that guesses wrongly: its first kex is not the negotiated
            // one, so the packet it sent ahead has to be read and dropped, or
            // everything after it is one message out of step.
            Negotiation wrong = Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "curve25519-sha256@libssh.org", "curve25519-sha256" },
                new String[] { "ssh-ed25519" },
                new String[] { "chacha20-poly1305@openssh.com" },
                true));
            checkTrue("a wrong guess marks the next packet for discard",
                wrong.discardGuessedPacket());
        } catch (IOException e) {
            fail("negotiation threw " + e);
        }

        checkRejected("no key exchange in common is refused",
            () -> Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "diffie-hellman-group14-sha1" },
                new String[] { "ssh-ed25519" },
                new String[] { "chacha20-poly1305@openssh.com" },
                false)));

        checkRejected("no host key algorithm in common is refused",
            () -> Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "curve25519-sha256" },
                new String[] { "ssh-rsa", "ecdsa-sha2-nistp256" },
                new String[] { "chacha20-poly1305@openssh.com" },
                false)));

        // Refusing this is what keeps the packet layer authenticated: an
        // agreement on a non-AEAD cipher would need a separate MAC we do not have.
        checkRejected("a cipher with no AEAD is refused",
            () -> Negotiation.between(clientKexInit(), serverKexInit(
                new String[] { "curve25519-sha256" },
                new String[] { "ssh-ed25519" },
                new String[] { "aes128-ctr" },
                false)));
    }

    /** RFC 4648 section 10. */
    private static void base64Vectors() {
        String[][] vectors = {
            { "", "" },
            { "f", "Zg==" },
            { "fo", "Zm8=" },
            { "foo", "Zm9v" },
            { "foob", "Zm9vYg==" },
            { "fooba", "Zm9vYmE=" },
            { "foobar", "Zm9vYmFy" }
        };
        boolean encoded = true;
        boolean decoded = true;
        for (int i = 0; i < vectors.length; i++) {
            if (!Base64.encode(Ascii.toBytes(vectors[i][0])).equals(vectors[i][1])) {
                encoded = false;
            }
            try {
                if (!sameBytes(Ascii.toBytes(vectors[i][0]), Base64.decode(vectors[i][1]))) {
                    decoded = false;
                }
            } catch (IOException e) {
                decoded = false;
            }
        }
        checkTrue("base64 encodes the RFC 4648 vectors", encoded);
        checkTrue("base64 decodes the RFC 4648 vectors", decoded);

        checkTrue("base64 omits padding when asked",
            "Zm9vYmE".equals(Base64.encodeUnpadded(Ascii.toBytes("fooba"))));

        try {
            checkTrue("base64 decodes without padding and across whitespace",
                sameBytes(Ascii.toBytes("fooba"), Base64.decode("Zm9v\n YmE")));
        } catch (IOException e) {
            fail("unpadded decode threw " + e);
        }

        checkRejected("base64 with a character outside the alphabet is refused",
            () -> Base64.decode("Zm9v!mE="));
        checkRejected("base64 of an impossible length is refused",
            () -> Base64.decode("Zm9vY"));
    }

    /**
     * The host key of the project's test container. The fingerprint is what
     * `ssh-keygen -lf` prints for it, so the string the handset shows can be
     * compared against the server character for character.
     */
    private static void hostKeyVectors() {
        byte[] blob = hex("0000000b7373682d6564323535313900000020"
            + "2ff01c2270598befd06f04f4c80df20da07c5a0834d13e327bc1c5eefd9bcbbf");
        try {
            HostKey key = HostKey.parse(blob);
            checkTrue("host key fingerprint matches ssh-keygen -lf",
                "SHA256:9tqjakW/Ia6U4hT3VgAv8EXXCxC1d3ez9mr5qjVTRZs".equals(key.fingerprint()));
            checkTrue("host key renders as a known_hosts line",
                ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/wHCJwWYvv0G8E9MgN8g2gfFoINNE"
                    + "+MnvBxe79m8u/").equals(key.toAuthorizedKey()));
            checkTrue("host key exposes the 32 raw bytes",
                key.publicKey().length == 32);
        } catch (IOException e) {
            fail("host key parse threw " + e);
        }

        checkRejected("a host key of the wrong algorithm is refused",
            () -> HostKey.parse(hex("00000007" + "7373682d727361" + "00000001" + "05")));
        checkRejected("an ssh-ed25519 key that is not 32 bytes is refused",
            () -> HostKey.parse(hex("0000000b7373682d65643235353139" + "0000000401020304")));
        checkRejected("a host key blob with trailing bytes is refused",
            () -> HostKey.parse(hex("0000000b7373682d6564323535313900000020"
                + "2ff01c2270598befd06f04f4c80df20da07c5a0834d13e327bc1c5eefd9bcbbf" + "ff")));
    }

    /**
     * RFC 8731 section 3 and RFC 4253 section 7.2, against values computed
     * outside the class. If the exchange hash is wrong by a byte the server's
     * signature simply fails to verify, with nothing in the failure to say
     * which of the eight fields was at fault — so it is worth pinning here.
     */
    private static void exchangeHashVectors() {
        String clientVersion = "SSH-2.0-berryssh_0.1";
        String serverVersion = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10";
        byte[] clientKexInit = counting(0, 20);
        byte[] serverKexInit = counting(100, 40);
        byte[] hostKeyBlob = hex("0000000b7373682d6564323535313900000020"
            + "2ff01c2270598befd06f04f4c80df20da07c5a0834d13e327bc1c5eefd9bcbbf");
        byte[] clientPublic = counting(0, 32);
        byte[] serverPublic = counting(32, 32);
        byte[] shared = hex("0f" + repeat("11", 31));

        byte[] h = KeyExchange.exchangeHash(clientVersion, serverVersion,
            clientKexInit, serverKexInit, hostKeyBlob, clientPublic, serverPublic, shared);
        check("exchange hash", h,
            "23f549f05c9e7da24577ec04c43b5e3f9bd9e9af8614dc5de961b6865fe54345");

        // Half of all shared secrets have the top bit set and gain an mpint sign
        // byte. Treating the secret as fixed-width would work about half the time.
        byte[] highSecret = hex("f0" + repeat("22", 31));
        check("exchange hash with a secret that needs an mpint sign byte",
            KeyExchange.exchangeHash(clientVersion, serverVersion,
                clientKexInit, serverKexInit, hostKeyBlob, clientPublic, serverPublic, highSecret),
            "2c55820c96b5bc6f70336346ef164bd3b124d8b964826675ac090eda577cfcf1");

        // 64 bytes crosses the one-hash boundary, which is the case the RFC's
        // extension rule exists for and the one an implementation gets wrong.
        check("derived key C, 64 bytes across the hash boundary",
            KeyExchange.deriveKey(shared, h, 'C', h, 64),
            "48f667892eda7f0cc12049bb69d17e412c994ac944879703452591036e99244e"
                + "b34e3a9d0b578f6470cf0fb35166036b7d274527fd9981c1bd476efe0e142d61");
        check("derived key D, 64 bytes",
            KeyExchange.deriveKey(shared, h, 'D', h, 64),
            "0697d95bd891623204b6e9db7d9e82573577e190653a7ed1d33835eb59a86874"
                + "aab166381e714e2c7d978a59cf5bb2fb1590fe14a0b478247a271e8fb0f7a470");
        check("derived key A, 16 bytes from one hash",
            KeyExchange.deriveKey(shared, h, 'A', h, 16),
            "132bce258cdfdb26edd5ce05dc891bc3");
    }

    /**
     * chacha20-poly1305@openssh.com against a reference written from
     * PROTOCOL.chacha20poly1305 rather than from this implementation. The two
     * key halves are the detail worth pinning: swapping them gives a cipher
     * that is perfectly self-consistent and cannot talk to anything.
     */
    private static void packetCipherVectors() {
        byte[] key = counting(0, 64);
        byte[] body = hex("0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000102030405060708090a");

        check("sealed packet: encrypted length, body and tag",
            new PacketCipher(key).seal(3, body),
            "fb1a92aa"
                + "8befb61198e00edb22e556a0114d3ce9cd76e66d6add5e45080e036ea6bd88c8"
                + "373ac47bfddf5152b56c3baaae5aa723");

        checkTrue("the length field decrypts on its own, before anything is authenticated",
            new PacketCipher(key).peekLength(3, hex("fb1a92aa")) == 32);

        // The sequence number is the nonce, which is what makes a packet
        // impossible to replay or reorder: its number authenticates it.
        checkTrue("a different sequence number produces a different packet",
            !toHex(new PacketCipher(key).seal(4, body))
                .equals(toHex(new PacketCipher(key).seal(3, body))));

        try {
            PacketCipher cipher = new PacketCipher(key);
            byte[] wire = cipher.seal(7, body);
            byte[] encryptedLength = slice(wire, 0, 4);
            byte[] encryptedBody = slice(wire, 4, wire.length - 20);
            byte[] tag = slice(wire, wire.length - 16, 16);
            checkTrue("a sealed packet opens back to the same body",
                sameBytes(body, cipher.open(7, encryptedLength, encryptedBody, tag)));

            checkRejected("a packet opened at the wrong sequence number is refused",
                () -> cipher.open(8, encryptedLength, encryptedBody, tag));
            checkRejected("a tampered tag is refused",
                () -> cipher.open(7, encryptedLength, encryptedBody, flip(tag, 0)));
            checkRejected("a tampered body is refused",
                () -> cipher.open(7, encryptedLength, flip(encryptedBody, 5), tag));
            // The tag covers the length field too, so tampering with it is
            // caught even though it is encrypted under a separate key.
            checkRejected("a tampered length field is refused",
                () -> cipher.open(7, flip(encryptedLength, 0), encryptedBody, tag));
        } catch (IOException e) {
            fail("packet cipher round trip threw " + e);
        }
    }

    /**
     * The framing changes once the AEAD is in play: RFC 4253 counts the length
     * field towards the block multiple, but chacha20-poly1305 encrypts it
     * separately, so it is excluded. Getting this wrong produces packets a
     * server rejects as corrupt without saying that padding is the objection.
     */
    private static void encryptedFraming() {
        byte[] key = counting(64, 64);
        boolean allRoundTripped = true;
        boolean allAligned = true;

        for (int length = 0; length <= 40; length++) {
            byte[] payload = counting(1, length);
            try {
                ByteArrayOutputStream sink = new ByteArrayOutputStream();
                Transport writer = new Transport(new ByteArrayInputStream(new byte[0]), sink);
                writer.encryptOutgoing(new PacketCipher(key));
                writer.writePacket(payload);
                byte[] wire = sink.toByteArray();

                // The encrypted run between the length field and the tag is
                // what has to be a whole number of blocks. RFC 4253's 16-byte
                // floor does not apply here — it exists for block ciphers, and
                // OpenSSH sends an 8-byte body for a one-byte message, so
                // requiring more would reject a real server's packets.
                int encrypted = wire.length - 4 - PacketCipher.TAG_LENGTH;
                if (encrypted % 8 != 0 || encrypted < 8) {
                    allAligned = false;
                }

                Transport reader = new Transport(new ByteArrayInputStream(wire),
                                                 new ByteArrayOutputStream());
                reader.decryptIncoming(new PacketCipher(key));
                if (!sameBytes(payload, reader.readPacket())) {
                    allRoundTripped = false;
                }
            } catch (IOException e) {
                fail("encrypted framing of a " + length + "-byte payload threw " + e);
                return;
            }
        }

        checkTrue("encrypted packets of every payload length 0..40 are block aligned", allAligned);
        checkTrue("encrypted packets of every payload length 0..40 round trip", allRoundTripped);

        // A cipher enabled on one side only must fail rather than produce
        // plausible nonsense, which is what a mis-ordered NEWKEYS would do.
        checkRejected("a plaintext reader refuses an encrypted packet", () -> {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            Transport writer = new Transport(new ByteArrayInputStream(new byte[0]), sink);
            writer.encryptOutgoing(new PacketCipher(key));
            writer.writePacket(Ascii.toBytes("this should not be readable in the clear"));
            new Transport(new ByteArrayInputStream(sink.toByteArray()),
                          new ByteArrayOutputStream()).readPacket();
        });
    }

    /**
     * UTF-8, which RFC 4252 requires for usernames and passwords while the
     * device's default encoding is ISO8859_1.
     *
     * The Turkish characters are the case that matters rather than an
     * illustration: under ISO8859_1 they encode to one byte each and the server
     * would compare the wrong bytes, reporting only that the login failed.
     */
    private static void utf8Vectors() {
        check("UTF-8 ASCII is unchanged", Utf8.encode("bb"), "6262");

        // U+00E7 U+011F U+0131 U+00F6 U+015F U+00FC — the six Turkish letters.
        check("UTF-8 encodes the Turkish letters",
            Utf8.encode("çğıöşü"),
            "c3a7c49fc4b1c3b6c59fc3bc");
        checkTrue("a Turkish password is 6 characters and 12 bytes",
            "çğıöşü".length() == 6
                && Utf8.encode("çğıöşü").length == 12);

        check("UTF-8 encodes a three-byte code point", Utf8.encode("€"), "e282ac");
        // U+1F600, which Java holds as a surrogate pair.
        check("UTF-8 encodes a surrogate pair as one four-byte sequence",
            Utf8.encode("😀"), "f09f9880");

        String[] roundTrips = {
            "", "bb", "çğıöşü", "€",
            "😀", "karışık ASCII ve Türkçe"
        };
        boolean allRoundTripped = true;
        for (int i = 0; i < roundTrips.length; i++) {
            if (!roundTrips[i].equals(Utf8.decode(Utf8.encode(roundTrips[i])))) {
                allRoundTripped = false;
            }
        }
        checkTrue("UTF-8 round trips, including outside the basic plane", allRoundTripped);

        // One bad byte should cost one character, not the session: this decodes
        // terminal output, where throwing would be the wrong response.
        checkTrue("a malformed byte becomes one replacement character",
            "a�b".equals(Utf8.decode(hex("61ff62"))));
        checkTrue("a truncated sequence at the end does not run off the array",
            Utf8.decode(hex("61c3")).length() == 2);
    }

    private static byte[] slice(byte[] b, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(b, offset, out, 0, length);
        return out;
    }

    private static byte[] flip(byte[] b, int index) {
        byte[] out = new byte[b.length];
        System.arraycopy(b, 0, out, 0, b.length);
        out[index] ^= 0x01;
        return out;
    }

    private static byte[] counting(int from, int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (from + i);
        }
        return b;
    }

    private static String repeat(String s, int times) {
        StringBuffer sb = new StringBuffer(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static KexInit clientKexInit() {
        return KexInit.clientWithCookie(new byte[16]);
    }

    /** Builds a server KEXINIT with arbitrary lists, by way of the wire format. */
    private static KexInit serverKexInit(String[] kex, String[] hostKey, String[] ciphers,
                                         boolean guessing) throws IOException {
        String[] macs = { "hmac-sha2-256", "hmac-sha1" };
        String[] compression = { "none", "zlib@openssh.com" };
        WireWriter w = new WireWriter(512);
        w.writeByte(20);
        w.writeRaw(new byte[16]);
        w.writeNameList(kex);
        w.writeNameList(hostKey);
        w.writeNameList(ciphers);
        w.writeNameList(ciphers);
        w.writeNameList(macs);
        w.writeNameList(macs);
        w.writeNameList(compression);
        w.writeNameList(compression);
        w.writeNameList(new String[0]);
        w.writeNameList(new String[0]);
        w.writeBoolean(guessing);
        w.writeUint32(0);
        return KexInit.parse(w.toByteArray());
    }

    private static Transport transportOver(String ascii) {
        return transportOver(Ascii.toBytes(ascii));
    }

    private static Transport transportOver(byte[] data) {
        return new Transport(new ByteArrayInputStream(data), new ByteArrayOutputStream());
    }

    private static void writeAscii(ByteArrayOutputStream out, String s) {
        byte[] b = Ascii.toBytes(s);
        out.write(b, 0, b.length);
    }

    private static boolean sameBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    private static void checkRejected(String name, Fallible f) {
        try {
            f.run();
            fail(name + " (nothing was thrown)");
        } catch (SshException e) {
            pass(name);
        } catch (IOException e) {
            fail(name + " (threw " + e + " rather than SshException)");
        }
    }

    private static void check(String name, byte[] actual, String expectedHex) {
        String got = toHex(actual);
        if (got.equals(expectedHex)) {
            pass(name);
        } else {
            fail(name);
            System.out.println("        expected " + expectedHex);
            System.out.println("        actual   " + got);
        }
    }

    private static void checkTrue(String name, boolean condition) {
        if (condition) {
            pass(name);
        } else {
            fail(name);
        }
    }

    private static void pass(String name) {
        passed++;
        System.out.println("  PASS  " + name);
    }

    private static void fail(String name) {
        failed++;
        System.out.println("  FAIL  " + name);
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
