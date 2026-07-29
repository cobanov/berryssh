import berryssh.protocol.Ascii;
import berryssh.protocol.SshException;
import berryssh.protocol.Transport;
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
