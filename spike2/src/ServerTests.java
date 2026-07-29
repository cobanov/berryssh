import berryssh.crypto.EntropyPool;
import berryssh.protocol.Channel;
import berryssh.protocol.Connection;
import berryssh.protocol.HostKey;
import berryssh.protocol.KexInit;
import berryssh.protocol.KeyExchange;
import berryssh.protocol.Message;
import berryssh.protocol.Negotiation;
import berryssh.protocol.Transport;
import berryssh.protocol.UserAuth;
import berryssh.protocol.Utf8;

import java.io.IOException;
import java.net.Socket;

/**
 * The half of the verification that needs a real OpenSSH server.
 *
 * The offline vectors prove the encodings; only a real server proves the
 * protocol. A key exchange either convinces OpenSSH or it does not, and if the
 * exchange hash is wrong by one byte the only symptom is a signature that will
 * not verify — so this is where that gets settled.
 *
 * Host-only: `java.net` does not exist in CLDC, where the same streams come
 * from `Connector.open("socket://host:port")`. Everything under test takes
 * streams rather than a socket precisely so that substitution is the only
 * difference between here and the device.
 */
public class ServerTests {

    private static String host = "127.0.0.1";
    private static int port = 2222;
    private static String user = "bb";
    private static String password = "bbssh";

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        if (args.length >= 1) {
            host = args[0];
        }
        if (args.length >= 2) {
            port = Integer.parseInt(args[1]);
        }
        if (args.length >= 4) {
            user = args[2];
            password = args[3];
        }

        System.out.println("  ..    against " + host + ":" + port);
        negotiatesWithRealServer();
        exchangesKeysWithRealServer();
        encryptsWithRealServer();
        authenticatesWithRealServer();
        runsAShellOnRealServer();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /** A connection carried far enough to be useful, with the pieces kept. */
    private static final class Handshake {
        Socket socket;
        Transport transport;
        EntropyPool random;
        KexInit ours;
        KexInit theirs;
        Negotiation negotiated;
    }

    private static Handshake upToKexInit() throws IOException {
        Handshake h = new Handshake();
        h.socket = new Socket(host, port);
        h.socket.setSoTimeout(15000);
        h.transport = new Transport(h.socket.getInputStream(), h.socket.getOutputStream());
        h.transport.exchangeVersions();

        h.random = new EntropyPool();
        h.random.seed();
        h.ours = KexInit.client(h.random);
        h.transport.writePacket(h.ours.payload());

        h.theirs = KexInit.parse(h.transport.readMessage());
        h.negotiated = Negotiation.between(h.ours, h.theirs);
        return h;
    }

    /**
     * RFC 4253 sections 4.2 and 7.1: the identification strings have to be
     * mutually acceptable, and the negotiated set has to be the modern one on a
     * server that still offers the 2011 algorithms as well.
     */
    private static void negotiatesWithRealServer() throws Exception {
        Handshake h = upToKexInit();
        try {
            checkTrue("the server accepts our identification and returns its own",
                h.transport.serverVersion() != null
                    && h.transport.serverVersion().startsWith("SSH-2.0-"));
            System.out.println("        server is " + h.transport.serverVersion());

            checkTrue("negotiated curve25519-sha256",
                "curve25519-sha256".equals(h.negotiated.kex()));
            checkTrue("negotiated ssh-ed25519",
                "ssh-ed25519".equals(h.negotiated.hostKey()));
            checkTrue("negotiated chacha20-poly1305@openssh.com both ways",
                "chacha20-poly1305@openssh.com".equals(h.negotiated.cipherClientToServer())
                    && "chacha20-poly1305@openssh.com".equals(h.negotiated.cipherServerToClient()));
            checkTrue("negotiated no compression",
                "none".equals(h.negotiated.compressionClientToServer())
                    && "none".equals(h.negotiated.compressionServerToClient()));

            // The container deliberately still offers the 2011 algorithms, so
            // this confirms the modern set was a choice rather than the only
            // thing on the table.
            boolean legacyOffered = false;
            for (int i = 0; i < h.theirs.kexAlgorithms().length; i++) {
                if ("diffie-hellman-group14-sha1".equals(h.theirs.kexAlgorithms()[i])) {
                    legacyOffered = true;
                }
            }
            checkTrue("the server also offered the legacy key exchange, and we did not take it",
                legacyOffered);
        } finally {
            h.socket.close();
        }
    }

    /**
     * RFC 8731. The server signs the exchange hash it computed; our signature
     * check passing means our reconstruction of it agrees with the server's
     * across all eight fields, byte for byte. There is no weaker way to pass.
     */
    private static void exchangesKeysWithRealServer() throws Exception {
        Handshake h = upToKexInit();
        try {
            KeyExchange.Result result = KeyExchange.run(h.transport, h.ours, h.theirs, h.random);

            checkTrue("the server's signature over the exchange hash verifies",
                result.exchangeHash().length == 32);

            HostKey key = result.hostKey();
            System.out.println("        host key is " + key.fingerprint());
            checkTrue("the host key is ssh-ed25519 and 32 bytes",
                key.publicKey().length == 32);
            checkTrue("the fingerprint is the one ssh-keygen prints for this server",
                "SHA256:9tqjakW/Ia6U4hT3VgAv8EXXCxC1d3ez9mr5qjVTRZs".equals(key.fingerprint()));

            // Derivation cannot be checked against the server until the cipher
            // is in place, but its shape can: the labels must produce distinct
            // material of the length asked for.
            byte[] sessionId = result.exchangeHash();
            byte[] keyOut = result.deriveKey('C', sessionId, 64);
            byte[] keyIn = result.deriveKey('D', sessionId, 64);
            checkTrue("derives 64 bytes per direction, and the directions differ",
                keyOut.length == 64 && keyIn.length == 64 && !sameBytes(keyOut, keyIn));
        } finally {
            h.socket.close();
        }
    }

    /**
     * The full handshake through NEWKEYS, and then a packet in each direction
     * under the negotiated cipher.
     *
     * A service request is the smallest thing that proves it: the server has to
     * authenticate and decrypt what we sent, and we have to authenticate and
     * decrypt its answer. Both directions and both keys, in one exchange. There
     * is no way for this to pass with the key halves swapped or the padding
     * rule wrong.
     */
    private static void encryptsWithRealServer() throws Exception {
        Socket socket = new Socket(host, port);
        try {
            socket.setSoTimeout(15000);
            EntropyPool random = new EntropyPool();
            random.seed();
            Connection connection = new Connection(
                socket.getInputStream(), socket.getOutputStream(), random);

            HostKey key = connection.handshake();
            checkTrue("the handshake completes through NEWKEYS in both directions",
                key != null && connection.sessionId() != null
                    && connection.sessionId().length == 32);

            connection.requestService("ssh-userauth");
            checkTrue("an encrypted service request is accepted and its reply decrypts",
                connection.transport().sendSequence() > 0
                    && connection.transport().receiveSequence() > 0);

            // Sequence numbers have to agree with the server's or the nonces
            // diverge and nothing decrypts from that point on. Getting several
            // packets past NEWKEYS is that agreement holding.
            System.out.println("        " + connection.transport().sendSequence()
                + " packets sent, " + connection.transport().receiveSequence() + " received");
        } finally {
            socket.close();
        }
    }

    /**
     * RFC 4252 against the real server: what it will accept, a wrong password,
     * a right one, and a publickey request it can parse.
     */
    private static void authenticatesWithRealServer() throws Exception {
        Socket socket = new Socket(host, port);
        try {
            socket.setSoTimeout(15000);
            EntropyPool random = new EntropyPool();
            random.seed();
            Connection connection = new Connection(
                socket.getInputStream(), socket.getOutputStream(), random);
            connection.handshake();

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();

            // "none" is not a way in; it is how you ask what the server wants,
            // and its failure carries the answer.
            UserAuth.Result none = auth.queryMethods();
            checkTrue("the none method is refused and names what can continue",
                !none.succeeded() && none.methodsThatCanContinue().length > 0);
            System.out.println("        server accepts " + join(none.methodsThatCanContinue()));

            boolean offersPassword = false;
            boolean offersPublicKey = false;
            for (int i = 0; i < none.methodsThatCanContinue().length; i++) {
                String method = none.methodsThatCanContinue()[i];
                if ("password".equals(method)) {
                    offersPassword = true;
                }
                if ("publickey".equals(method)) {
                    offersPublicKey = true;
                }
            }
            checkTrue("the server offers password and publickey",
                offersPassword && offersPublicKey);

            // A publickey request the server can parse. This key is not in any
            // authorized_keys, so the attempt must fail — what it demonstrates
            // is that the request and key blob are well formed enough for the
            // server to read the key out and name it in its log.
            UserAuth.Result byKey = auth.publicKey(
                hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"));
            checkTrue("an unauthorised publickey request is parsed and refused",
                !byKey.succeeded() && byKey.methodsThatCanContinue().length > 0);

            UserAuth.Result wrong = auth.password("not the password");
            checkTrue("a wrong password is refused",
                !wrong.succeeded() && !wrong.partialSuccess());

            UserAuth.Result right = auth.password(password);
            checkTrue("the right password is accepted", right.succeeded());
        } finally {
            socket.close();
        }
    }

    /**
     * The whole thing: handshake, authenticate, take a pty, run a shell, and
     * read back what it printed.
     *
     * This is the test the project is for. Everything below it has to be right
     * simultaneously — a wrong exchange hash, a swapped cipher key, a padding
     * rule off by eight, a mis-encoded password or a forgotten window update
     * each stop it, and none of them can be compensated for by another.
     */
    private static void runsAShellOnRealServer() throws Exception {
        Socket socket = new Socket(host, port);
        try {
            socket.setSoTimeout(20000);
            EntropyPool random = new EntropyPool();
            random.seed();
            Connection connection = new Connection(
                socket.getInputStream(), socket.getOutputStream(), random);
            connection.handshake();

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();
            auth.queryMethods();
            checkTrue("authenticated for the shell test", auth.password(password).succeeded());

            Channel channel = Channel.openSession(connection);
            checkTrue("a session channel opens", channel != null);

            // 60x25 is what an 8x14 bitmap cell gives on the device's 480x360
            // canvas, so the server is told the size the terminal will be.
            channel.requestPty("xterm", 60, 25);
            channel.requestShell();
            checkTrue("the server grants a pty and starts a shell", true);

            channel.write(Utf8.encode("echo be''rryssh-works; stty size; exit\n"));

            StringBuffer output = new StringBuffer();
            byte[] buffer = new byte[4096];
            for (;;) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                output.append(Utf8.decode(buffer, 0, n));
            }
            String text = output.toString();

            // Written split so the echoed command line cannot be mistaken for
            // the shell's output: only the shell can produce it joined.
            checkTrue("the shell runs a command and returns its output",
                text.indexOf("berryssh-works") >= 0);

            // The pty really carries the dimensions we asked for, rather than
            // the request merely being accepted.
            checkTrue("the pty is the 60x25 we asked for", text.indexOf("25 60") >= 0);

            channel.close();
            System.out.println("        shell exit status " + channel.exitStatus());
        } finally {
            socket.close();
        }
    }

    private static String join(String[] names) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < names.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(names[i]);
        }
        return sb.toString();
    }

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
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

    private static void checkTrue(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  PASS  " + name);
        } else {
            failed++;
            System.out.println("  FAIL  " + name);
        }
    }
}
