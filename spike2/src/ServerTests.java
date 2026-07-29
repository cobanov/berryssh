import berryssh.crypto.EntropyPool;
import berryssh.protocol.BridgeAuth;
import berryssh.protocol.Channel;
import berryssh.protocol.Connection;
import berryssh.protocol.HostKey;
import berryssh.protocol.KexInit;
import berryssh.protocol.KeyExchange;
import berryssh.protocol.Message;
import berryssh.protocol.Negotiation;
import berryssh.protocol.Transport;
import berryssh.protocol.UserAuth;
import berryssh.protocol.WebSocket;
import berryssh.protocol.Utf8;
import berryssh.terminal.VT320;

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
    private static int rekeyPort = 2223;

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
        rendersARealSessionThroughTheTerminal();
        survivesTypingWhileOutputArrives();
        survivesARekey();
        authenticatesWithAKey();
        reachesAServerThroughAWebSocket();
        refusesAWrongBridgeKey();

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

    /**
     * A real session's bytes, through the terminal emulator.
     *
     * The offline terminal vectors use sequences somebody chose to write down.
     * This one takes what a shell on a pty actually emits — echo, prompts,
     * clearing, cursor addressing, colour, and the ordering between them — and
     * checks the screen that results. That combination is what a hand-written
     * vector cannot reproduce.
     */
    private static void rendersARealSessionThroughTheTerminal() throws Exception {
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
            auth.password(password);

            final Channel channel = Channel.openSession(connection);
            channel.requestPty("xterm", 60, 25);
            channel.requestShell();

            VT320 terminal = new VT320(60, 25) {
                public void sendData(byte[] b, int offset, int length) throws IOException {
                    channel.write(b, offset, length);
                }

                public void beep() {
                }

                public void resize() {
                }
            };

            // Clear, address the cursor, print in colour, then leave so that no
            // prompt is drawn over the result. The escapes are written as shell
            // octal so that this source file holds no control bytes.
            channel.write(Utf8.encode(
                "printf '\\033[2J\\033[5;10H\\033[32mMARKER\\033[0m'; exit\n"));

            byte[] buffer = new byte[4096];
            for (;;) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                terminal.putString(Utf8.decode(buffer, 0, n));
            }

            StringBuffer atMarker = new StringBuffer();
            for (int i = 0; i < 6; i++) {
                atMarker.append(terminal.getChar(9 + i, 4));
            }
            checkTrue("a real session's escape sequences land where the server put them",
                "MARKER".equals(atMarker.toString()));

            // The clear really happened: the echoed command line was on row 0
            // and is gone.
            boolean topRowClear = true;
            for (int i = 0; i < 60; i++) {
                if (terminal.getChar(i, 0) > 32) {
                    topRowClear = false;
                }
            }
            checkTrue("the screen the server cleared is clear", topRowClear);

            channel.close();
        } finally {
            socket.close();
        }
    }

    /**
     * Two threads on one connection, which is what the application does every
     * time somebody types while something is printing.
     *
     * The reader sends window updates as it consumes; the writer sends the
     * keystrokes. Both go through the same transport and the same sequence
     * numbers, and those numbers are the AEAD nonces — so if sending is not
     * serialised, two packets get sealed under one nonce and the far end stops
     * being able to decrypt anything. The failure is total and permanent, not
     * intermittent, which is the one mercy in it.
     *
     * A marker command afterwards is the check: if the streams desynchronised
     * at any point, nothing gets that far.
     */
    private static void survivesTypingWhileOutputArrives() throws Exception {
        Socket socket = new Socket(host, port);
        try {
            socket.setSoTimeout(30000);
            EntropyPool random = new EntropyPool();
            random.seed();
            Connection connection = new Connection(
                socket.getInputStream(), socket.getOutputStream(), random);
            connection.handshake();

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();
            auth.queryMethods();
            auth.password(password);

            final Channel channel = Channel.openSession(connection);
            channel.requestPty("xterm", 60, 25);
            channel.requestShell();

            // Big enough to cross the window refill threshold, which is the
            // whole point: below it the reader never sends anything, only one
            // thread is writing, and the race this exists to catch cannot
            // happen. At 1 MB per refill this is several.
            // Written split so the pty's echo of the command line cannot itself
            // contain the marker. It can, and did: the loop then ended on the
            // echo after thirteen bytes and the test measured nothing at all,
            // which is why it passed with the bug still in place.
            channel.write(Utf8.encode("seq 1 30''0000\n"));

            final Exception[] writerFailure = new Exception[1];
            final boolean[] readingDone = new boolean[1];
            final long[] typed = new long[1];
            Thread typist = new Thread(new Runnable() {
                public void run() {
                    try {
                        // For as long as the reader is reading, rather than a
                        // fixed count that finishes in the first moment. The
                        // contention is the test; a burst that is over before
                        // the transfer starts exercises nothing.
                        while (!readingDone[0]) {
                            channel.write(Utf8.encode("x"));
                            typed[0]++;
                        }
                    } catch (Exception e) {
                        writerFailure[0] = e;
                    }
                }
            });
            typist.start();

            // Only the tail is kept: several megabytes in a StringBuffer would
            // be measuring the host's memory, not the protocol.
            boolean sawEnd = false;
            long total = 0;
            StringBuffer tail = new StringBuffer();
            byte[] buffer = new byte[4096];
            while (!sawEnd) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    System.out.println("        read ended after " + total
                        + " bytes; finished=" + channel.isFinished());
                    break;
                }
                total += n;
                tail.append(Utf8.decode(buffer, 0, n));
                if (tail.length() > 4096) {
                    tail.delete(0, tail.length() - 2048);
                }
                if (tail.toString().indexOf("300000") >= 0) {
                    sawEnd = true;
                }
            }
            readingDone[0] = true;
            typist.join(30000);

            checkTrue("typing while output arrives does not break the writer",
                writerFailure[0] == null);
            checkTrue("all of the output arrived, past several window refills",
                sawEnd && total > 1024 * 1024);
            System.out.println("        " + (total / 1024) + " KB read while "
                + typed[0] + " keystrokes were sent");

            // Ctrl-U first, to throw away the line of 'x' the typing left.
            channel.write(new byte[] { 0x15 });
            channel.write(Utf8.encode("echo st''ill-alive\n"));

            StringBuffer after = new StringBuffer();
            long deadline = System.currentTimeMillis() + 15000;
            while (after.toString().indexOf("still-alive") < 0
                    && System.currentTimeMillis() < deadline) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                after.append(Utf8.decode(buffer, 0, n));
            }
            checkTrue("the connection still works afterwards",
                after.toString().indexOf("still-alive") >= 0);

            channel.write(Utf8.encode("exit\n"));
            channel.close();
        } finally {
            socket.close();
        }
    }

    /**
     * A server asking to rekey mid-session.
     *
     * OpenSSH does this after about a gigabyte or an hour. Before it was
     * handled, the KEXINIT reached the channel and the session died with a
     * complaint about an unexpected message — an hour into a connection, for no
     * visible reason.
     *
     * Waiting an hour is not a test, so this runs against a throwaway server
     * with RekeyLimit set to 64 KB (tools/rekey-server.sh). It is deliberately
     * not the shared container: that one is what the handset connects to.
     */
    private static void survivesARekey() throws Exception {
        Socket socket;
        try {
            socket = new Socket(host, rekeyPort);
        } catch (IOException e) {
            System.out.println("  SKIP  rekey: nothing on " + host + ":" + rekeyPort
                + " (tools/rekey-server.sh)");
            return;
        }
        try {
            socket.setSoTimeout(30000);
            EntropyPool random = new EntropyPool();
            random.seed();
            Connection connection = new Connection(
                socket.getInputStream(), socket.getOutputStream(), random);
            connection.handshake();
            byte[] firstSessionId = connection.sessionId();

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();
            auth.queryMethods();
            auth.password(password);

            Channel channel = Channel.openSession(connection);
            channel.requestPty("xterm", 60, 25);
            channel.requestShell();

            // Well past 64 KB, so the server asks to rekey more than once.
            channel.write(Utf8.encode("seq 1 10''0000\n"));

            long total = 0;
            boolean sawEnd = false;
            StringBuffer tail = new StringBuffer();
            byte[] buffer = new byte[4096];
            while (!sawEnd) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                total += n;
                tail.append(Utf8.decode(buffer, 0, n));
                if (tail.length() > 4096) {
                    tail.delete(0, tail.length() - 2048);
                }
                if (tail.toString().indexOf("100000") >= 0) {
                    sawEnd = true;
                }
            }

            checkTrue("a session survives the rekeys a 64 KB limit forces",
                sawEnd && total > 64 * 1024);
            System.out.println("        " + (total / 1024) + " KB through a "
                + (total / 65536) + "-rekey session");

            // The session identifier is fixed at the first exchange for the
            // life of the connection: it is what the authentication signature
            // was bound to, so replacing it would invalidate it after the fact.
            checkTrue("the session identifier did not change",
                sameBytes(firstSessionId, connection.sessionId()));

            channel.write(Utf8.encode("echo st''ill-alive\n"));
            StringBuffer after = new StringBuffer();
            long deadline = System.currentTimeMillis() + 15000;
            while (after.toString().indexOf("still-alive") < 0
                    && System.currentTimeMillis() < deadline) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                after.append(Utf8.decode(buffer, 0, n));
            }
            checkTrue("the connection still works after rekeying",
                after.toString().indexOf("still-alive") >= 0);

            channel.write(Utf8.encode("exit\n"));
            channel.close();
        } finally {
            socket.close();
        }
    }

    /**
     * Public key authentication, end to end.
     *
     * The one part of the protocol that had never been confirmed: signing
     * matches the RFC 8032 vectors and the server parses our request, but
     * whether OpenSSH *accepts* the signature needs a key in an
     * authorized_keys file. The throwaway server carries one — the RFC 8032
     * test vector 3 seed, published in the RFC and used in this project's
     * crypto vectors, which secures nothing.
     */
    private static void authenticatesWithAKey() throws Exception {
        Socket socket;
        try {
            socket = new Socket(host, rekeyPort);
        } catch (IOException e) {
            System.out.println("  SKIP  publickey: nothing on " + host + ":" + rekeyPort
                + " (tools/rekey-server.sh)");
            return;
        }
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

            byte[] seed = hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
            checkTrue("OpenSSH accepts a signature we made", auth.publicKey(seed).succeeded());

            // And a key the server has not been given must be refused, or the
            // test above would prove only that the server accepts anything.
            Socket second = new Socket(host, rekeyPort);
            try {
                second.setSoTimeout(20000);
                EntropyPool r2 = new EntropyPool();
                r2.seed();
                Connection c2 = new Connection(
                    second.getInputStream(), second.getOutputStream(), r2);
                c2.handshake();
                UserAuth a2 = new UserAuth(c2, user);
                a2.begin();
                a2.queryMethods();
                byte[] other =
                    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
                checkTrue("an unauthorised key is refused", !a2.publicKey(other).succeeded());
            } finally {
                second.close();
            }
        } finally {
            socket.close();
        }
    }

    /** What tools/wsbridge-test.json is started with. Not a secret; a fixture. */
    private static final String BRIDGE_KEY = "spike2-bridge-key-not-a-secret";
    private static final String BRIDGE_TARGET = "testserver";

    /**
     * A full session carried inside an authenticated WebSocket bridge.
     *
     * This is how the handset reaches a network whose only entrance speaks
     * HTTP: it cannot run a VPN, and behind Cloudflare there is no raw TCP
     * route to fall back on. The bridge on the far side turns the frames back
     * into a socket — but only for someone holding the key, and only to a
     * machine it was configured to reach.
     *
     * The bridge used here is written from RFC 6455 independently of the
     * client, which is the point — a client tested against its own idea of the
     * protocol proves nothing.
     */
    private static void reachesAServerThroughAWebSocket() throws Exception {
        Socket socket;
        try {
            socket = new Socket(host, 8090);
        } catch (IOException e) {
            System.out.println("  SKIP  websocket: nothing on " + host + ":8090");
            return;
        }
        try {
            socket.setSoTimeout(20000);
            EntropyPool random = new EntropyPool();
            random.seed();

            WebSocket ws = WebSocket.connect(socket.getInputStream(), socket.getOutputStream(),
                host + ":8090", "/", random);
            checkTrue("the bridge upgrades the connection", ws != null);

            String[] targets = BridgeAuth.authenticate(
                ws.inputStream(), ws.outputStream(), BRIDGE_KEY);
            checkTrue("the bridge names what it will reach",
                contains(targets, BRIDGE_TARGET));
            BridgeAuth.open(ws.inputStream(), ws.outputStream(), BRIDGE_TARGET);

            // From here nothing knows it is not a socket, which is the whole
            // reason Connection was built to take streams.
            Connection connection = new Connection(ws.inputStream(), ws.outputStream(), random);
            HostKey key = connection.handshake();
            checkTrue("the key exchange completes through the WebSocket",
                "SHA256:9tqjakW/Ia6U4hT3VgAv8EXXCxC1d3ez9mr5qjVTRZs".equals(key.fingerprint()));

            UserAuth auth = new UserAuth(connection, user);
            auth.begin();
            auth.queryMethods();
            checkTrue("authentication works through the WebSocket",
                auth.password(password).succeeded());

            Channel channel = Channel.openSession(connection);
            channel.requestPty("xterm", 60, 25);
            channel.requestShell();
            channel.write(Utf8.encode("echo thro''ugh-the-tunnel; exit\n"));

            StringBuffer output = new StringBuffer();
            byte[] buffer = new byte[4096];
            for (;;) {
                int n = channel.read(buffer, 0, buffer.length);
                if (n < 0) {
                    break;
                }
                output.append(Utf8.decode(buffer, 0, n));
            }
            checkTrue("a shell runs through the WebSocket",
                output.toString().indexOf("through-the-tunnel") >= 0);
            channel.close();
        } finally {
            socket.close();
        }
    }

    /**
     * The other half of the bridge's job: refusing.
     *
     * Run against the same bridge and the same reachable server, so a pass
     * means the key was what stopped it and not something incidental. Without
     * this the suite would prove the door opens and say nothing about whether
     * it is ever shut.
     */
    private static void refusesAWrongBridgeKey() throws Exception {
        Socket socket;
        try {
            socket = new Socket(host, 8090);
        } catch (IOException e) {
            System.out.println("  SKIP  websocket refusal: nothing on " + host + ":8090");
            return;
        }
        try {
            socket.setSoTimeout(20000);
            EntropyPool random = new EntropyPool();
            random.seed();

            WebSocket ws = WebSocket.connect(socket.getInputStream(), socket.getOutputStream(),
                host + ":8090", "/", random);
            try {
                BridgeAuth.authenticate(ws.inputStream(), ws.outputStream(),
                    BRIDGE_KEY + "x");
                checkTrue("a wrong bridge key is refused", false);
            } catch (IOException e) {
                checkTrue("a wrong bridge key is refused", true);
            }
        } finally {
            socket.close();
        }

        // And a name the bridge does not have gets nothing, even with the key.
        Socket second = new Socket(host, 8090);
        try {
            second.setSoTimeout(20000);
            EntropyPool random = new EntropyPool();
            random.seed();

            WebSocket ws = WebSocket.connect(second.getInputStream(),
                second.getOutputStream(), host + ":8090", "/", random);
            BridgeAuth.authenticate(ws.inputStream(), ws.outputStream(), BRIDGE_KEY);
            try {
                BridgeAuth.open(ws.inputStream(), ws.outputStream(), "not-configured");
                checkTrue("a target outside the allowlist is refused", false);
            } catch (IOException e) {
                checkTrue("a target outside the allowlist is refused", true);
            }
        } finally {
            second.close();
        }
    }

    private static boolean contains(String[] values, String wanted) {
        for (int i = 0; i < values.length; i++) {
            if (wanted.equals(values[i])) {
                return true;
            }
        }
        return false;
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
