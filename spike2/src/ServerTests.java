import berryssh.crypto.EntropyPool;
import berryssh.protocol.KexInit;
import berryssh.protocol.Message;
import berryssh.protocol.Negotiation;
import berryssh.protocol.Transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * The half of the verification that needs a real OpenSSH server.
 *
 * The offline vectors prove the encodings; only a real server proves the
 * protocol. Several of these issues have no meaningful self-test — a key
 * exchange either convinces an OpenSSH server or it does not.
 *
 * This runs against the container the project keeps for the purpose (see the
 * README), reached over a plain socket. It is host-only: `java.net` does not
 * exist in CLDC, where the same streams come from
 * `Connector.open("socket://host:port")`. Everything under test takes streams
 * rather than a socket precisely so that this substitution is the only
 * difference between here and the device.
 */
public class ServerTests {

    private static String host = "127.0.0.1";
    private static int port = 2222;

    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        if (args.length >= 1) {
            host = args[0];
        }
        if (args.length >= 2) {
            port = Integer.parseInt(args[1]);
        }

        System.out.println("  ..    against " + host + ":" + port);
        negotiatesWithRealServer();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /**
     * RFC 4253 sections 4.2 and 7.1 against a server that did not read our
     * code: the identification strings have to be mutually acceptable and the
     * negotiated set has to be the modern one, on a server that also still
     * offers the 2011 algorithms this project exists to avoid.
     */
    private static void negotiatesWithRealServer() throws Exception {
        Socket socket = new Socket(host, port);
        try {
            socket.setSoTimeout(10000);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            Transport transport = new Transport(in, out);
            transport.exchangeVersions();
            checkTrue("the server accepts our identification and returns its own",
                transport.serverVersion() != null
                    && transport.serverVersion().startsWith("SSH-2.0-"));
            System.out.println("        server is " + transport.serverVersion());

            EntropyPool random = new EntropyPool();
            random.seed();
            KexInit ours = KexInit.client(random);
            transport.writePacket(ours.payload());

            byte[] reply = transport.readPacket();
            checkTrue("the server answers KEXINIT with KEXINIT",
                (reply[0] & 0xff) == Message.KEXINIT);

            KexInit theirs = KexInit.parse(reply);
            Negotiation negotiated = Negotiation.between(ours, theirs);

            checkTrue("negotiated curve25519-sha256",
                "curve25519-sha256".equals(negotiated.kex()));
            checkTrue("negotiated ssh-ed25519",
                "ssh-ed25519".equals(negotiated.hostKey()));
            checkTrue("negotiated chacha20-poly1305@openssh.com both ways",
                "chacha20-poly1305@openssh.com".equals(negotiated.cipherClientToServer())
                    && "chacha20-poly1305@openssh.com".equals(negotiated.cipherServerToClient()));
            checkTrue("negotiated no compression",
                "none".equals(negotiated.compressionClientToServer())
                    && "none".equals(negotiated.compressionServerToClient()));

            // The container deliberately still offers the 2011 algorithms, so
            // this confirms the modern set was a choice rather than the only
            // thing on the table.
            boolean serverStillOffersLegacy = false;
            for (int i = 0; i < theirs.kexAlgorithms().length; i++) {
                if ("diffie-hellman-group14-sha1".equals(theirs.kexAlgorithms()[i])) {
                    serverStillOffersLegacy = true;
                }
            }
            checkTrue("the server also offered the legacy key exchange, and we did not take it",
                serverStillOffersLegacy);
        } finally {
            socket.close();
        }
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
