package berryssh.protocol;

import java.io.IOException;

import berryssh.crypto.Ed25519;

/**
 * User authentication, RFC 4252.
 *
 * The shape of the exchange is worth stating because it is not obvious: a
 * failure carries the list of methods that could still work, so the `none`
 * method is not a way of logging in but a way of asking what the server will
 * accept. It is expected to fail, and its failure is the useful part.
 *
 * Usernames and passwords go on the wire as UTF-8 regardless of what the
 * device's default encoding is — see {@link Utf8} for why that is not a
 * theoretical point here.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class UserAuth {

    /** The service authentication is a gateway to. */
    public static final String CONNECTION_SERVICE = "ssh-connection";

    private static final String AUTH_SERVICE = "ssh-userauth";

    private final Connection connection;
    private final String user;
    private String banner;

    public UserAuth(Connection connection, String user) {
        this.connection = connection;
        this.user = user;
    }

    /**
     * Anything the server asked to be shown to the user.
     *
     * A banner is often the one place a server states its terms of use, so it
     * is collected rather than dropped, and it can arrive at any point during
     * authentication including before the first request.
     */
    public String banner() {
        return banner;
    }

    /** The outcome of one attempt. */
    public static final class Result {

        private final boolean succeeded;
        private final boolean partial;
        private final String[] continueWith;

        Result(boolean succeeded, boolean partial, String[] continueWith) {
            this.succeeded = succeeded;
            this.partial = partial;
            this.continueWith = continueWith;
        }

        public boolean succeeded() {
            return succeeded;
        }

        /**
         * True when the method was accepted but the server wants another one as
         * well. The attempt worked; the session is simply not open yet, and
         * treating this as a failure would send the user round to retype a
         * password that was already correct.
         */
        public boolean partialSuccess() {
            return partial;
        }

        /** The methods the server says could still succeed. */
        public String[] methodsThatCanContinue() {
            return continueWith;
        }
    }

    /** Starts the authentication service. Must be called before any attempt. */
    public void begin() throws IOException {
        connection.requestService(AUTH_SERVICE);
    }

    /**
     * Asks the server what it will accept, using the `none` method.
     *
     * A server with no authentication configured at all may accept this, which
     * is why the result is returned rather than assumed to be a failure.
     */
    public Result queryMethods() throws IOException {
        WireWriter w = request("none");
        connection.transport().writePacket(w.toByteArray());
        return readOutcome();
    }

    public Result password(String password) throws IOException {
        WireWriter w = request("password");
        w.writeBoolean(false);
        w.writeString(Utf8.encode(password));
        connection.transport().writePacket(w.toByteArray());
        return readOutcome();
    }

    /**
     * Authenticates with an Ed25519 key, given the 32-byte seed OpenSSH stores
     * as the private key.
     *
     * The signature covers the session identifier as well as the request. That
     * binding is what stops a server from taking a signature made against it
     * and replaying it to a third party as the user: the session identifier
     * differs for every connection, so the signature only means anything on
     * the one it was made for.
     */
    public Result publicKey(byte[] seed) throws IOException {
        byte[] publicKey = Ed25519.publicKey(seed);

        WireWriter blob = new WireWriter(64);
        blob.writeAsciiString(HostKey.ALGORITHM);
        blob.writeString(publicKey);
        byte[] keyBlob = blob.toByteArray();

        WireWriter signed = new WireWriter(256);
        signed.writeString(connection.sessionId());
        appendRequest(signed, "publickey");
        signed.writeBoolean(true);
        signed.writeAsciiString(HostKey.ALGORITHM);
        signed.writeString(keyBlob);

        byte[] signature = Ed25519.sign(seed, signed.toByteArray());
        WireWriter signatureBlob = new WireWriter(96);
        signatureBlob.writeAsciiString(HostKey.ALGORITHM);
        signatureBlob.writeString(signature);

        WireWriter w = request("publickey");
        w.writeBoolean(true);
        w.writeAsciiString(HostKey.ALGORITHM);
        w.writeString(keyBlob);
        w.writeString(signatureBlob.toByteArray());
        connection.transport().writePacket(w.toByteArray());
        return readOutcome();
    }

    private WireWriter request(String method) {
        WireWriter w = new WireWriter(256);
        appendRequest(w, method);
        return w;
    }

    private void appendRequest(WireWriter w, String method) {
        w.writeByte(Message.USERAUTH_REQUEST);
        w.writeString(Utf8.encode(user));
        w.writeAsciiString(CONNECTION_SERVICE);
        w.writeAsciiString(method);
    }

    private Result readOutcome() throws IOException {
        for (;;) {
            byte[] payload = connection.transport().readMessage();
            int type = payload[0] & 0xff;

            if (type == Message.USERAUTH_BANNER) {
                WireReader r = new WireReader(payload);
                r.readByte();
                banner = Utf8.decode(r.readString());
                continue;
            }
            if (type == Message.USERAUTH_SUCCESS) {
                return new Result(true, false, new String[0]);
            }
            if (type == Message.USERAUTH_FAILURE) {
                WireReader r = new WireReader(payload);
                r.readByte();
                String[] continueWith = r.readNameList();
                boolean partial = r.readBoolean();
                return new Result(false, partial, continueWith);
            }
            // 60 is method-specific. In the publickey method it is PK_OK, an
            // answer to a query we never send: we always sign up front, because
            // asking first costs an extra round trip on a link where round
            // trips are the expensive part.
            throw new SshException("unexpected " + Message.name(type)
                + " during authentication");
        }
    }
}
