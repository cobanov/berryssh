package berryssh.protocol;

import java.io.IOException;

/**
 * A protocol error.
 *
 * It extends IOException so that a caller driving the connection needs one
 * catch for both a broken socket and a malformed packet: at that level the
 * remedy is the same either way, which is to drop the connection.
 */
public class SshException extends IOException {

    public SshException(String message) {
        super(message);
    }
}
