package berryssh.protocol;

import java.io.IOException;

/**
 * A session channel: a pty, a shell, and the bytes going both ways.
 * RFC 4254.
 *
 * The flow control is the part that has to be right rather than merely
 * present. Each side advertises a window and may not send past it; a client
 * that forgets to top its window up receives a few tens of kilobytes and then
 * hangs for good, which reads as a network fault rather than as a bug here.
 *
 * Only one channel is opened, because the client does one thing. That keeps
 * dispatch to a single recipient check rather than a table, and it is the
 * reason a message for another channel is an error instead of something to
 * route.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Channel {

    /**
     * 2 MB. Generous on purpose: every refill is a packet, and on this link the
     * round trip costs far more than the memory does — the device measured
     * ~357 MB of free heap.
     */
    private static final int INITIAL_WINDOW = 2 * 1024 * 1024;

    /** Below half, the window is topped back up. */
    private static final int REFILL_AT = INITIAL_WINDOW / 2;

    private static final int MAX_PACKET = 32 * 1024;

    /** Our channel number. With one channel it can be a constant. */
    private static final int LOCAL_ID = 0;

    private final Connection connection;

    /**
     * Guards the server's window, and is what a blocked writer waits on.
     *
     * The window is decremented by whoever is sending — the UI thread — and
     * replenished by whoever is reading, so it is the one piece of channel
     * state two threads genuinely share.
     */
    private final Object windowLock = new Object();

    private int remoteId;
    private long remoteWindow;
    private int remoteMaxPacket;
    private long localWindow = INITIAL_WINDOW;

    private byte[] pending = new byte[0];
    private int pendingAt;

    private volatile boolean eof;
    private volatile boolean closed;
    private int exitStatus = -1;

    private Channel(Connection connection) {
        this.connection = connection;
    }

    /** Opens a session channel and waits for the server to confirm it. */
    public static Channel openSession(Connection connection) throws IOException {
        Channel channel = new Channel(connection);

        WireWriter w = new WireWriter(64);
        w.writeByte(Message.CHANNEL_OPEN);
        w.writeAsciiString("session");
        w.writeUint32(LOCAL_ID);
        w.writeUint32(INITIAL_WINDOW);
        w.writeUint32(MAX_PACKET);
        connection.transport().writePacket(w.toByteArray());

        for (;;) {
            byte[] payload = connection.transport().readMessage();
            int type = payload[0] & 0xff;
            WireReader r = new WireReader(payload);
            r.readByte();

            if (type == Message.CHANNEL_OPEN_CONFIRMATION) {
                r.readUint32();
                channel.remoteId = (int) r.readUint32();
                channel.remoteWindow = r.readUint32();
                channel.remoteMaxPacket = (int) r.readUint32();
                return channel;
            }
            if (type == Message.CHANNEL_OPEN_FAILURE) {
                r.readUint32();
                long reason = r.readUint32();
                throw new SshException("the server refused a session channel ("
                    + reason + "): " + r.readAsciiString());
            }
            channel.handleOther(type, payload);
        }
    }

    /**
     * Asks for a pseudo-terminal.
     *
     * The pixel dimensions are sent as zero, which tells the server to work
     * from the character grid. That is the honest answer here: the terminal is
     * a bitmap font on a canvas, so its pixel size says nothing a program could
     * use.
     */
    public void requestPty(String term, int columns, int rows) throws IOException {
        WireWriter w = new WireWriter(64);
        w.writeByte(Message.CHANNEL_REQUEST);
        w.writeUint32(remoteId);
        w.writeAsciiString("pty-req");
        w.writeBoolean(true);
        w.writeAsciiString(term);
        w.writeUint32(columns);
        w.writeUint32(rows);
        w.writeUint32(0);
        w.writeUint32(0);
        // Terminal modes, as opcode-value pairs ended by TTY_OP_END. Empty:
        // the server's defaults are what a shell would get locally.
        w.writeString(new byte[] { 0 });
        connection.transport().writePacket(w.toByteArray());
        awaitReply("pty-req");
    }

    public void requestShell() throws IOException {
        WireWriter w = new WireWriter(32);
        w.writeByte(Message.CHANNEL_REQUEST);
        w.writeUint32(remoteId);
        w.writeAsciiString("shell");
        w.writeBoolean(true);
        connection.transport().writePacket(w.toByteArray());
        awaitReply("shell");
    }

    /** Tells the server the terminal changed size. RFC 4254 sends no reply to this. */
    public void windowChange(int columns, int rows) throws IOException {
        WireWriter w = new WireWriter(48);
        w.writeByte(Message.CHANNEL_REQUEST);
        w.writeUint32(remoteId);
        w.writeAsciiString("window-change");
        w.writeBoolean(false);
        w.writeUint32(columns);
        w.writeUint32(rows);
        w.writeUint32(0);
        w.writeUint32(0);
        connection.transport().writePacket(w.toByteArray());
    }

    /**
     * Sends data, splitting it to the server's maximum packet size and waiting
     * when its window is full.
     */
    public void write(byte[] data, int offset, int length) throws IOException {
        while (length > 0) {
            int take;
            synchronized (windowLock) {
                // Wait to be told the window opened; do not go and read for it.
                // Reading here would put a second thread on the socket while
                // the reader is already parked on it, and both would advance
                // the receive sequence — so the nonces would diverge and
                // nothing would decrypt from that point on.
                while (remoteWindow == 0 && !closed) {
                    try {
                        windowLock.wait();
                    } catch (InterruptedException e) {
                        throw new SshException("interrupted waiting for the channel window");
                    }
                }
                if (closed) {
                    throw new SshException("the channel closed before the data could be sent");
                }
                take = length;
                if (take > remoteMaxPacket) {
                    take = remoteMaxPacket;
                }
                if (take > remoteWindow) {
                    take = (int) remoteWindow;
                }
                remoteWindow -= take;
            }

            // Sent outside the lock: writePacket serialises itself, and holding
            // this one across a socket write would stall the reader's window
            // updates behind it.
            WireWriter w = new WireWriter(take + 16);
            w.writeByte(Message.CHANNEL_DATA);
            w.writeUint32(remoteId);
            w.writeString(data, offset, take);
            connection.transport().writePacket(w.toByteArray());

            offset += take;
            length -= take;
        }
    }

    public void write(byte[] data) throws IOException {
        write(data, 0, data.length);
    }

    /**
     * Reads what the server has sent, blocking until there is some.
     *
     * @return the number of bytes read, or -1 once the server has finished
     */
    public int read(byte[] buffer, int offset, int length) throws IOException {
        while (pendingAt == pending.length) {
            if (eof || closed) {
                return -1;
            }
            pump();
        }
        int take = pending.length - pendingAt;
        if (take > length) {
            take = length;
        }
        System.arraycopy(pending, pendingAt, buffer, offset, take);
        pendingAt += take;

        // Credit the server for what has actually been consumed, not for what
        // arrived. Topping up on arrival would advertise room we do not have.
        localWindow -= take;
        if (localWindow <= REFILL_AT) {
            long top = INITIAL_WINDOW - localWindow;
            WireWriter w = new WireWriter(16);
            w.writeByte(Message.CHANNEL_WINDOW_ADJUST);
            w.writeUint32(remoteId);
            w.writeUint32(top);
            connection.transport().writePacket(w.toByteArray());
            localWindow += top;
        }
        return take;
    }

    /** True once the server has sent EOF or closed the channel. */
    public boolean isFinished() {
        return (eof || closed) && pendingAt == pending.length;
    }

    /**
     * The shell's exit status, or -1 if none was seen.
     *
     * Only captured if it arrives before EOF. Reading stops at EOF because
     * that is when the server has promised there is no more data, and carrying
     * on until CLOSE would hang against a server that half-closes and keeps the
     * channel open for ours. A terminal does not act on the status, so the
     * trade favours never hanging.
     */
    public int exitStatus() {
        return exitStatus;
    }

    public void close() throws IOException {
        synchronized (windowLock) {
            if (closed) {
                return;
            }
            closed = true;
            windowLock.notifyAll();
        }
        WireWriter w = new WireWriter(16);
        w.writeByte(Message.CHANNEL_CLOSE);
        w.writeUint32(remoteId);
        connection.transport().writePacket(w.toByteArray());
    }

    /** Reads and dispatches exactly one message. */
    private void pump() throws IOException {
        byte[] payload = connection.transport().readMessage();
        int type = payload[0] & 0xff;

        if (type == Message.CHANNEL_DATA) {
            WireReader r = new WireReader(payload);
            r.readByte();
            checkRecipient(r.readUint32());
            append(r.readString());
            return;
        }
        if (type == Message.CHANNEL_EXTENDED_DATA) {
            WireReader r = new WireReader(payload);
            r.readByte();
            checkRecipient(r.readUint32());
            r.readUint32();
            // With a pty the server merges stderr into the terminal stream
            // anyway, so anything arriving here belongs in the same place: a
            // terminal that hid it would lose error messages entirely.
            append(r.readString());
            return;
        }
        handleOther(type, payload);
    }

    private void handleOther(int type, byte[] payload) throws IOException {
        WireReader r = new WireReader(payload);
        r.readByte();

        if (type == Message.CHANNEL_WINDOW_ADJUST) {
            checkRecipient(r.readUint32());
            long more = r.readUint32();
            synchronized (windowLock) {
                remoteWindow += more;
                windowLock.notifyAll();
            }
            return;
        }
        if (type == Message.CHANNEL_EOF) {
            eof = true;
            return;
        }
        if (type == Message.CHANNEL_CLOSE) {
            // Waking any blocked writer matters as much as the flag: without
            // it, a send that was waiting on the window waits for ever.
            synchronized (windowLock) {
                closed = true;
                windowLock.notifyAll();
            }
            return;
        }
        if (type == Message.CHANNEL_REQUEST) {
            r.readUint32();
            String request = r.readAsciiString();
            boolean wantReply = r.readBoolean();
            if ("exit-status".equals(request)) {
                exitStatus = (int) r.readUint32();
            }
            if (wantReply) {
                // We implement no channel requests, and saying so is required:
                // a server waiting on a reply that never comes stalls.
                WireWriter w = new WireWriter(16);
                w.writeByte(Message.CHANNEL_FAILURE);
                w.writeUint32(remoteId);
                connection.transport().writePacket(w.toByteArray());
            }
            return;
        }
        if (type == Message.GLOBAL_REQUEST) {
            r.readAsciiString();
            if (r.readBoolean()) {
                WireWriter w = new WireWriter(8);
                w.writeByte(Message.REQUEST_FAILURE);
                connection.transport().writePacket(w.toByteArray());
            }
            return;
        }
        throw new SshException("unexpected " + Message.name(type) + " on a session channel");
    }

    private void awaitReply(String request) throws IOException {
        for (;;) {
            byte[] payload = connection.transport().readMessage();
            int type = payload[0] & 0xff;
            if (type == Message.CHANNEL_SUCCESS) {
                return;
            }
            if (type == Message.CHANNEL_FAILURE) {
                throw new SshException("the server refused " + request);
            }
            // Data can arrive before the reply does; it is not lost.
            if (type == Message.CHANNEL_DATA || type == Message.CHANNEL_EXTENDED_DATA) {
                WireReader r = new WireReader(payload);
                r.readByte();
                checkRecipient(r.readUint32());
                if (type == Message.CHANNEL_EXTENDED_DATA) {
                    r.readUint32();
                }
                append(r.readString());
                continue;
            }
            handleOther(type, payload);
        }
    }

    private void checkRecipient(long recipient) throws IOException {
        if (recipient != LOCAL_ID) {
            throw new SshException("message for channel " + recipient + ", which is not ours");
        }
    }

    private void append(byte[] data) {
        int left = pending.length - pendingAt;
        byte[] combined = new byte[left + data.length];
        System.arraycopy(pending, pendingAt, combined, 0, left);
        System.arraycopy(data, 0, combined, left, data.length);
        pending = combined;
        pendingAt = 0;
    }
}
