package berryssh.terminal;

/**
 * The logging {@link VT320} expects, which is as little as it can be.
 *
 * BBSSH's logger is left behind with the rest of its platform. What the
 * emulator actually uses it for is reporting escape sequences it does not
 * recognise, which is diagnostic rather than operational — a terminal's job
 * when it meets one is to ignore it and carry on, and it does.
 *
 * Off by default. On the handset there is no console for this to reach, and a
 * VT320 driven by a chatty program can produce these faster than they could be
 * read. Turning it on is for finding out why something rendered oddly, with the
 * client driven from the host.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Log {

    private static boolean enabled;

    private Log() {
    }

    public static void setEnabled(boolean on) {
        enabled = on;
    }

    public static void debug(String message) {
        if (enabled) {
            System.out.println("debug: " + message);
        }
    }

    public static void warn(String message) {
        if (enabled) {
            System.out.println("warn: " + message);
        }
    }

    /**
     * Errors are printed whether or not logging is on. They report a failure to
     * send, which is not something to discard silently.
     */
    public static void error(String message) {
        System.out.println("error: " + message);
    }
}
