import berryssh.terminal.VT320;

import java.io.IOException;

/**
 * The terminal emulator, driven directly.
 *
 * VT320 came across from BBSSH nearly unchanged, so these are not vectors for
 * new code — they check that the port kept working, and pin the behaviours the
 * renderer and the SSH layer depend on. Escape sequence handling in the round
 * is checked against a real shell in ServerTests, since that produces sequences
 * nobody thought to write down here.
 *
 * Escapes are built with {@link #esc} rather than written literally: a source
 * file with invisible control bytes in it cannot be reviewed, and a stray one
 * would be impossible to see.
 *
 * Host-only, like the rest of the suite.
 */
public class TerminalTests {

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        writesAndReads();
        wraps();
        handlesEscapeSequences();
        scrolls();
        sendsKeys();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /** A terminal that records what it would have sent, and draws nowhere. */
    private static final class Headless extends VT320 {
        final StringBuffer sent = new StringBuffer();

        Headless(int columns, int rows) {
            super(columns, rows);
        }

        public void sendData(byte[] b, int offset, int length) throws IOException {
            for (int i = 0; i < length; i++) {
                sent.append((char) (b[offset + i] & 0xff));
            }
        }

        public void beep() {
        }

        public void resize() {
        }
    }

    private static void writesAndReads() {
        Headless t = new Headless(60, 25);
        t.putString("hello");
        checkTrue("text written appears on the screen", "hello".equals(row(t, 0, 5)));

        t.putString("\r\nsecond");
        checkTrue("carriage return and newline move to the next row",
            "second".equals(row(t, 1, 6)));
    }

    private static void wraps() {
        Headless t = new Headless(10, 4);
        t.putString("0123456789abc");
        checkTrue("text past the last column wraps to the next row",
            "0123456789".equals(row(t, 0, 10)) && "abc".equals(row(t, 1, 3)));
    }

    private static void handlesEscapeSequences() {
        Headless t = new Headless(20, 5);

        // CUP is one-based, so row 3 column 5 is index (4, 2).
        t.putString(esc("[3;5H") + "x");
        checkTrue("cursor addressing puts the character where it was asked",
            t.getChar(4, 2) == 'x');

        // Erase-in-display clears to NUL and leaves the cursor alone, which is
        // what a real terminal does — a program that wanted the cursor moved
        // would have said so, and clearing usually precedes a redraw.
        t.putString(esc("[2J"));
        checkTrue("erase-in-display clears the screen", t.getChar(4, 2) < 32);

        // The cursor really did stay put: this lands just past where the 'x'
        // was, because writing it advanced the cursor one column.
        t.putString(esc("[31m") + "red" + esc("[0m"));
        checkTrue("colour sequences are consumed rather than printed",
            "red".equals(rowFrom(t, 2, 5, 3)));

        // An unrecognised sequence has to be swallowed whole. A terminal that
        // printed its own confusion would corrupt the screen at the first
        // surprise, and a real session is full of surprises.
        Headless unknown = new Headless(20, 5);
        unknown.putString(esc("[?9999h") + "after");
        checkTrue("an unrecognised sequence is swallowed",
            "after".equals(row(unknown, 0, 5)));
    }

    private static void scrolls() {
        Headless t = new Headless(10, 3);
        t.putString("one\r\ntwo\r\nthree\r\nfour");
        checkTrue("output past the last row scrolls the screen",
            "two".equals(row(t, 0, 3))
                && "three".equals(row(t, 1, 5))
                && "four".equals(row(t, 2, 4)));
    }

    private static void sendsKeys() {
        Headless t = new Headless(20, 5);
        t.keyTyped(VT320.VK_ENTER, (char) 0, 0);
        checkTrue("Enter sends a carriage return", t.sent.toString().indexOf('\r') >= 0);

        // The cursor keys are why a terminal needs a keyboard mapping at all:
        // they are escape sequences rather than characters, so there is nothing
        // for a plain key-to-character table to produce.
        Headless arrows = new Headless(20, 5);
        arrows.keyPressed(VT320.VK_UP, 0);
        checkTrue("the up arrow sends an escape sequence",
            arrows.sent.length() >= 3 && arrows.sent.charAt(0) == 27);
    }

    /** Builds an escape sequence without putting a control byte in the source. */
    private static String esc(String rest) {
        return ((char) 27) + rest;
    }

    private static String row(VT320 t, int line, int length) {
        return rowFrom(t, line, 0, length);
    }

    private static String rowFrom(VT320 t, int line, int column, int length) {
        StringBuffer sb = new StringBuffer(length);
        for (int i = 0; i < length; i++) {
            sb.append(t.getChar(column + i, line));
        }
        return sb.toString();
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
