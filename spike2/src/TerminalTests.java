import berryssh.device.Keyboard;
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
        dispatchesKeys();
        keepsScrollback();

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

    /**
     * Key dispatch, and specifically the ordering that got it wrong on the
     * device.
     *
     * MIDP lets a device map keys to game actions, and BlackBerry maps the
     * letters so that games written for a numeric keypad work on a QWERTY: 'w'
     * reports UP, 'a' reports LEFT. Consulting the game action before the
     * character therefore turns typing into cursor movement on exactly those
     * letters and leaves every other key working — which is why it presented as
     * "some keys do nothing and some produce something else" rather than as a
     * keyboard that was plainly broken.
     *
     * The MIDP game action values are written out here rather than imported, so
     * the test does not depend on the stub jar being on the host classpath.
     */
    private static void dispatchesKeys() {
        final int UP = 1, LEFT = 2, RIGHT = 5, DOWN = 6;

        // A letter that the device also calls a direction is still a letter.
        checkTrue("'w' types 'w' even though the device reports UP",
            "w".equals(sendKey('w', UP)));
        checkTrue("'a' types 'a' even though the device reports LEFT",
            "a".equals(sendKey('a', LEFT)));
        checkTrue("'s' types 's' even though the device reports DOWN",
            "s".equals(sendKey('s', DOWN)));
        checkTrue("'d' types 'd' even though the device reports RIGHT",
            "d".equals(sendKey('d', RIGHT)));

        checkTrue("a letter with no game action still types itself",
            "q".equals(sendKey('q', 0)));
        checkTrue("space is a character, not a fire button",
            " ".equals(sendKey(' ', 8)));

        // The trackpad reports a direction and no character, so it still moves.
        String up = sendKey(-1, UP);
        checkTrue("a key with no character and a direction sends a cursor sequence",
            up.length() >= 3 && up.charAt(0) == 27);

        checkTrue("Enter sends a carriage return", sendKey(13, 0).indexOf('\r') >= 0);
        // Backspace has to reach VT320 through keyPressed: keyTyped drops it,
        // which sent nothing at all and left no way to correct a typo.
        checkTrue("Backspace sends something", sendKey(8, 0).length() > 0);
        checkTrue("Delete deletes too, on a handset with one such key",
            sendKey(127, 0).equals(sendKey(8, 0)) && sendKey(127, 0).length() > 0);
        checkTrue("Tab sends one", "\t".equals(sendKey(9, 0)));

        // A key we know nothing about must send nothing rather than a guess.
        checkTrue("an unmapped key sends nothing", "".equals(sendKey(-999, 0)));

        // Sticky Ctrl, on the character path.
        Headless t = new Headless(20, 5);
        Keyboard k = new Keyboard(t);
        k.toggleControl();
        checkTrue("Ctrl is armed", k.controlPending());
        k.keyPressed('c', 0);
        checkTrue("Ctrl-C sends 0x03 and disarms",
            t.sent.length() == 1 && t.sent.charAt(0) == 3 && !k.controlPending());

        // Ctrl-I must be Tab. Under a Turkish locale a case fold would make
        // this the one letter of the alphabet that stopped working.
        checkTrue("Ctrl-I is Tab under any locale", Keyboard.controlOf('i') == 9);
        checkTrue("Ctrl-I is Tab from the capital too", Keyboard.controlOf('I') == 9);
    }

    /**
     * Scrollback, which the emulator does not have until it is asked for.
     *
     * The constructor sizes the buffer to the screen, so a terminal built and
     * left alone keeps nothing: paging up would show the screen already on
     * display. This is the mechanism the canvas reads through, checked here
     * because the canvas itself needs MIDP and cannot run on the host.
     */
    private static void keepsScrollback() {
        Headless plain = new Headless(20, 4);
        plain.putString("one\r\ntwo\r\nthree\r\nfour\r\nfive\r\n");
        checkTrue("without asking, nothing is kept above the screen",
            plain.screenBase == 0);

        Headless t = new Headless(20, 4);
        t.setScrollbackBufferSize(100);
        for (int i = 1; i <= 40; i++) {
            t.putString("line" + i + "\r\n");
        }

        checkTrue("history accumulates above the live screen", t.screenBase > 0);

        // The live screen still shows the end.
        checkTrue("the live screen is the most recent output",
            "line40".equals(row(t, 2, 6)));

        // And the buffer holds what scrolled past, which is what the canvas
        // reads when it pages up.
        boolean foundEarlier = false;
        for (int line = 0; line < t.screenBase; line++) {
            StringBuffer sb = new StringBuffer();
            for (int c = 0; c < 6; c++) {
                sb.append((char) t.terminalData[line][c]);
            }
            if ("line10".equals(sb.toString())) {
                foundEarlier = true;
            }
        }
        checkTrue("a line that scrolled off is still in the buffer", foundEarlier);
    }

    /** Feeds one key through the dispatcher and returns what reached the wire. */
    private static String sendKey(int keyCode, int gameAction) {
        Headless t = new Headless(20, 5);
        new Keyboard(t).keyPressed(keyCode, gameAction);
        return t.sent.toString();
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
