import berryssh.device.Keyboard;
import berryssh.terminal.BitmapFont;
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
        mapsCharactersToGlyphs();
        behavesLikeXterm();
        typesBeyondAscii();
        survivesHostileOutput();

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

    /**
     * The server is told this is an xterm, so programs send what the xterm
     * terminfo entry says to. Each of these was wrong, and each is something a
     * full-screen program does all the time.
     */
    private static void behavesLikeXterm() {
        Headless t = new Headless(20, 6);
        // "vpa". ncurses uses it whenever only the row changes.
        t.putString(esc("[3d") + "v");
        checkTrue("vertical position is one-based, like every other address",
            t.getChar(0, 2) == 'v');

        t.putString(esc("[2;4H") + esc("[6n"));
        checkTrue("the cursor position report is one-based",
            t.sent.toString().endsWith(esc("[2;4R")));

        Headless insert = new Headless(10, 2);
        insert.putString("abc" + esc("[1;2H") + esc("[@"));
        checkTrue("insert-character with no count inserts one",
            insert.getChar(0, 0) == 'a' && insert.getChar(1, 0) == ' '
                && insert.getChar(2, 0) == 'b' && insert.getChar(3, 0) == 'c');

        // "38;5;1" is red from the 256-colour palette. Its arguments used to
        // be read as attributes: 5 is blink, 1 is bold, and no colour was set.
        Headless colour = new Headless(10, 2);
        colour.putString(esc("[38;5;1m") + "r" + esc("[0m") + esc("[38;2;0;255;0m") + "g"
            + esc("[0m") + esc("[90m") + "d" + esc("[0m") + esc("[48;5;4m") + "b");
        checkTrue("a 256-colour foreground sets that colour and nothing else",
            attributes(colour, 0) == ((1 + 1) << 4));
        checkTrue("a true-colour foreground becomes the nearest of the sixteen",
            attributes(colour, 1) == (((2 + 1) << 4) | VT320.BOLD));
        checkTrue("bright black is drawn, as bold black, rather than dropped",
            attributes(colour, 2) == (((0 + 1) << 4) | VT320.BOLD));
        checkTrue("a 256-colour background sets the background",
            attributes(colour, 3) == ((4 + 1) << 8));

        // "reset" sends this. Honouring it left the emulator 80 columns wide
        // on a screen, and a pty, that were still 60.
        Headless narrow = new Headless(10, 3);
        narrow.putString(esc("[?3l") + "0123456789ab");
        checkTrue("the width does not change because a program asked",
            "ab".equals(row(narrow, 1, 2)));

        // What a shell prompt sends to set the window title, in both endings.
        Headless title = new Headless(20, 2);
        title.putString(esc("]0;user@host: ~") + "\u0007" + "x"
            + esc("]0;again") + esc("\\") + "y");
        checkTrue("a window title is swallowed, whichever way it ends",
            "xy".equals(row(title, 0, 2)));

        Headless cursor = new Headless(10, 2);
        cursor.putString(esc("[?25l"));
        boolean hidden = !cursor.showcursor;
        cursor.putString(esc("[?25h"));
        checkTrue("a program can hide the cursor and show it again",
            hidden && cursor.showcursor);
    }

    /** The attributes of a cell on the first row. */
    private static int attributes(VT320 t, int column) {
        return (int) (t.terminalData[t.screenBase][column] >>> 32);
    }

    /**
     * What is typed leaves as UTF-8. It used to leave as the low byte of each
     * character, which is the same thing only for ASCII.
     */
    private static void typesBeyondAscii() {
        Headless t = new Headless(20, 5);
        Keyboard keyboard = new Keyboard(t);
        keyboard.keyPressed(0x015f, 0);
        checkTrue("a typed s-cedilla is sent as its two UTF-8 bytes",
            "\u00c5\u009f".equals(t.sent.toString()));

        t.sent.setLength(0);
        keyboard.keyPressed(0x011f, 0);
        checkTrue("a typed g-breve is not sent as a control character",
            "\u00c4\u009f".equals(t.sent.toString()));

        // A pty erases on DEL. ^H works in a shell, whose line editor takes
        // both, and is typed into anything else that reads a line.
        t.sent.setLength(0);
        keyboard.keyPressed(8, 0);
        checkTrue("Backspace sends DEL, as xterm does",
            "\u007f".equals(t.sent.toString()));
    }

    /**
     * Every byte that reaches the emulator is the server's to choose, and a
     * `cat` of the wrong file chooses them at random. An exception in here ends
     * the session, so there must not be one.
     */
    private static void survivesHostileOutput() {
        String[] onceFatal = {
            esc("[") + repeat("1;", 40) + "m",   // more parameters than slots
            esc("[99999999999999999999L"),       // a count that overflows an int
            esc("[2;5r") + esc("[4;1H") + esc("[9L"),   // more lines than the region has
            esc("[1;20H") + "x" + esc("[5X"),    // erase starting past the edge
            esc("8"),                            // restore with nothing saved
            esc("]") + "\\",                   // a terminator with nothing before it
            esc("P") + "\\",
            esc("Y") + "\u0001\u0001",         // a VT52 address above the screen
            esc("[3g") + "\t\t\t\t",
        };
        boolean survived = true;
        for (int i = 0; i < onceFatal.length; i++) {
            Headless t = new Headless(20, 5);
            try {
                t.putString(onceFatal[i] + "ok");
            } catch (RuntimeException e) {
                System.out.println("        sequence " + i + " threw " + e);
                survived = false;
            }
        }
        checkTrue("the sequences that used to throw no longer do", survived);

        // Random input, weighted towards what starts and continues an escape
        // sequence. Seeded, so a failure here is the same failure every run.
        String alphabet = esc("") + esc("") + "[[[;;;0123456789?=>!#()*+$'\"hlmHJKABCDGLMPSTXZ@"
            + "abcdefgnpqrstuxy\r\n\t\u0008\u0007\u000e\u000f\u009b\u0090\u009c\u009d"
            + "\u0084\u0085\u0088\u008d\u008e\u008fş─ ]\\^_";
        java.util.Random random = new java.util.Random(20261114L);
        String firstFailure = null;
        for (int round = 0; round < 20000 && firstFailure == null; round++) {
            int columns = 1 + random.nextInt(80);
            int rows = 1 + random.nextInt(30);
            Headless t = new Headless(columns, rows);
            t.setScrollbackBufferSize(40);
            StringBuffer input = new StringBuffer();
            int length = 1 + random.nextInt(60);
            for (int i = 0; i < length; i++) {
                if (random.nextInt(12) == 0) {
                    input.append(random.nextInt(100000));
                } else {
                    input.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
            }
            try {
                t.putString(input.toString());
                if (random.nextInt(4) == 0) {
                    columns = 1 + random.nextInt(80);
                    rows = 1 + random.nextInt(30);
                    t.setScreenSize(columns, rows, true);
                    t.putString(input.toString());
                }
                if (t.ROW < 0 || t.ROW >= rows || t.COLUMN < 0 || t.COLUMN > columns
                        || t.screenBase < 0 || t.screenBase + rows > t.terminalData.length) {
                    firstFailure = "round " + round + " left the cursor at " + t.ROW + ","
                        + t.COLUMN + " on " + columns + "x" + rows;
                }
            } catch (RuntimeException e) {
                firstFailure = "round " + round + " threw " + e;
            }
        }
        if (firstFailure != null) {
            System.out.println("        " + firstFailure);
        }
        checkTrue("twenty thousand random sequences throw nothing and leave the cursor on the screen",
            firstFailure == null);
    }

    private static String repeat(String s, int times) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
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
     * The character-to-cell mapping, which is what was wrong.
     *
     * The arithmetic this replaced assumed a contiguous Latin-1 layout, so it
     * could not distinguish a character it had a glyph for from one it did not:
     * Turkish letters above U+00FF resolved to some empty cell and drew
     * nothing, with no way to tell that from a space.
     */
    private static void mapsCharactersToGlyphs() {
        checkTrue("space is the first cell", BitmapFont.indexOf(' ') == 0);
        checkTrue("ASCII is contiguous from there",
            BitmapFont.indexOf('A') == 'A' - ' ' && BitmapFont.indexOf('~') == '~' - ' ');

        // The letters that were missing. Each must now have a cell, and each
        // must have its own.
        char[] turkish = { 'ç', 'Ç', 'ö', 'Ö', 'ü', 'Ü', 'ğ', 'Ğ', 'ı', 'İ', 'ş', 'Ş' };
        boolean allMapped = true;
        for (int i = 0; i < turkish.length; i++) {
            if (BitmapFont.indexOf(turkish[i]) < 0) {
                allMapped = false;
            }
            for (int j = i + 1; j < turkish.length; j++) {
                if (BitmapFont.indexOf(turkish[i]) == BitmapFont.indexOf(turkish[j])) {
                    allMapped = false;
                }
            }
        }
        checkTrue("every Turkish letter has a cell of its own", allMapped);

        // Box drawing, which is most of what a terminal UI puts on screen.
        checkTrue("box drawing is mapped",
            BitmapFont.indexOf('─') >= 0 && BitmapFont.indexOf('│') >= 0
                && BitmapFont.indexOf('┌') >= 0 && BitmapFont.indexOf('┼') >= 0);
        checkTrue("block elements are mapped", BitmapFont.indexOf('█') >= 0);

        // Control codes and anything outside the ranges must be reported as
        // absent rather than resolved to a cell that happens to be in bounds.
        checkTrue("control codes have no cell",
            BitmapFont.indexOf((char) 7) < 0 && BitmapFont.indexOf((char) 27) < 0);
        checkTrue("C1 controls have no cell", BitmapFont.indexOf((char) 0x85) < 0);
        checkTrue("a character outside the ranges has no cell",
            BitmapFont.indexOf('\u4e00') < 0 && BitmapFont.indexOf('\u0400') < 0);

        // Every mapped character has to land inside the atlas the layout claims.
        boolean inBounds = true;
        for (int c = 0; c < 0x3000; c++) {
            int index = BitmapFont.indexOf((char) c);
            if (index >= BitmapFont.layoutSize()) {
                inBounds = false;
            }
        }
        checkTrue("no character maps past the end of the layout", inBounds);
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

        // Past its capacity the buffer drops the oldest line for each new one.
        // The moment it first filled used to lose a line from the middle
        // instead, and leave the last row of the array unused from then on.
        Headless full = new Headless(20, 5);
        full.setScrollbackBufferSize(10);
        for (int i = 0; i < 40; i++) {
            full.putString("L" + i + "\r\n");
        }
        boolean contiguous = full.screenBase == 10 && full.terminalData.length == 15;
        for (int line = 0; line + 1 < full.terminalData.length && contiguous; line++) {
            // Fourteen lines of text and the empty one the cursor is on.
            String expected = "L" + (26 + line);
            StringBuffer sb = new StringBuffer();
            for (int c = 0; c < expected.length(); c++) {
                sb.append((char) full.terminalData[line][c]);
            }
            contiguous = expected.equals(sb.toString());
        }
        checkTrue("a full buffer keeps the newest lines, in order, with none missing",
            contiguous);
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
