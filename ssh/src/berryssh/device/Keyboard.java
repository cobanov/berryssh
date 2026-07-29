package berryssh.device;

import javax.microedition.lcdui.Canvas;

import berryssh.terminal.VT320;

/**
 * Turns MIDP key events into terminal input.
 *
 * A terminal needs keys a handset does not have. The BlackBerry QWERTY covers
 * the letters and, through Alt, the symbols printed on the keycaps — but there
 * is no Ctrl, no Esc, and no function row, and those are not optional for
 * anything you would actually want a terminal for.
 *
 * Ctrl is therefore sticky rather than held: press the Ctrl command, then the
 * letter. Holding two keys is awkward on a thumb keyboard and impossible to
 * detect portably, since MIDP reports key presses and not modifier state.
 *
 * <b>What is assumed rather than measured.</b> MIDP guarantees the game actions
 * and the numeric keypad codes, and those are what the arrows and the trackpad
 * come through as. It says nothing about what a BlackBerry sends for its own
 * Escape, Menu, Symbol and Alt keys, and this is written against the plain MIDP
 * values without those having been read off the hardware. The probe in spike1
 * reports the code of the last key pressed and is the way to settle them; until
 * it has been run, the constants below marked as unverified are the plausible
 * values and not the known ones.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Keyboard {

    private static final int ASCII_BACKSPACE = 8;
    private static final int ASCII_TAB = 9;
    private static final int ASCII_LINE_FEED = 10;
    private static final int ASCII_CARRIAGE_RETURN = 13;
    private static final int ASCII_ESCAPE = 27;
    private static final int ASCII_DELETE = 127;

    /**
     * Unverified: the code a BlackBerry sends for its Escape key. On the
     * devices this targets it is generally the same negative code used for
     * "back", but that has not been read off the hardware here.
     */
    private static final int BLACKBERRY_ESCAPE = -8;

    private final VT320 terminal;

    private boolean controlPending;

    public Keyboard(VT320 terminal) {
        this.terminal = terminal;
    }

    /** True while the next key will be sent as a control character. */
    public boolean controlPending() {
        return controlPending;
    }

    /** Arms or disarms the sticky Ctrl. */
    public void toggleControl() {
        controlPending = !controlPending;
    }

    /** Sends Escape on its own, for the key the keyboard does not have. */
    public void sendEscape() {
        terminal.keyTyped(VT320.VK_ESCAPE, (char) ASCII_ESCAPE, 0);
    }

    /**
     * Handles a key.
     *
     * @param keyCode    the MIDP key code
     * @param gameAction the canvas's game action for it, or 0
     */
    public void keyPressed(int keyCode, int gameAction) {
        // A character is a character, whatever else the device calls it.
        //
        // This ordering is the whole point. MIDP lets a device map keys to game
        // actions, and BlackBerry maps the letters — 'w' is UP, 'a' is LEFT,
        // 's' is DOWN, 'd' is RIGHT — so that games written for a numeric
        // keypad work on a QWERTY. Asking for the game action first therefore
        // turns typing into cursor movement on exactly those letters, and
        // leaves the rest working, which is what makes it look like a font or
        // an encoding problem rather than a dispatch one.
        //
        // The trackpad and any dedicated cursor keys report no character, so
        // they still reach the game actions below.
        if (keyCode > 0 && isPrintable((char) keyCode)) {
            type((char) keyCode);
            return;
        }

        if (keyCode == BLACKBERRY_ESCAPE) {
            sendEscape();
            return;
        }

        switch (keyCode) {
            case ASCII_CARRIAGE_RETURN:
            case ASCII_LINE_FEED:
                terminal.keyTyped(VT320.VK_ENTER, (char) 0, 0);
                return;
            case ASCII_BACKSPACE:
                // Through keyPressed, not keyTyped. VT320 splits its input that
                // way — its own dispatchKey routes backspace to keyPressed —
                // and keyTyped drops it silently, so this sent nothing at all
                // and there was no way to correct a typo.
                terminal.keyPressed(VT320.VK_BACK_SPACE, 0);
                return;
            case ASCII_DELETE:
                // Also backspace. VT320 has no keyPressed handling for DEL, and
                // this handset has one deletion key rather than two — sending
                // nothing because the codes differ in ASCII would be pedantry
                // at the cost of the key working.
                terminal.keyPressed(VT320.VK_BACK_SPACE, 0);
                return;
            case ASCII_TAB:
                terminal.keyTyped(VT320.VK_TAB, (char) ASCII_TAB, 0);
                return;
            case ASCII_ESCAPE:
                sendEscape();
                return;
            default:
                break;
        }

        // Only now the game actions, which on this hardware means the trackpad
        // and anything else with no character of its own.
        switch (gameAction) {
            case Canvas.UP:
                terminal.keyPressed(VT320.VK_UP, 0);
                return;
            case Canvas.DOWN:
                terminal.keyPressed(VT320.VK_DOWN, 0);
                return;
            case Canvas.LEFT:
                terminal.keyPressed(VT320.VK_LEFT, 0);
                return;
            case Canvas.RIGHT:
                terminal.keyPressed(VT320.VK_RIGHT, 0);
                return;
            default:
                break;
        }

        // A key we have no mapping for. Dropping it is right: inventing a
        // character would put rubbish into the session, and the Keys readout is
        // there to find out what it was.
    }

    private void type(char c) {
        if (controlPending) {
            controlPending = false;
            int control = controlOf(c);
            if (control >= 0) {
                terminal.keyTyped(0, (char) control, 0);
            }
            return;
        }
        terminal.keyTyped(0, c, 0);
    }

    /**
     * Whether this character is one a terminal should send as itself.
     *
     * The C1 range is excluded along with the C0 controls: those arrive as
     * named keys handled above, and passing one through as a character would
     * send a byte the far end reads as the start of an escape sequence.
     */
    public static boolean isPrintable(char c) {
        return (c >= 32 && c < 127) || c > 159;
    }

    /**
     * The control character for a key, or -1 if there is none.
     *
     * Done by arithmetic on the ASCII ranges rather than by case folding. The
     * device's locale is Turkish, where upper-casing 'i' gives a dotted capital
     * that is not 'I', so Ctrl-I would stop being Tab — silently, and only on
     * that one letter.
     */
    public static int controlOf(char c) {
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 1;
        }
        if (c >= 'A' && c <= 'Z') {
            return c - 'A' + 1;
        }
        switch (c) {
            case ' ':  return 0;    // Ctrl-Space, the NUL a few programs want
            case '[':  return 27;   // Ctrl-[ is Escape
            case '\\': return 28;
            case ']':  return 29;
            case '^':  return 30;
            case '_':  return 31;
            case '?':  return 127;  // Ctrl-? is Delete
            default:   return -1;
        }
    }
}
