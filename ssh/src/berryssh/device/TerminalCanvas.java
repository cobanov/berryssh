package berryssh.device;

import java.io.IOException;

import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Graphics;

import berryssh.terminal.BitmapFont;
import berryssh.terminal.VT320;

/**
 * The terminal on screen.
 *
 * Drawing is per character cell out of the font atlas rather than through
 * MIDP's text API, for the reason in {@link BitmapFont}: the smallest system
 * font this device offers gives a 21x13 terminal, which is not one.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class TerminalCanvas extends Canvas {

    private static final int BACKGROUND = 0x000000;
    private static final int FOREGROUND = 0xffffff;
    private static final int STATUS = 0x808080;

    private final BitmapFont font;
    private VT320 terminal;
    private Keyboard keyboard;
    private String status = "";

    private boolean shown;
    private boolean showKeyCodes;
    private String lastKey = "";

    /**
     * Starts windowed rather than full screen, deliberately.
     *
     * Full screen buys about two more rows and costs the menu: MIDP does not
     * promise that commands stay reachable without one, and on this device they
     * do not. That trade is only ever worth making by choice — a terminal you
     * cannot get out of is worse than a slightly shorter one, and there is no
     * other way off this screen, since every command lives in that menu.
     */
    public TerminalCanvas(BitmapFont font) {
        this.font = font;
        setFullScreenMode(false);
    }

    /** The size changes, so the caller has to tell the session to resize too. */
    public void setFullScreen(boolean on) {
        setFullScreenMode(on);
        repaint();
    }

    public void attach(VT320 terminal, Keyboard keyboard) {
        this.terminal = terminal;
        this.keyboard = keyboard;
        repaint();
    }

    /**
     * Blocks until the canvas is actually on screen.
     *
     * setCurrent is asynchronous and full-screen mode is not applied until the
     * canvas is shown, so getWidth and getHeight are not to be trusted before
     * this returns. Reading them early gave a zero height, hence a negative row
     * count, hence a paint loop that never ran — a blank terminal under a
     * status line that drew perfectly well.
     */
    public synchronized void awaitShown(long milliseconds) {
        long deadline = System.currentTimeMillis() + milliseconds;
        while (!shown) {
            long left = deadline - System.currentTimeMillis();
            if (left <= 0) {
                return;
            }
            try {
                wait(left);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    protected synchronized void showNotify() {
        shown = true;
        notifyAll();
    }

    protected void sizeChanged(int width, int height) {
        synchronized (this) {
            shown = true;
            notifyAll();
        }
        repaint();
    }

    /**
     * How many columns of this font fit the canvas.
     *
     * Never below one. A zero or negative grid is not a smaller terminal, it is
     * a terminal that draws nothing, and it should not be reachable by
     * arithmetic on a size that has not arrived yet.
     */
    public int columns() {
        return atLeastOne(font.columnsIn(getWidth()));
    }

    /** Rows, less one kept for the status line. */
    public int rows() {
        return atLeastOne(font.rowsIn(getHeight()) - 1);
    }

    private static int atLeastOne(int n) {
        return n < 1 ? 1 : n;
    }

    /**
     * Shows the raw code of each key pressed instead of the status message.
     *
     * This is the measurement issue #11 has been waiting for. MIDP guarantees
     * nothing about what a BlackBerry sends for its own Escape, Menu, Symbol
     * and Alt keys, and putting the readout in the app itself means the numbers
     * can be read off the hardware in the place they matter rather than from a
     * separate probe.
     */
    public void toggleKeyCodes() {
        showKeyCodes = !showKeyCodes;
        repaint();
    }

    public void setStatus(String message) {
        status = message == null ? "" : message;
        repaint();
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();

        g.setColor(BACKGROUND);
        g.fillRect(0, 0, width, height);

        if (terminal != null) {
            font.setColours(FOREGROUND, BACKGROUND);
            int columns = columns();
            int rows = rows();
            // Held across the whole screen rather than per character: the
            // session thread must not scroll the buffer out from under a
            // half-drawn frame, which would tear the picture and, during a
            // resize, index past the end of it.
            synchronized (terminal.getTermBufferMutex()) {
                for (int row = 0; row < rows; row++) {
                    for (int column = 0; column < columns; column++) {
                        char c = terminal.getChar(column, row);
                        if (c > 32) {
                            font.drawChar(g, c,
                                column * font.cellWidth(), row * font.cellHeight());
                        }
                    }
                }
            }
        }

        // The status line carries the one piece of state the terminal itself
        // cannot show: whether the sticky Ctrl is armed. Without it, an armed
        // Ctrl is invisible until it swallows the next keystroke.
        String line = showKeyCodes ? lastKey : status;
        if (keyboard != null && keyboard.controlPending()) {
            line = "^ " + line;
        }
        font.setColours(STATUS, BACKGROUND);
        int y = height - font.cellHeight();
        for (int i = 0; i < line.length() && i < columns(); i++) {
            font.drawChar(g, line.charAt(i), i * font.cellWidth(), y);
        }
    }

    protected void keyPressed(int keyCode) {
        deliver(keyCode);
    }

    /**
     * Key repeat is available on this device and is wanted: holding a cursor
     * key should scroll rather than move once.
     */
    protected void keyRepeated(int keyCode) {
        deliver(keyCode);
    }

    private void deliver(int keyCode) {
        int action = 0;
        try {
            action = getGameAction(keyCode);
        } catch (IllegalArgumentException e) {
            // MIDP allows this for a code it does not recognise, and a QWERTY
            // handset produces plenty it does not. The key is still a key.
            action = 0;
        }

        // Recorded before anything can go wrong with it, and whether or not
        // there is a session yet: a key that produces no output is exactly the
        // case this readout exists to explain.
        lastKey = "key " + keyCode + " action " + action
            + " grid " + columns() + "x" + rows();

        if (keyboard != null) {
            keyboard.keyPressed(keyCode, action);
        }
        repaint();
    }
}
