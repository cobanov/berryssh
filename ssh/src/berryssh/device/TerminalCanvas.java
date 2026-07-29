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

    public TerminalCanvas(BitmapFont font) {
        this.font = font;
        setFullScreenMode(true);
    }

    public void attach(VT320 terminal, Keyboard keyboard) {
        this.terminal = terminal;
        this.keyboard = keyboard;
        repaint();
    }

    /** How many columns of this font fit the canvas. */
    public int columns() {
        return font.columnsIn(getWidth());
    }

    /** Rows, less one kept for the status line. */
    public int rows() {
        return font.rowsIn(getHeight()) - 1;
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
            for (int row = 0; row < rows; row++) {
                for (int column = 0; column < columns; column++) {
                    char c = terminal.getChar(column, row);
                    if (c > 32) {
                        font.drawChar(g, c, column * font.cellWidth(), row * font.cellHeight());
                    }
                }
            }
        }

        // The status line carries the one piece of state the terminal itself
        // cannot show: whether the sticky Ctrl is armed. Without it, an armed
        // Ctrl is invisible until it swallows the next keystroke.
        String line = status;
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
        if (keyboard == null) {
            return;
        }
        int action = 0;
        try {
            action = getGameAction(keyCode);
        } catch (IllegalArgumentException e) {
            // MIDP allows this for a code it does not recognise, and a QWERTY
            // handset produces plenty it does not. The key is still a key.
            action = 0;
        }
        keyboard.keyPressed(keyCode, action);
        repaint();
    }
}
