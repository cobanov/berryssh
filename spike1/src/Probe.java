import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.midlet.MIDlet;

/**
 * Spike 1: prove the build -> package -> OTA -> run pipeline on a real device,
 * and bring back the measurements the terminal UI will need.
 *
 * Deliberately plain MIDP 2.0 / CLDC 1.1 with no RIM APIs, so the suite needs
 * no BlackBerry code signature. Written for -source 1.3: no generics, no
 * StringBuilder, no enhanced for.
 */
public class Probe extends MIDlet implements CommandListener {

    private final Command exitCommand = new Command("Exit", Command.EXIT, 1);
    private final Command modeCommand = new Command("Keys / Report", Command.SCREEN, 1);
    private final Command pageCommand = new Command("Next page", Command.SCREEN, 2);
    private final Command clearCommand = new Command("Clear keys", Command.SCREEN, 3);
    private ProbeCanvas canvas;

    protected void startApp() {
        Display display = Display.getDisplay(this);
        if (canvas == null) {
            canvas = new ProbeCanvas(display);
            canvas.addCommand(modeCommand);
            canvas.addCommand(pageCommand);
            canvas.addCommand(clearCommand);
            canvas.addCommand(exitCommand);
            canvas.setCommandListener(this);
        }
        display.setCurrent(canvas);
    }

    protected void pauseApp() {
    }

    protected void destroyApp(boolean unconditional) {
    }

    public void commandAction(Command c, Displayable d) {
        if (c == exitCommand) {
            destroyApp(true);
            notifyDestroyed();
        } else if (c == modeCommand) {
            canvas.toggleMode();
        } else if (c == pageCommand) {
            canvas.nextPage();
        } else if (c == clearCommand) {
            canvas.clearKeys();
        }
    }
}

class ProbeCanvas extends Canvas {

    /** A terminal needs a monospaced font; measure the one we would actually use. */
    private final Font mono = Font.getFont(Font.FACE_MONOSPACE, Font.STYLE_PLAIN, Font.SIZE_SMALL);

    /** Colour capability lives on Display, not Canvas. */
    private final Display display;

    /* The keyboard survey.
     *
     * A terminal needs Ctrl, Esc, Tab and arrows, and this keyboard has none of
     * them as such — so every physical key has to be identified before any of it
     * can be mapped. The probe used to show only the code of the last key
     * pressed, which meant reading a number off the screen and writing it down
     * forty times without losing your place. That is why the mapping never got
     * done.
     *
     * Now every key pressed is kept, with the name and game action the platform
     * gives for it, so the survey is one pass over the keyboard and then a few
     * photographs.
     *
     * Paging is on the soft menu rather than on a key, because on this screen
     * every key press is data. A key that moved the page would be a key that
     * could not be surveyed.
     */
    private static final int MAX_KEYS = 128;
    private final int[] keyCodes = new int[MAX_KEYS];
    private final String[] keyNames = new String[MAX_KEYS];
    private final int[] keyActions = new int[MAX_KEYS];
    private int keyCount = 0;

    private boolean keyMode = false;
    private int page = 0;

    ProbeCanvas(Display display) {
        this.display = display;
    }

    void toggleMode() {
        keyMode = !keyMode;
        page = 0;
        repaint();
    }

    void nextPage() {
        page++;
        repaint();
    }

    void clearKeys() {
        keyCount = 0;
        page = 0;
        repaint();
    }

    public void paint(Graphics g) {
        int w = getWidth();
        int h = getHeight();

        g.setColor(0x000000);
        g.fillRect(0, 0, w, h);
        g.setFont(mono);

        if (keyMode) {
            paintKeys(g, w, h);
        } else {
            paintReport(g, w, h);
        }
    }

    private void paintReport(Graphics g, int w, int h) {
        int lineHeight = mono.getHeight();
        // Cell width from a wide-ish glyph; monospace should make this uniform.
        int cellWidth = mono.charWidth('W');
        int cols = cellWidth > 0 ? w / cellWidth : 0;
        int rows = lineHeight > 0 ? h / lineHeight : 0;

        String[] lines = new String[] {
            "SPIKE 1 OK",
            "canvas   " + w + "x" + h,
            "cell     " + cellWidth + "x" + lineHeight,
            "terminal " + cols + "x" + rows,
            "platform " + prop("microedition.platform"),
            "encoding " + prop("microedition.encoding"),
            "locale   " + prop("microedition.locale"),
            "colors   " + display.numColors() + (display.isColor() ? " color" : " mono"),
            "pointer  " + hasPointerEvents(),
            "repeat   " + hasRepeatEvents(),
            "keys     " + keyCount + " seen - menu > Keys",
            "mem      " + (Runtime.getRuntime().freeMemory() / 1024) + "k free / "
                        + (Runtime.getRuntime().totalMemory() / 1024) + "k total",
        };

        g.setColor(0x33FF33);
        int y = 0;
        for (int i = 0; i < lines.length; i++) {
            if (y + lineHeight > h) {
                break;
            }
            g.drawString(lines[i], 0, y, Graphics.TOP | Graphics.LEFT);
            y += lineHeight;
        }

        // A one-cell reference box: confirms drawing coordinates land where we expect.
        g.setColor(0xFF3333);
        g.drawRect(w - cellWidth - 1, h - lineHeight - 1, cellWidth, lineHeight);
    }

    private void paintKeys(Graphics g, int w, int h) {
        int lineHeight = mono.getHeight();
        int perPage = (h / lineHeight) - 2;
        int pages;
        int start;
        int y = 0;
        int i;

        if (perPage < 1) {
            perPage = 1;
        }
        pages = (keyCount + perPage - 1) / perPage;
        if (pages < 1) {
            pages = 1;
        }
        if (page >= pages) {
            page = 0;              /* wraps, so one command is enough to cycle */
        }
        start = page * perPage;

        g.setColor(0xFFFF33);
        g.drawString("KEYS  " + keyCount + " seen  page " + (page + 1) + "/" + pages,
                     0, y, Graphics.TOP | Graphics.LEFT);
        y += lineHeight;

        if (keyCount == 0) {
            g.setColor(0x999999);
            g.drawString("press every key once", 0, y, Graphics.TOP | Graphics.LEFT);
            y += lineHeight;
            g.drawString("then Alt and Shift layers", 0, y, Graphics.TOP | Graphics.LEFT);
            return;
        }

        g.setColor(0x33FF33);
        for (i = start; i < keyCount && i < start + perPage; i++) {
            String line = pad(String.valueOf(keyCodes[i]), 6)
                        + pad(keyNames[i], 9)
                        + (keyActions[i] != 0 ? "act " + keyActions[i] : "");
            g.drawString(line, 0, y, Graphics.TOP | Graphics.LEFT);
            y += lineHeight;
        }
    }

    /** Left-aligned in a fixed width, so the columns line up in a photograph. */
    private static String pad(String s, int width) {
        String out = s == null ? "?" : s;
        while (out.length() < width) {
            out = out + " ";
        }
        return out;
    }

    /**
     * Key codes differ across BlackBerry models; record what this device
     * actually sends, once per distinct code.
     *
     * getKeyName is what makes the list readable afterwards — it says which
     * physical key produced a code, so the survey does not depend on
     * remembering the order things were pressed in.
     */
    protected void keyPressed(int keyCode) {
        int i;

        for (i = 0; i < keyCount; i++) {
            if (keyCodes[i] == keyCode) {
                repaint();
                return;
            }
        }
        if (keyCount < MAX_KEYS) {
            keyCodes[keyCount] = keyCode;
            String name;
            try {
                name = getKeyName(keyCode);
            } catch (Exception e) {
                /* Undocumented codes are exactly the ones worth surveying, and
                 * some devices throw rather than return anything for them. */
                name = "?";
            }
            keyNames[keyCount] = name;
            try {
                keyActions[keyCount] = getGameAction(keyCode);
            } catch (Exception e) {
                keyActions[keyCount] = 0;
            }
            keyCount++;
        }
        repaint();
    }

    private static String prop(String name) {
        String v = System.getProperty(name);
        return v == null ? "(null)" : v;
    }
}
