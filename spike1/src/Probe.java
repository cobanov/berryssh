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
    private ProbeCanvas canvas;

    protected void startApp() {
        Display display = Display.getDisplay(this);
        if (canvas == null) {
            canvas = new ProbeCanvas(display);
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
        }
    }
}

class ProbeCanvas extends Canvas {

    /** A terminal needs a monospaced font; measure the one we would actually use. */
    private final Font mono = Font.getFont(Font.FACE_MONOSPACE, Font.STYLE_PLAIN, Font.SIZE_SMALL);

    /** Colour capability lives on Display, not Canvas. */
    private final Display display;

    ProbeCanvas(Display display) {
        this.display = display;
    }

    public void paint(Graphics g) {
        int w = getWidth();
        int h = getHeight();

        g.setColor(0x000000);
        g.fillRect(0, 0, w, h);
        g.setFont(mono);

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
            "lastkey  " + (lastKey == 0 ? "(press a key)" : String.valueOf(lastKey)),
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

    private int lastKey = 0;

    /** Key codes differ across BlackBerry models; show what this device actually sends. */
    protected void keyPressed(int keyCode) {
        lastKey = keyCode;
        repaint();
    }

    private static String prop(String name) {
        String v = System.getProperty(name);
        return v == null ? "(null)" : v;
    }
}
