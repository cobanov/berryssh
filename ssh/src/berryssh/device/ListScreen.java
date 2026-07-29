package berryssh.device;

import javax.microedition.lcdui.Canvas;
import javax.microedition.lcdui.Graphics;

/**
 * A drawn list of rows.
 *
 * Used for the connection list and for the editor's fields, because they are
 * the same shape: a title, rows of a name over a detail, one of them selected,
 * and a hint at the foot.
 *
 * Every command the owner adds stays in the menu. The drawing here cannot be
 * verified without the hardware, and a screen that draws wrongly must still be
 * one the user can act on and leave — which is the trap full-screen mode set
 * earlier, when the menu vanished along with the way out.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class ListScreen extends Canvas {

    /** What the owner does when a row is chosen. */
    public interface Listener {
        void selected(int index);
    }

    private final String title;
    private final Listener listener;

    private String[] names = new String[0];
    private String[] details = new String[0];
    private String hint = "";
    private int selected;
    private int scroll;

    public ListScreen(String title, Listener listener) {
        this.title = title;
        this.listener = listener;
        setFullScreenMode(false);
    }

    public void setRows(String[] names, String[] details) {
        this.names = names;
        this.details = details;
        if (selected >= names.length) {
            selected = names.length == 0 ? 0 : names.length - 1;
        }
        repaint();
    }

    public void setHint(String hint) {
        this.hint = hint == null ? "" : hint;
        repaint();
    }

    public int selectedIndex() {
        return selected;
    }

    public void select(int index) {
        if (index >= 0 && index < names.length) {
            selected = index;
            repaint();
        }
    }

    protected void paint(Graphics g) {
        int width = getWidth();
        int height = getHeight();

        g.setColor(Chrome.BACKGROUND);
        g.fillRect(0, 0, width, height);

        int top = Chrome.drawTitleBar(g, width, title);
        int bottom = hint.length() > 0
            ? Chrome.drawFooter(g, width, height, hint)
            : height;

        int rowHeight = Chrome.rowHeight();
        int visible = (bottom - top) / rowHeight;
        if (visible < 1) {
            visible = 1;
        }
        // Keep the selection on screen without moving the list more than it
        // has to: a list that recentres on every keypress is disorienting.
        if (selected < scroll) {
            scroll = selected;
        }
        if (selected >= scroll + visible) {
            scroll = selected - visible + 1;
        }
        if (scroll > names.length - visible) {
            scroll = names.length - visible;
        }
        if (scroll < 0) {
            scroll = 0;
        }

        g.setClip(0, top, width, bottom - top);
        for (int i = 0; i < visible && scroll + i < names.length; i++) {
            int index = scroll + i;
            Chrome.drawRow(g, width, top + i * rowHeight,
                names[index],
                index < details.length ? details[index] : null,
                index == selected);
        }
        g.setClip(0, 0, width, height);

        // Say there is more, rather than letting the list end at the edge with
        // no sign that it did not.
        if (scroll + visible < names.length) {
            g.setColor(Chrome.ACCENT);
            g.fillTriangle(width - 12, bottom - 10, width - 4, bottom - 10, width - 8, bottom - 4);
        }
        if (scroll > 0) {
            g.setColor(Chrome.ACCENT);
            g.fillTriangle(width - 12, top + 10, width - 4, top + 10, width - 8, top + 4);
        }
    }

    protected void keyPressed(int keyCode) {
        move(keyCode);
    }

    protected void keyRepeated(int keyCode) {
        move(keyCode);
    }

    private void move(int keyCode) {
        int action = 0;
        try {
            action = getGameAction(keyCode);
        } catch (IllegalArgumentException e) {
            action = 0;
        }

        if (action == Canvas.UP) {
            select(selected - 1);
            return;
        }
        if (action == Canvas.DOWN) {
            select(selected + 1);
            return;
        }
        if (action == Canvas.FIRE || keyCode == 10 || keyCode == 13) {
            if (selected >= 0 && selected < names.length) {
                listener.selected(selected);
            }
        }
    }
}
