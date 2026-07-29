package berryssh.device;

import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;

/**
 * The palette and the furniture the drawn screens share.
 *
 * MIDP's own Form and List are drawn by the device, which means a white 2003
 * feature-phone menu in front of a terminal that looks nothing like it. A
 * Canvas gives every pixel, which is how the terminal is already drawn.
 *
 * Text is left to MIDP's Font rather than the terminal's bitmap atlas. The
 * atlas is monospace at eight pixels wide, which is right for a terminal grid
 * and wrong for a label; the system font is proportional and is rendered by
 * the device at whatever quality it manages natively.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class Chrome {

    public static final int BACKGROUND = 0x0d0d10;
    public static final int BAR = 0x1b1b22;
    public static final int ROW = 0x16161c;
    public static final int SELECTED = 0x1f4d7a;
    public static final int ACCENT = 0x4a90d9;
    public static final int TEXT = 0xe8e8ea;
    public static final int MUTED = 0x8a8a92;
    public static final int RULE = 0x2a2a33;

    public static final int PADDING = 6;

    private Chrome() {
    }

    public static Font title() {
        return Font.getFont(Font.FACE_PROPORTIONAL, Font.STYLE_BOLD, Font.SIZE_SMALL);
    }

    public static Font label() {
        return Font.getFont(Font.FACE_PROPORTIONAL, Font.STYLE_BOLD, Font.SIZE_SMALL);
    }

    public static Font detail() {
        return Font.getFont(Font.FACE_PROPORTIONAL, Font.STYLE_PLAIN, Font.SIZE_SMALL);
    }

    /** Height of a two-line row: a name and what it reaches. */
    public static int rowHeight() {
        return label().getHeight() + detail().getHeight() + PADDING;
    }

    public static int barHeight() {
        return title().getHeight() + PADDING * 2;
    }

    /** Draws the top bar and returns the y the content starts at. */
    public static int drawTitleBar(Graphics g, int width, String text) {
        int height = barHeight();
        g.setColor(BAR);
        g.fillRect(0, 0, width, height);
        g.setColor(ACCENT);
        g.fillRect(0, height - 2, width, 2);
        g.setColor(TEXT);
        g.setFont(title());
        g.drawString(text, PADDING, PADDING, Graphics.TOP | Graphics.LEFT);
        return height;
    }

    /** Draws the hint line at the foot and returns the y it starts at. */
    public static int drawFooter(Graphics g, int width, int height, String hint) {
        Font font = detail();
        int top = height - font.getHeight() - PADDING;
        g.setColor(BAR);
        g.fillRect(0, top, width, height - top);
        g.setColor(RULE);
        g.drawLine(0, top, width, top);
        g.setColor(MUTED);
        g.setFont(font);
        g.drawString(hint, PADDING, top + PADDING / 2, Graphics.TOP | Graphics.LEFT);
        return top;
    }

    /**
     * Draws one row.
     *
     * The detail line is clipped rather than wrapped: a hostname long enough to
     * wrap would push every row below it out of place, and a list whose rows
     * move as the contents change is harder to use than one that truncates.
     */
    public static void drawRow(Graphics g, int width, int y, String name, String detail,
                               boolean selected) {
        int height = rowHeight();
        g.setColor(selected ? SELECTED : ROW);
        g.fillRect(0, y, width, height - 1);
        if (selected) {
            g.setColor(ACCENT);
            g.fillRect(0, y, 3, height - 1);
        }

        g.setColor(TEXT);
        g.setFont(label());
        g.drawString(clip(name, label(), width - PADDING * 2),
            PADDING + 4, y + PADDING / 2, Graphics.TOP | Graphics.LEFT);

        if (detail != null && detail.length() > 0) {
            g.setColor(selected ? TEXT : MUTED);
            g.setFont(detail());
            g.drawString(clip(detail, detail(), width - PADDING * 2),
                PADDING + 4, y + PADDING / 2 + label().getHeight(),
                Graphics.TOP | Graphics.LEFT);
        }
    }

    /** Trims a string to fit, with an ellipsis, measuring as it goes. */
    public static String clip(String text, Font font, int width) {
        if (font.stringWidth(text) <= width) {
            return text;
        }
        for (int i = text.length() - 1; i > 0; i--) {
            String candidate = text.substring(0, i) + "...";
            if (font.stringWidth(candidate) <= width) {
                return candidate;
            }
        }
        return "";
    }
}
