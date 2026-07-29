package berryssh.terminal;

import java.io.IOException;
import java.io.InputStream;

import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.Image;

/**
 * A terminal font drawn from a bitmap atlas.
 *
 * MIDP cannot supply a usable terminal font. Measured on the Bold 9790, the
 * smallest monospace cell it offers is 22x27 pixels, which gives a 21x13
 * terminal on a 480x360 screen — and MIDP exposes exactly three font sizes, so
 * there is no way to ask for smaller. An 8x14 cell from an atlas gives 60x25.
 *
 * The approach and the atlases come from BBSSH, whose renderer derives from
 * Roar Lauritzsen's LCDFont. Its code could not be reused: it is written
 * against net.rim.device.api, which is the one thing this project cannot touch.
 * The layout is the borrowed part.
 *
 * Glyphs are laid out row-major, cell index counting from the first printable
 * character, with the ranges MIDP would never draw omitted from the atlas
 * entirely — so the index is not the character code and the gaps have to be
 * subtracted.
 *
 * Written for -source 1.3: no generics, no enhanced for, no StringBuilder.
 */
public final class BitmapFont {

    /**
     * What the atlas contains, as inclusive ranges in cell order.
     *
     * This has to stay identical to the table in tools/MakeAtlas.java, which
     * lays the atlas out from it. A character's cell is its position in this
     * sequence, so inserting a range in the middle renumbers everything after
     * it and both sides must move together.
     *
     * An explicit table rather than arithmetic, because the arithmetic that
     * came before assumed a contiguous Latin-1 layout and therefore could not
     * tell a character it had no glyph for from one it did. Turkish letters
     * above U+00FF mapped to whatever cell the sum landed on, which was empty,
     * so they drew nothing and nothing said why.
     */
    private static final int[] RANGES = {
        0x0020, 0x007E,   // ASCII printable
        0x00A0, 0x00FF,   // Latin-1 supplement: covers c-cedilla, o and u umlaut
        0x011E, 0x011F,   // G-breve
        0x0130, 0x0131,   // dotted and dotless I
        0x015E, 0x015F,   // S-cedilla
        0x2500, 0x257F,   // box drawing, which is most of what a terminal UI draws
        0x2580, 0x259F    // block elements
    };

    private final int cellWidth;
    private final int cellHeight;
    private final int imageWidth;
    private final int columns;

    /** How many cells the atlas actually holds glyphs for. */
    private final int glyphs;

    /**
     * The atlas as it was drawn: white on black, with the red, green and blue
     * channels carrying separate coverage for the three subpixels of an LCD
     * stripe rather than one grey level.
     */
    private final int[] monochrome;

    /** The same glyphs recoloured for the current foreground and background. */
    private final int[] coloured;

    /** Which colour pair each glyph in {@link #coloured} was last drawn for. */
    private final long[] cachedFor;

    private int[] current;
    private long currentColours = -1;
    private int foreground = 0xffffff;
    private int fgRed, fgGreen, fgBlue, bgRed, bgGreen, bgBlue;

    private BitmapFont(Image atlas, int cellWidth, int cellHeight) {
        this.cellWidth = cellWidth;
        this.cellHeight = cellHeight;
        this.imageWidth = atlas.getWidth();
        this.columns = imageWidth / cellWidth;

        int pixels = imageWidth * atlas.getHeight();
        monochrome = new int[pixels];
        coloured = new int[pixels];
        atlas.getRGB(monochrome, 0, imageWidth, 0, 0, imageWidth, atlas.getHeight());

        int cells = columns * (atlas.getHeight() / cellHeight);
        int described = 0;
        for (int i = 0; i < RANGES.length; i += 2) {
            described += RANGES[i + 1] - RANGES[i] + 1;
        }
        // The table describes the atlas; if the file is smaller than the table
        // says, trusting the table would read past the end of the image.
        this.glyphs = described < cells ? described : cells;

        cachedFor = new long[this.glyphs + 1];
        for (int i = 0; i < cachedFor.length; i++) {
            cachedFor[i] = -1;
        }
        current = monochrome;
    }

    /**
     * Loads an atlas from the jar.
     *
     * @param resource  a path such as "/fonts/BVSM8x14.png"
     * @param cellWidth  the glyph cell width the atlas was drawn at
     * @param cellHeight the glyph cell height
     */
    public static BitmapFont load(String resource, int cellWidth, int cellHeight)
            throws IOException {
        InputStream in = BitmapFont.class.getResourceAsStream(resource);
        if (in == null) {
            throw new IOException("no font atlas at " + resource);
        }
        try {
            return new BitmapFont(Image.createImage(in), cellWidth, cellHeight);
        } finally {
            in.close();
        }
    }

    public int cellWidth() {
        return cellWidth;
    }

    public int cellHeight() {
        return cellHeight;
    }

    /** How many columns and rows of this font fit a canvas. */
    public int columnsIn(int pixels) {
        return pixels / cellWidth;
    }

    public int rowsIn(int pixels) {
        return pixels / cellHeight;
    }

    /**
     * Selects the colours subsequent characters are drawn in.
     *
     * White on black is the atlas as drawn, so it costs nothing; everything
     * else is recoloured per glyph on first use and cached until the colours
     * change again. A terminal spends most of its time in one or two colour
     * pairs, which is what makes that cache worth having.
     */
    public void setColours(int foreground, int background) {
        // Kept whatever branch is taken: the missing-glyph box is drawn with
        // the graphics context's own colour, and the fast path below returns
        // before the components are unpacked.
        this.foreground = foreground;
        if (foreground == 0xffffff && background == 0x000000) {
            current = monochrome;
            return;
        }
        current = coloured;

        long pair = ((long) foreground << 32) | (background & 0xffffffffL);
        if (pair == currentColours) {
            return;
        }
        currentColours = pair;
        fgRed = (foreground >> 16) & 0xff;
        fgGreen = (foreground >> 8) & 0xff;
        fgBlue = foreground & 0xff;
        bgRed = (background >> 16) & 0xff;
        bgGreen = (background >> 8) & 0xff;
        bgBlue = background & 0xff;

        // Everything cached was for the previous pair.
        for (int i = 0; i < cachedFor.length; i++) {
            cachedFor[i] = -1;
        }
    }

    /**
     * Draws one character.
     *
     * A character the atlas has no glyph for gets a hollow box rather than
     * nothing. A hole in a line of text is indistinguishable from a space,
     * which is exactly how the missing Turkish letters went unnoticed until a
     * terminal UI made the gaps obvious.
     */
    public void drawChar(Graphics g, char c, int x, int y) {
        int index = glyphIndex(c);
        if (index < 0) {
            drawMissing(g, x, y);
            return;
        }
        int offset = (index / columns) * cellHeight * imageWidth
                   + (index % columns) * cellWidth;

        if (current == coloured && cachedFor[index] != currentColours) {
            recolour(offset);
            cachedFor[index] = currentColours;
        }
        g.drawRGB(current, offset, imageWidth, x, y, cellWidth, cellHeight, false);
    }

    /** Fills one cell with the background colour, for a blank or a cleared line. */
    public void fillCell(Graphics g, int x, int y, int background) {
        g.setColor(background);
        g.fillRect(x, y, cellWidth, cellHeight);
    }

    /**
     * The cell a character occupies in the layout, or -1 if it has none.
     *
     * Static and free of the loaded atlas so the mapping can be checked on the
     * host, where an Image cannot be constructed. The instance method below
     * adds the only thing that needs the atlas: whether that cell exists in the
     * file that was actually loaded.
     */
    public static int indexOf(char c) {
        int at = 0;
        for (int i = 0; i < RANGES.length; i += 2) {
            if (c >= RANGES[i] && c <= RANGES[i + 1]) {
                return at + (c - RANGES[i]);
            }
            at += RANGES[i + 1] - RANGES[i] + 1;
        }
        return -1;
    }

    /** How many cells the layout describes, whatever the atlas holds. */
    public static int layoutSize() {
        int total = 0;
        for (int i = 0; i < RANGES.length; i += 2) {
            total += RANGES[i + 1] - RANGES[i] + 1;
        }
        return total;
    }

    private int glyphIndex(char c) {
        int index = indexOf(c);
        return (index >= 0 && index < glyphs) ? index : -1;
    }

    /**
     * A hollow box, for a character with no glyph.
     *
     * Drawn rather than looked up, so it exists whatever the atlas contains —
     * including when the atlas is the thing that is wrong.
     */
    private void drawMissing(Graphics g, int x, int y) {
        g.setColor(foreground);
        g.drawRect(x + 1, y + 2, cellWidth - 3, cellHeight - 5);
    }

    /**
     * Blends one glyph between the current colours.
     *
     * The blend is per channel rather than per pixel because the atlas is
     * subpixel antialiased: red, green and blue hold the coverage of three
     * separate subpixels, so averaging them into one grey level would throw
     * away the horizontal resolution that makes an 8-pixel-wide glyph legible.
     */
    private void recolour(int offset) {
        for (int row = 0; row < cellHeight; row++) {
            int at = offset + row * imageWidth;
            for (int column = 0; column < cellWidth; column++) {
                int pixel = monochrome[at + column];
                int r = (pixel >> 16) & 0xff;
                int g = (pixel >> 8) & 0xff;
                int b = pixel & 0xff;

                if (r == 0 && g == 0 && b == 0) {
                    r = bgRed;
                    g = bgGreen;
                    b = bgBlue;
                } else {
                    r = blend(fgRed, bgRed, r);
                    g = blend(fgGreen, bgGreen, g);
                    b = blend(fgBlue, bgBlue, b);
                }
                coloured[at + column] = 0xff000000 | (r << 16) | (g << 8) | b;
            }
        }
    }

    private static int blend(int foreground, int background, int coverage) {
        if (coverage == 255) {
            return foreground;
        }
        return (foreground * coverage + background * (255 - coverage)) / 255;
    }
}
