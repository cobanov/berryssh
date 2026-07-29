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

    /** Everything below the space is a control code and is not in the atlas. */
    private static final int FIRST_PRINTABLE = 33;

    /** 127..159 are C1 controls, also absent. */
    private static final int C1_START = 127;
    private static final int C1_END = 159;

    /** A soft hyphen, absent for the same reason. */
    private static final int SOFT_HYPHEN = 173;

    private final int cellWidth;
    private final int cellHeight;
    private final int imageWidth;
    private final int columns;

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

        cachedFor = new long[columns * (atlas.getHeight() / cellHeight) + 1];
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
     * Draws one character. Anything with no glyph in the atlas draws nothing,
     * which is what a terminal should do with a control code.
     */
    public void drawChar(Graphics g, char c, int x, int y) {
        int index = glyphIndex(c);
        if (index < 0) {
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
     * Maps a character to its cell, or -1 if the atlas has no glyph for it.
     *
     * The atlas omits the control ranges rather than leaving them blank, so
     * every character above a gap sits earlier in the grid than its code would
     * suggest and the gaps have to be subtracted in order.
     */
    private int glyphIndex(char c) {
        if (c < FIRST_PRINTABLE || (c >= C1_START && c <= C1_END) || c == SOFT_HYPHEN) {
            return -1;
        }
        int index = c - FIRST_PRINTABLE;
        if (c > C1_END) {
            index -= (C1_END - C1_START + 1);
        }
        if (c > SOFT_HYPHEN) {
            index -= 1;
        }
        if (index >= cachedFor.length) {
            return -1;
        }
        return index;
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
