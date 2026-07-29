import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;

import javax.imageio.ImageIO;

/**
 * Generates a terminal font atlas.
 *
 * The atlas that shipped first came from BBSSH and covered U+0020 to U+00FF and
 * nothing else — which left the four Turkish letters from Latin Extended-A and
 * the whole box-drawing range with no glyph. Generating it means the coverage
 * is a decision rather than an inheritance.
 *
 * The character set is defined by {@link #RANGES} and must stay identical to
 * the table in berryssh.terminal.BitmapFont. Cells are laid out row-major in
 * the order the ranges appear, and the index of a character is its position in
 * that sequence — so adding a range in the middle renumbers everything after
 * it, and both sides have to move together.
 *
 * Rendered with LCD subpixel antialiasing, because that is what the renderer
 * expects: it blends the red, green and blue channels separately, treating each
 * as coverage for one subpixel. A greyscale atlas still works — the three
 * channels simply carry the same value — but it throws away the horizontal
 * resolution that makes an eight-pixel glyph legible.
 *
 * Host-only build tool. Not part of the MIDlet.
 *
 *   java tools/MakeAtlas.java <font.ttf> <cellWidth> <cellHeight> <out.png>
 */
public final class MakeAtlas {

    /**
     * Start and end of each range, inclusive. Kept deliberately small: every
     * cell costs atlas space, and the atlas is loaded whole into memory on a
     * device where that used to matter.
     */
    static final int[] RANGES = {
        0x0020, 0x007E,   // ASCII printable
        0x00A0, 0x00FF,   // Latin-1 supplement: covers ç Ç ö Ö ü Ü
        0x011E, 0x011F,   // Ğ ğ
        0x0130, 0x0131,   // İ ı
        0x015E, 0x015F,   // Ş ş
        0x2500, 0x257F,   // box drawing
        0x2580, 0x259F    // block elements
    };

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: MakeAtlas <font.ttf> <cellWidth> <cellHeight> <out.png>");
            System.exit(2);
        }
        File source = new File(args[0]);
        int cellWidth = Integer.parseInt(args[1]);
        int cellHeight = Integer.parseInt(args[2]);
        File out = new File(args[3]);

        int count = 0;
        for (int i = 0; i < RANGES.length; i += 2) {
            count += RANGES[i + 1] - RANGES[i] + 1;
        }

        // 256 wide keeps the atlas the size the renderer already handles; the
        // height grows to whatever the character set needs.
        int columns = 256 / cellWidth;
        int rows = (count + columns - 1) / columns;
        int width = 256;
        int height = rows * cellHeight;

        Font base = Font.createFont(Font.TRUETYPE_FONT, source);
        Font font = fit(base, cellWidth, cellHeight);

        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.BLACK);
        g.fillRect(0, 0, width, height);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
            RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS,
            RenderingHints.VALUE_FRACTIONALMETRICS_OFF);
        g.setFont(font);
        g.setColor(Color.WHITE);

        FontMetrics metrics = g.getFontMetrics();
        int baseline = (cellHeight - metrics.getHeight()) / 2 + metrics.getAscent();
        if (baseline < metrics.getAscent()) {
            baseline = metrics.getAscent();
        }
        if (baseline > cellHeight) {
            baseline = cellHeight;
        }

        int index = 0;
        int missing = 0;
        for (int r = 0; r < RANGES.length; r += 2) {
            for (int c = RANGES[r]; c <= RANGES[r + 1]; c++) {
                int x = (index % columns) * cellWidth;
                int y = (index / columns) * cellHeight;
                if (!font.canDisplay((char) c)) {
                    missing++;
                } else {
                    String s = String.valueOf((char) c);
                    // Centred on the cell rather than left-aligned: the box
                    // drawing characters have to meet across a cell boundary,
                    // and a half-pixel offset is a visible break in a table.
                    int advance = metrics.charWidth((char) c);
                    // Clipped to the cell. Without it a tall glyph's
                    // antialiasing spills into the neighbour above or below,
                    // and since the atlas is read a cell at a time that spill
                    // appears as a smudge attached to an unrelated character.
                    g.setClip(x, y, cellWidth, cellHeight);
                    g.drawString(s, x + (cellWidth - advance) / 2, y + baseline);
                    g.setClip(null);
                }
                index++;
            }
        }
        g.dispose();

        ImageIO.write(image, "png", out);
        System.out.println(out.getName() + ": " + width + "x" + height
            + ", " + columns + "x" + rows + " cells, "
            + index + " characters at " + font.getSize() + "pt"
            + (missing > 0 ? ", " + missing + " the font cannot draw" : ""));
    }

    /**
     * The largest size whose widest glyph still fits the cell.
     *
     * Measured rather than calculated from the em size: a monospace font's
     * advance is not its ink extent, and a glyph one pixel too wide bleeds into
     * the next cell, which in a terminal means every column after it looks
     * wrong.
     */
    private static Font fit(Font base, int cellWidth, int cellHeight) {
        BufferedImage probe = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = probe.createGraphics();
        Font best = base.deriveFont(6f);
        for (float size = 6f; size <= 40f; size += 0.5f) {
            Font candidate = base.deriveFont(size);
            FontMetrics m = g.getFontMetrics(candidate);
            if (m.charWidth('M') <= cellWidth && m.getHeight() <= cellHeight) {
                best = candidate;
            }
        }
        g.dispose();
        return best;
    }
}
