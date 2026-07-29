#!/usr/bin/env bash
# Regenerate the terminal font atlases.
#
# The atlas that shipped first came from BBSSH and covered Latin-1 and nothing
# else, so Turkish ğ ı ş İ and the whole box-drawing range had no glyph. These
# are generated instead, from a typeface whose licence permits it.
#
# DejaVu Sans Mono is the continuation of the Bitstream Vera Sans Mono family
# the original atlas came from, so the result looks like what it replaces. The
# monospace fonts already on a Mac — Menlo, Monaco, Courier New, Andale Mono —
# all cover what is needed and none may be used: baking their glyphs into a GPL
# project would redistribute a derivative of a proprietary typeface, which is
# exactly what this project left behind with BBSSH's Courier New atlases.
#
#   tools/make_atlas.sh
set -euo pipefail

cd "$(dirname "$0")/.."

FONT_VERSION=2.37
FONT_DIR=lib/fonts
FONT="$FONT_DIR/DejaVuSansMono.ttf"

if [ ! -f "$FONT" ]; then
    echo "==> fetching DejaVu Sans Mono $FONT_VERSION"
    mkdir -p "$FONT_DIR"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL -o "$tmp/dejavu.zip" \
        "https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_${FONT_VERSION//./_}/dejavu-fonts-ttf-$FONT_VERSION.zip"
    unzip -q -j "$tmp/dejavu.zip" "*/ttf/DejaVuSansMono.ttf" -d "$FONT_DIR"
    unzip -q -j "$tmp/dejavu.zip" "*/LICENSE" -d "$FONT_DIR" 2>/dev/null || true
fi

echo "==> generating atlases"
for spec in "8 14 mono8x14.png" "6 11 mono6x11.png" "6 9 mono6x9.png"; do
    set -- $spec
    java tools/MakeAtlas.java "$FONT" "$1" "$2" "ssh/res/fonts/$3"
done

echo "done"
