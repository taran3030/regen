"""Builds Regen's logo files from one canonical mark and real Gabarito ExtraBold outlines.

    python assets/logo/build.py <gabarito-500-800.woff2>

The mark: six axolotl gills fanning up from one point to make a shield (concept 2 in the Figma file "Regen brand").
"""
import pathlib
import sys

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

OUT = pathlib.Path(__file__).parent

# Palette: Axolotl Labs Night canal (dark) and Leucistic (light).
# "outer" and "inner" are the pink gill pairs, "middle" the cream pair, "dot" the gold heart and period.
DARK = {"ground": "#081A28", "outer": "#F29BB4", "middle": "#F6F1E7", "inner": "#F29BB4", "ink": "#F6F1E7", "dot": "#E9B949"}
LIGHT = {"ground": "#FBEFF1", "outer": "#D45F82", "middle": "#1B1F3B", "inner": "#D45F82", "ink": "#1B1F3B", "dot": "#B07D12"}

# ---------------------------------------------------------------- the mark (512 x 512 design grid, canonical)

# Six gills fanning up from one point, which together make a shield: concept 2 from the Figma file "Regen
# brand", with the outer pair raised so all six tips sit on one arc (the shield's crest), and a larger heart.
OUTER_L = "M111 104C84 104 68 127 73 161C81 301 159 383 248 438C217 354 177 285 153 156C148 125 139 104 111 104Z"
OUTER_R = "M401 104C428 104 444 127 439 161C431 301 353 383 264 438C295 354 335 285 359 156C364 125 373 104 401 104Z"
MIDDLE_L = "M169 88C142 88 124 108 129 140C140 235 185 299 248 357C234 276 220 211 207 130C202 103 189 88 169 88Z"
MIDDLE_R = "M343 88C370 88 388 108 383 140C372 235 327 299 264 357C278 276 292 211 305 130C310 103 323 88 343 88Z"
INNER_L = "M220 92C195 92 183 113 188 141C197 196 219 238 248 274V128C248 106 238 92 220 92Z"
INNER_R = "M292 92C317 92 329 113 324 141C315 196 293 238 264 274V128C264 106 274 92 292 92Z"
HEART = "M256 281L272 305L256 329L240 305Z"
# The mark's box on the grid: x 68 to 444, y 88 to 438. Square it around the center for the 64 x 64 mark.
GRID = (60, 57, 392)  # x, y, size of the square crop


def mark_layers(c, mono=False):
    if not mono:
        return "".join(
            f'<path d="{d}" fill="{c[role]}"/>'
            for d, role in (
                (OUTER_L, "outer"), (OUTER_R, "outer"), (MIDDLE_L, "middle"), (MIDDLE_R, "middle"),
                (INNER_L, "inner"), (INNER_R, "inner"), (HEART, "dot"),
            )
        )
    # One color: the gills overlap, so cut a thin gap around the middle pair and around the heart, or the
    # six gills merge into one blob.
    col = c["outer"]
    gap = "".join(f'<path d="{d}" fill="black" stroke="black" stroke-width="16" stroke-linejoin="round"/>' for d in (MIDDLE_L, MIDDLE_R))
    heart_gap = f'<path d="{HEART}" fill="black" stroke="black" stroke-width="16" stroke-linejoin="round"/>'
    return (
        f'<mask id="regen-gap" maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512"><rect width="512" height="512" fill="white"/>{gap}{heart_gap}</mask>'
        f'<g mask="url(#regen-gap)">' + "".join(f'<path d="{d}" fill="{col}"/>' for d in (OUTER_L, OUTER_R, INNER_L, INNER_R)) + "</g>"
        + "".join(f'<path d="{d}" fill="{col}"/>' for d in (MIDDLE_L, MIDDLE_R, HEART))
    )


def mark_group(c, size, x=0, y=0, mono=False):
    """The mark scaled to a size x size square at (x, y)."""
    gx, gy, gs = GRID
    s = size / gs
    return f'<g transform="translate({x:g} {y:g}) scale({s:.5f}) translate({-gx} {-gy})">{mark_layers(c, mono)}</g>'


# ---------------------------------------------------------------- the wordmark, from real outlines


def wordmark_paths(font_path):
    """'Regen' as one outlined path in font units (y up) plus the period's bounds, at weight 800."""
    font = TTFont(font_path)
    if "fvar" in font:
        font = instantiateVariableFont(font, {"wght": 800})
    cmap = font.getBestCmap()
    gs = font.getGlyphSet()
    hmtx = font["hmtx"]
    # Gabarito's kerning lives in GPOS; at display size the default spacing tightened a touch reads best.
    track = -12
    x = 0
    pen = SVGPathPen(gs)
    for ch in "Regen":
        name = cmap[ord(ch)]
        gs[name].draw(TransformPen(pen, (1, 0, 0, 1, x, 0)))
        x += hmtx[name][0] + track
    word = pen.getCommands()
    # The period as its own path, so it can be gold.
    dot_pen = SVGPathPen(gs)
    name = cmap[ord(".")]
    gs[name].draw(TransformPen(dot_pen, (1, 0, 0, 1, x - 34, 0)))
    width = x - 34 + hmtx[name][0]
    upm = font["head"].unitsPerEm
    cap = font["OS/2"].sCapHeight or int(upm * 0.7)
    return word, dot_pen.getCommands(), width, cap


def svg(view_w, view_h, body, label="Regen"):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {view_w:g} {view_h:g}" role="img" aria-label="{label}">{body}</svg>\n'


def main(font_path):
    word, dot, wwidth, cap = wordmark_paths(font_path)

    def wordmark_group(c, height, x0, baseline):
        s = height / cap
        return (
            f'<g transform="translate({x0:g} {baseline:g}) scale({s:.5f} {-s:.5f})">'
            f'<path d="{word}" fill="{c["ink"]}"/><path d="{dot}" fill="{c["dot"]}"/></g>'
        ), wwidth * s

    files = {}
    # logo-mark: the canonical 64 x 64 mark, dark colorway on transparent.
    files["logo-mark.svg"] = svg(64, 64, mark_group(DARK, 64))
    files["logo-mark-light.svg"] = svg(64, 64, mark_group(LIGHT, 64))
    # logo-full: mark + wordmark, 320 x 72.
    for name, c in (("logo-full.svg", DARK), ("logo-full-light.svg", LIGHT)):
        g, _ = wordmark_group(c, 34, 80, 53)
        files[name] = svg(320, 72, mark_group(c, 64, 4, 4) + g)
    # logo-wordmark: text only, 180 x 40.
    for name, c in (("logo-wordmark.svg", DARK), ("logo-wordmark-light.svg", LIGHT)):
        g, w = wordmark_group(c, 26, 4, 33)
        files[name] = svg(max(180, w + 8), 40, g)
    # logo-icon: 512 x 512 app icon on the Night canal ground.
    files["logo-icon.svg"] = svg(512, 512, f'<rect width="512" height="512" rx="112" fill="{DARK["ground"]}"/>' + mark_group(DARK, 340, 86, 86))
    # favicon: 16 x 16 on the ground. Six gills still read at this size; the heart is dropped.
    fav_layers = "".join(f'<path d="{d}" fill="{DARK[r]}"/>' for d, r in ((OUTER_L, "outer"), (OUTER_R, "outer"), (MIDDLE_L, "middle"), (MIDDLE_R, "middle"), (INNER_L, "inner"), (INNER_R, "inner")))
    gx, gy, gs = GRID
    files["favicon.svg"] = svg(16, 16, f'<rect width="16" height="16" rx="3.5" fill="{DARK["ground"]}"/><g transform="translate(1 1) scale({14 / gs:.5f}) translate({-gx} {-gy})">{fav_layers}</g>')
    # Monochrome: same geometry, one color.
    for name, col in (("logo-white.svg", "#FFFFFF"), ("logo-black.svg", "#000000")):
        mono = {k: col for k in DARK}
        g, _ = wordmark_group(mono, 34, 80, 53)
        files[name] = svg(320, 72, mark_group(mono, 64, 4, 4, mono=True) + g)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(files)} files; wordmark {wwidth} units wide, cap height {cap}")


if __name__ == "__main__":
    main(sys.argv[1])
