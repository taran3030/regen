"""Builds Regen's logo files: an r and a block cursor that types out "regen." and backspaces.

    python3 assets/logo/build.py           # write every file
    python3 assets/logo/build.py --check   # exit 1 if a committed file differs from what this makes

The letters are drawn, not set in a font (concept 1, round two, in the Figma file "Regen brand"). One grid:
x-height 224, vertical stem 56, horizontal bar 48, the g's descender to 296, 28 between letters. The r and n
share a 45-degree notch where the arm leaves the stem. The cursor is the only colored part.

Files:
    logo-mark(-light).svg       r and the cursor
    logo-full(-light).svg       regen. and the cursor
    logo-wordmark(-light).svg   regen. on its own
    logo-white.svg, logo-black.svg   regen. and the cursor in one color
    logo-icon.svg, favicon.svg  the mark on a midnight tile
    logo-animated(-light).svg   the typing loop, self-contained, for the README
    typing.svg, typing.css      the same logo with classes, and the styles that animate it, for web pages
"""
import pathlib
import sys

OUT = pathlib.Path(__file__).parent

DARK = {"ink": "#E8F6FA", "cursor": "#3BD5E6"}  # frost and scan cyan, on midnight
LIGHT = {"ink": "#06111C", "cursor": "#0A8FA3"}  # cyan is too faint on white, so a deeper one
MIDNIGHT = "#06111C"

# ---------------------------------------------------------------- the letters

# Each glyph: advance, outer outline, holes. y grows down; the baseline is y = 224.
GLYPHS = {
    "r": (152, [(0, 0), (56, 0), (56, 20), (76, 0), (152, 0), (152, 60), (96, 60), (56, 100), (56, 224), (0, 224)], []),
    "e": (224, [(0, 0), (224, 0), (224, 144), (56, 144), (56, 176), (224, 176), (224, 224), (0, 224)],
          [[(56, 48), (168, 48), (168, 96), (56, 96)]]),
    "g": (224, [(0, 0), (224, 0), (224, 296), (0, 296), (0, 248), (168, 248), (168, 176), (0, 176)],
          [[(56, 48), (168, 48), (168, 128), (56, 128)]]),
    "n": (224, [(0, 0), (56, 0), (56, 20), (76, 0), (224, 0), (224, 224), (168, 224), (168, 60), (96, 60),
                (56, 100), (56, 224), (0, 224)], []),
    ".": (56, [(0, 168), (56, 168), (56, 224), (0, 224)], []),
}
NAME = "regen."
GAP = 28
CURSOR_W, CURSOR_H = 72, 224
DESCENDER = 296


def layout(text):
    """Where each letter starts, and where the cursor sits after them."""
    x, placed = 0, []
    for ch in text:
        placed.append((ch, x))
        x += GLYPHS[ch][0] + GAP
    return placed, x


FULL_CURSOR_X = layout(NAME)[1]          # 1272
FULL_W = FULL_CURSOR_X + CURSOR_W        # 1344
WORDMARK_W = FULL_CURSOR_X - GAP         # 1244
MARK_W = layout("r")[1] + CURSOR_W       # 252


def outline(points, dx):
    """A closed outline as compact path data, shifted right by dx."""
    (x0, y0), *rest = points
    d, px, py = [f"M{x0 + dx} {y0}"], x0, y0
    for x, y in rest:
        if y == py:
            d.append(f"H{x + dx}")
        elif x == px:
            d.append(f"V{y}")
        else:
            d.append(f"L{x + dx} {y}")
        px, py = x, y
    return "".join(d) + "Z"


def glyph_path(ch, dx):
    _, outer, holes = GLYPHS[ch]
    return "".join(outline(p, dx) for p in [outer, *holes])


def letters(text, ink, classed=False):
    out = []
    for i, (ch, x) in enumerate(layout(text)[0]):
        cls = f' class="rg__{"r" if i == 0 else f"k{i}"}"' if classed else ""
        out.append(f'<path{cls} fill="{ink}" fill-rule="evenodd" d="{glyph_path(ch, x)}"/>')
    return out


def cursor(x, colour, classed=False):
    cls = ' class="rg__cursor"' if classed else ""
    return f'<rect{cls} x="{x}" y="0" width="{CURSOR_W}" height="{CURSOR_H}" fill="{colour}"/>'


def svg(view_w, view_h, body, label="Regen", extra=""):
    inner = "\n".join(f"  {line}" for line in body)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {view_w} {view_h}" '
            f'role="img" aria-label="{label}"{extra}>\n{inner}\n</svg>\n')


def tile(scale, radius):
    """The mark centered on a 512 midnight tile."""
    w, h = MARK_W * scale, CURSOR_H * scale
    tx, ty = (512 - w) / 2, (512 - h) / 2
    g = letters("r", DARK["ink"]) + [cursor(layout("r")[1], DARK["cursor"])]
    body = [f'<rect width="512" height="512" rx="{radius}" fill="{MIDNIGHT}"/>',
            f'<g transform="translate({tx:g} {ty:g}) scale({scale:g})">', *[f"  {x}" for x in g], "</g>"]
    return svg(512, 512, body)


# ---------------------------------------------------------------- the animation

BLINK = 530  # ms, the usual terminal blink
TYPED = [("re", 150), ("reg", 115), ("rege", 170), ("regen", 135), ("regen.", 240)]  # uneven, like a person

# (text on screen, cursor showing, ms). The cursor stays solid while keys are pressed.
LOOP = (
    [("r", True, BLINK), ("r", False, BLINK), ("r", True, BLINK), ("r", False, BLINK), ("r", True, 260)]
    + [(t, True, ms) for t, ms in TYPED]
    + [("regen.", False, BLINK), ("regen.", True, BLINK), ("regen.", False, BLINK), ("regen.", True, BLINK),
       ("regen.", False, BLINK), ("regen.", True, 300)]
    + [("regen", True, 75), ("rege", True, 75), ("reg", True, 75), ("re", True, 75)]  # backspace, like a held key
)
# Played once: two blinks, the typing, three blinks, then it rests on the name with a steady cursor.
ONCE = (
    LOOP[:5] + [(t, True, ms) for t, ms in TYPED]
    + [("regen.", False, BLINK), ("regen.", True, BLINK), ("regen.", False, BLINK), ("regen.", True, BLINK),
       ("regen.", False, BLINK), ("regen.", True, 0)]
)


def cursor_shift(text):
    """How far left of its finished position the cursor sits after this text."""
    return layout(text)[1] - FULL_CURSOR_X


def keyframes(name, states, value):
    total = sum(ms for _, _, ms in states)
    frames, t = [], 0
    for text, on, ms in states:
        v = value(text, on)
        if not frames or frames[-1][1] != v:
            frames.append((t, v))
        t += ms
    if frames[-1][0] != total:
        frames.append((total, value(*states[-1][:2])))

    def pct(ms):
        return f"{100 * ms / total:.3f}".rstrip("0").rstrip(".") + "%"

    rows = "\n".join(f"  {pct(ms)} {{ {v} }}" for ms, v in frames)
    return f"@keyframes {name} {{\n{rows}\n}}"


def animation_css(mode, states, selector, timing):
    """Keyframes and rules for one mode: 'loop' or 'once'."""
    secs = f"{sum(ms for _, _, ms in states) / 1000:g}s"
    blocks, rules = [], []
    for i in range(1, len(NAME)):
        blocks.append(keyframes(f"rg-{mode}-k{i}", states, lambda text, on, i=i: f"opacity: {1 if len(text) > i else 0};"))
        rules.append(f"{selector} .rg__k{i} {{ animation: rg-{mode}-k{i} {secs} step-end {timing}; }}")
    blocks.append(keyframes(f"rg-{mode}-cursor", states,
                            lambda text, on: f"opacity: {1 if on else 0}; transform: translateX({cursor_shift(text)}px);"))
    rules.append(f"{selector} .rg__cursor {{ animation: rg-{mode}-cursor {secs} step-end {timing}; }}")
    return rules, blocks


def reduced_motion(selector):
    # !important so it also beats .rg-armed, which hides the letters while the logo waits to play.
    parts = ", ".join(f"{selector} .rg__k{i}" for i in range(1, len(NAME))) + f", {selector} .rg__cursor"
    return ("@media (prefers-reduced-motion: reduce) {\n"
            f"  {parts} {{ animation: none !important; opacity: 1 !important; transform: none !important; }}\n}}")


def typing_css():
    loop_rules, loop_frames = animation_css("loop", LOOP, ".rg--loop", "infinite")
    once_rules, once_frames = animation_css("once", ONCE, ".rg--once.is-playing", "forwards")
    waiting = ".rg-armed .rg--once:not(.is-playing)"
    armed = [f"{waiting} .rg__k{i} {{ opacity: 0; }}" for i in range(1, len(NAME))]
    armed.append(f"{waiting} .rg__cursor {{ transform: translateX({cursor_shift('r')}px); }}")
    return "\n".join([
        "/* Regen's cursor logo. Generated by assets/logo/build.py in github.com/taran3030/regen; edit it there. */",
        "/* Without these classes, or with reduced motion, the logo is the finished regen. and a still cursor. */",
        "/* .rg--loop types and backspaces forever. .rg--once waits as r while an ancestor has .rg-armed, then */",
        "/* plays once when the logo gets .is-playing, and rests on regen. Put .rg-armed on <html> from a script */",
        "/* in <head>, so the page never draws the finished logo before it plays. */",
        "",
        *loop_rules, "", *armed, *once_rules, "", *loop_frames, "", *once_frames, "", reduced_motion(".rg"), "",
    ])


def animated_svg(colours):
    rules, frames = animation_css("loop", LOOP, ".rg--loop", "infinite")
    style = "\n".join(["<style>", *rules, *frames, reduced_motion(".rg"), "</style>"])
    body = [*style.split("\n"), *letters(NAME, colours["ink"], classed=True),
            cursor(FULL_CURSOR_X, colours["cursor"], classed=True)]
    return svg(FULL_W, DESCENDER, body, extra=' class="rg rg--loop"')


# ---------------------------------------------------------------- the files


def files():
    full = lambda c: letters(NAME, c["ink"]) + [cursor(FULL_CURSOR_X, c["cursor"])]
    mono = lambda colour: full({"ink": colour, "cursor": colour})
    mark = lambda c: letters("r", c["ink"]) + [cursor(layout("r")[1], c["cursor"])]
    return {
        "logo-mark.svg": svg(MARK_W, CURSOR_H, mark(DARK)),
        "logo-mark-light.svg": svg(MARK_W, CURSOR_H, mark(LIGHT)),
        "logo-full.svg": svg(FULL_W, DESCENDER, full(DARK)),
        "logo-full-light.svg": svg(FULL_W, DESCENDER, full(LIGHT)),
        "logo-wordmark.svg": svg(WORDMARK_W, DESCENDER, letters(NAME, DARK["ink"])),
        "logo-wordmark-light.svg": svg(WORDMARK_W, DESCENDER, letters(NAME, LIGHT["ink"])),
        "logo-white.svg": svg(FULL_W, DESCENDER, mono("#FFFFFF")),
        "logo-black.svg": svg(FULL_W, DESCENDER, mono("#000000")),
        "logo-icon.svg": tile(1.2, 112),
        "favicon.svg": tile(1.45, 96),
        "logo-animated.svg": animated_svg(DARK),
        "logo-animated-light.svg": animated_svg(LIGHT),
        "typing.svg": svg(FULL_W, DESCENDER, letters(NAME, DARK["ink"], classed=True)
                          + [cursor(FULL_CURSOR_X, DARK["cursor"], classed=True)], extra=' class="rg"'),
        "typing.css": typing_css(),
    }


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for name, text in files().items():
        path = OUT / name
        if check:
            current = path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else None
            if current != text:
                stale.append(name)
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
    if check:
        if stale:
            print("Out of date (run python3 assets/logo/build.py): " + ", ".join(stale))
            return 1
        print("Logo files match build.py.")
        return 0
    print(f"Wrote {len(files())} files to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
