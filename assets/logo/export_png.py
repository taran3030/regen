"""Renders PNGs of Regen's logo SVGs with headless Chromium (Playwright), at the sizes upload targets need.

    python assets/logo/export_png.py
"""
import pathlib
from playwright.sync_api import sync_playwright

D = pathlib.Path(__file__).parent
PNG = D / "png"
SIZES = [
    ("logo-icon.svg", "logo-icon-512.png", 512, 512),
    ("logo-icon.svg", "logo-icon-1024.png", 1024, 1024),
    ("logo-mark.svg", "logo-mark-512.png", 512, 512),
    ("logo-mark-light.svg", "logo-mark-light-512.png", 512, 512),
    ("logo-full.svg", "logo-full.png", 1280, 288),
    ("logo-full-light.svg", "logo-full-light.png", 1280, 288),
    ("logo-white.svg", "logo-white.png", 1280, 288),
    ("logo-black.svg", "logo-black.png", 1280, 288),
    ("logo-wordmark.svg", "logo-wordmark.png", 720, 160),
    ("favicon.svg", "favicon-16.png", 16, 16),
    ("favicon.svg", "favicon-32.png", 32, 32),
    ("favicon.svg", "favicon-48.png", 48, 48),
]

PNG.mkdir(exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch()
    for src, out, w, h in SIZES:
        pg = b.new_page(viewport={"width": w, "height": h})
        # The SVG goes into the page itself: a blank page can't load file:// images, and an <img> that
        # fails draws a broken-image icon that looks like output.
        markup = (D / src).read_text(encoding="utf-8").replace("<svg ", f'<svg width="{w}" height="{h}" ', 1)
        pg.set_content(f'<html><body style="margin:0;background:transparent;line-height:0">{markup}</body></html>')
        pg.wait_for_timeout(150)
        pg.screenshot(path=str(PNG / out), omit_background=True)
        pg.close()
    b.close()


def coverage(path):
    """Share of pixels the logo actually covers. A failed image load leaves a mostly empty frame."""
    from PIL import Image
    alpha = Image.open(path).convert("RGBA").getchannel("A")
    return sum(alpha.histogram()[201:]) / (alpha.width * alpha.height)


# The thinnest real one, the wordmark, covers over 40% of its frame; a broken-image icon, under a fifth.
empty = [out for _, out, _, _ in SIZES if coverage(PNG / out) < 0.2]
if empty:
    raise SystemExit("These came out empty, so the SVG didn't render: " + ", ".join(empty))
print(f"wrote {len(SIZES)} PNGs, and each one shows the logo")
