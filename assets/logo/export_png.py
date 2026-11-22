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
        pg.set_content(f'<html><body style="margin:0;background:transparent"><img src="{(D / src).as_uri()}" style="width:{w}px;height:{h}px;object-fit:contain;display:block"></body></html>')
        pg.wait_for_timeout(150)
        pg.screenshot(path=str(PNG / out), omit_background=True)
        pg.close()
    b.close()
print(f"wrote {len(SIZES)} PNGs")
