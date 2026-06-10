"""Generate PNG copies of the app icon for use as favicon / PWA manifest icons.

The design code is duplicated from make_ico.py rather than imported, because
that module executes top-level write code at import time.
"""
from pathlib import Path
from PIL import Image, ImageDraw

DEST_DIR = Path(__file__).parent / "local"
SIZES = [192, 256]


def draw_icon(size: int) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    NAVY        = (11,  25,  41,  255)
    CYAN        = (0,  212, 228, 255)
    CYAN_FILL   = (0,  212, 228,  50)
    CYAN_BASE   = (0,  212, 228,  90)
    CYAN_BORDER = (0,  212, 228,  55)

    radius = max(2, s // 7)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=NAVY)
    bw = max(1, s // 64)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius,
                        outline=CYAN_BORDER, width=bw)

    PAD = s * 0.16
    X0, X1 = 4.0, 28.0
    Y0, Y1 = 7.0, 28.0

    def to_px(xr, yr):
        x = PAD + (xr - X0) / (X1 - X0) * (s - 2 * PAD)
        y = PAD + (yr - Y0) / (Y1 - Y0) * (s - 2 * PAD)
        return (x, y)

    z  = [to_px(4, 26), to_px(12, 8), to_px(20, 22), to_px(28, 12)]
    bl = [to_px(4, 26), to_px(28, 26)]
    lw = max(2, round(s / 24))

    baseline_y = bl[0][1]
    for i in range(len(z) - 1):
        x0, y0 = z[i]
        x1, y1 = z[i + 1]
        d.polygon([(x0, y0), (x1, y1), (x1, baseline_y), (x0, baseline_y)],
                  fill=CYAN_FILL)

    d.line(bl, fill=CYAN_BASE, width=max(1, round(lw * 0.55)))
    d.line(z, fill=CYAN, width=lw)

    dr = max(1, round(s / 30))
    px, py = z[1]
    d.ellipse([px - dr, py - dr, px + dr, py + dr], fill=CYAN)

    return img.convert("RGBA")


for sz in SIZES:
    img = draw_icon(sz)
    out = DEST_DIR / f"pan_copilot_{sz}.png"
    img.save(out, "PNG", optimize=True)
    print(f"wrote {out} ({out.stat().st_size:,} bytes)")
