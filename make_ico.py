# Generate pan_copilot.ico and write it to the PAN Copilot_APP repo.
import struct, os

try:
    from PIL import Image, ImageDraw
    USE_PILLOW = True
except ImportError:
    USE_PILLOW = False

DEST = r"C:\Users\jmill\Downloads\PAN Copilot_APP\local\pan_copilot.ico"

def draw_icon_pillow(size):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    NAVY        = (11,  25,  41,  255)   # #0B1929
    CYAN        = (0,  212, 228, 255)    # #00D4E4
    CYAN_FILL   = (0,  212, 228,  50)    # area under zigzag
    CYAN_BASE   = (0,  212, 228,  90)    # baseline stroke
    CYAN_BORDER = (0,  212, 228,  55)    # rounded-square border

    # Background: rounded square
    radius = max(2, s // 7)
    try:
        d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=NAVY)
    except AttributeError:
        d.rectangle([0, 0, s - 1, s - 1], fill=NAVY)

    # Subtle cyan border
    if s >= 32:
        bw = max(1, s // 64)
        try:
            d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius,
                                 outline=CYAN_BORDER, width=bw)
        except (AttributeError, TypeError):
            pass

    # ── ADK Cyber zigzag ──────────────────────────────────────────
    # Source: site SVG 32×32 viewbox
    #   Zigzag:  M4 26  L12 8  L20 22  L28 12
    #   Baseline: M4 26  L28 26  (opacity .5)
    # Map x∈[4,28] and y∈[7,28] to the icon canvas with 16% padding.
    # y_src starts at 7 (just above the highest point at 8) so the peak
    # sits comfortably inside the top padding band.
    PAD   = s * 0.16
    X0, X1 = 4.0, 28.0
    Y0, Y1 = 7.0, 28.0

    def to_px(xr, yr):
        x = PAD + (xr - X0) / (X1 - X0) * (s - 2 * PAD)
        y = PAD + (yr - Y0) / (Y1 - Y0) * (s - 2 * PAD)
        return (x, y)

    z  = [to_px(4, 26), to_px(12, 8), to_px(20, 22), to_px(28, 12)]
    bl = [to_px(4, 26), to_px(28, 26)]

    lw = max(2, round(s / 24))

    # Filled area under zigzag — drawn as per-segment trapezoids to avoid
    # PIL's even-odd rule creating holes in the concave polygon
    baseline_y = bl[0][1]
    for i in range(len(z) - 1):
        x0, y0 = z[i]
        x1, y1 = z[i + 1]
        d.polygon([(x0, y0), (x1, y1), (x1, baseline_y), (x0, baseline_y)],
                  fill=CYAN_FILL)

    # Baseline
    d.line(bl, fill=CYAN_BASE, width=max(1, round(lw * 0.55)))

    # Zigzag line
    d.line(z, fill=CYAN, width=lw)

    # Peak dot (highest point = z[1]) for sizes where it reads well
    if s >= 32:
        dr = max(1, round(s / 30))
        px, py = z[1]
        d.ellipse([px - dr, py - dr, px + dr, py + dr], fill=CYAN)

    return img.convert("RGBA")


def draw_icon_stdlib(size):
    """Pure stdlib fallback — simple colored square."""
    # Create RGBA pixels manually: navy bg with a cyan square in center
    pixels = []
    s = size
    for y in range(s):
        row = []
        for x in range(s):
            cx_ = s / 2
            cy_ = s / 2
            # Simple: dark background with cyan center square
            margin = s // 4
            if margin <= x < s - margin and margin <= y < s - margin:
                row.append((0, 212, 228, 255))   # cyan
            else:
                row.append((11, 25, 41, 255))    # navy
        pixels.append(row)
    return pixels  # list of rows of (r,g,b,a) tuples


def rgba_to_bmp_dib_pillow(img):
    w, h = img.size
    hdr = struct.pack('<IiiHHIIiiII', 40, w, -(h*2), 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = bytearray()
    for y in range(h):
        for x in range(w):
            r, g, b, a = img.getpixel((x, y))
            pixels += bytes([b, g, r, a])
    row_bytes = ((w + 31) // 32) * 4
    and_mask = bytes(row_bytes * h)
    return hdr + bytes(pixels) + and_mask


def rgba_to_bmp_dib_stdlib(pixel_rows, size):
    w = h = size
    hdr = struct.pack('<IiiHHIIiiII', 40, w, -(h*2), 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = bytearray()
    for row in pixel_rows:
        for (r, g, b, a) in row:
            pixels += bytes([b, g, r, a])
    row_bytes = ((w + 31) // 32) * 4
    and_mask = bytes(row_bytes * h)
    return hdr + bytes(pixels) + and_mask


def build_ico(sizes):
    dibs = {}
    for sz in sizes:
        if USE_PILLOW:
            img = draw_icon_pillow(sz)
            dibs[sz] = rgba_to_bmp_dib_pillow(img)
        else:
            px = draw_icon_stdlib(sz)
            dibs[sz] = rgba_to_bmp_dib_stdlib(px, sz)

    count = len(sizes)
    data_offset = 6 + count * 16
    entries, blobs = [], []
    for sz in sizes:
        dib = dibs[sz]
        w = sz if sz < 256 else 0
        h = sz if sz < 256 else 0
        entries.append(struct.pack('<BBBBHHII', w, h, 0, 0, 1, 32, len(dib), data_offset))
        blobs.append(dib)
        data_offset += len(dib)

    return struct.pack('<HHH', 0, 1, count) + b''.join(entries) + b''.join(blobs)


sizes = [16, 24, 32, 48, 64, 128, 256]
ico = build_ico(sizes)
with open(DEST, 'wb') as f:
    f.write(ico)
print(f"{'Pillow' if USE_PILLOW else 'stdlib'} mode")
print(f"Written {len(ico):,} bytes -> {DEST}")
