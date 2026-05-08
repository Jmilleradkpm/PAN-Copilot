# Generate pan_copilot.ico and write it to the PAN Copilot_APP repo.
import struct, math, os

try:
    from PIL import Image, ImageDraw
    USE_PILLOW = True
except ImportError:
    USE_PILLOW = False

DEST = r"C:\Users\jmill\Downloads\PAN Copilot_APP\local\pan_copilot.ico"

def draw_icon_pillow(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size
    bg = (11, 25, 41, 255)
    cy = (0, 212, 228, 255)
    pad = max(1, s // 16)
    cx_, cy_ = s / 2, s / 2
    r = s / 2 - pad
    hex_pts = [(cx_ + r * math.cos(math.radians(a - 30)),
                cy_ + r * math.sin(math.radians(a - 30))) for a in range(0, 360, 60)]
    d.polygon(hex_pts, fill=bg)
    bw = max(1, s // 24)
    d.polygon(hex_pts, outline=(0, 212, 228, 255), width=bw)
    inner = r * 0.65
    left  = cx_ - inner
    right = cx_ + inner
    base  = cy_ + inner * 0.45
    pts_x = [left, left+inner*0.3, left+inner*0.6, cx_, cx_+inner*0.4, right]
    pts_y = [base, base-inner*0.25, base-inner*0.55, base-inner*0.80, base-inner*0.45, base]
    chart_pts = list(zip(pts_x, pts_y)) + [(right, base), (left, base)]
    d.polygon(chart_pts, fill=(0, 212, 228, 180))
    lw = max(1, s // 32)
    d.line(list(zip(pts_x, pts_y)), fill=cy, width=lw)
    pk_x, pk_y = cx_, cy_ - inner * 0.80
    dr = max(1, s // 18)
    d.ellipse([pk_x-dr, pk_y-dr, pk_x+dr, pk_y+dr], fill=cy)
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
