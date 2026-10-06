#!/usr/bin/env python3
"""Generate overstep.ico with the stdlib only (no Pillow). A dark tile with a cyan
'>' chevron — the overstep mark (stepping over the boundary)."""
import math
import struct
import sys
import zlib

W = H = 64
BG = (13, 17, 23)
AC = (57, 208, 216)
px = bytearray(W * H * 4)


def setp(x, y, r, g, b, a=255):
    if 0 <= x < W and 0 <= y < H:
        i = (y * W + x) * 4
        px[i:i + 4] = bytes((r, g, b, a))


for y in range(H):
    for x in range(W):
        setp(x, y, *BG)


def line(x0, y0, x1, y1, col, t=4):
    steps = max(abs(x1 - x0), abs(y1 - y0)) or 1
    for s in range(steps + 1):
        x = round(x0 + (x1 - x0) * s / steps)
        y = round(y0 + (y1 - y0) * s / steps)
        for dx in range(-t, t + 1):
            for dy in range(-t, t + 1):
                if dx * dx + dy * dy <= t * t:
                    setp(x + dx, y + dy, *col)


# a bold ">" chevron
line(22, 15, 46, 32, AC, t=4)
line(46, 32, 22, 49, AC, t=4)


def png(data, w, h):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw.extend(data[y * w * 4:(y + 1) * w * 4])
    comp = zlib.compress(bytes(raw), 9)

    def chunk(typ, d):
        c = typ + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", comp) + chunk(b"IEND", b"")


def ico(pngdata, w, h):
    hdr = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", w if w < 256 else 0, h if h < 256 else 0,
                        0, 0, 1, 32, len(pngdata), 22)
    return hdr + entry + pngdata


out = sys.argv[1] if len(sys.argv) > 1 else "overstep.ico"
with open(out, "wb") as f:
    f.write(ico(png(px, W, H), W, H))
print(f"wrote {out}")
