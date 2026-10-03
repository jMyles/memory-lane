"""The app's icon, drawn here: a white speech bubble on magenta, as a PNG.

Pure Python (zlib and struct), so installing magenta as an app needs
no image files in the repo and no imaging library on the server. Edges are
smoothed from signed distances. Everything sits inside the middle 80%, so a
launcher that crops icons to a circle ("maskable") loses none of it.
"""

import functools
import math
import struct
import zlib

MAGENTA = (0xB8, 0x10, 0x6B)
WHITE = (0xFF, 0xFF, 0xFF)


def _circle(px, py, cx, cy, r):
    return math.hypot(px - cx, py - cy) - r


def _triangle(px, py, a, b, c):
    """Signed distance (roughly) to a triangle: the largest of its edges' half-plane distances."""
    d = -1e9
    pts = (a, b, c)
    # Orient the edges so the inside is negative.
    area = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
    sign = 1 if area > 0 else -1
    for (x1, y1), (x2, y2) in zip(pts, pts[1:] + pts[:1]):
        ex, ey = x2 - x1, y2 - y1
        length = math.hypot(ex, ey)
        d = max(d, sign * ((px - x1) * ey - (py - y1) * ex) / length)
    return d


def _bubble(px, py):
    """Signed distance to the bubble, its tail, minus three dots (units: the icon's width)."""
    body = math.hypot((px - 0.5) / 1.18, py - 0.46) - 0.25
    tail = _triangle(px, py, (0.34, 0.6), (0.48, 0.66), (0.28, 0.78))
    shape = min(body, tail)
    dots = min(_circle(px, py, x, 0.46, 0.035) for x in (0.4, 0.5, 0.6))
    return max(shape, -dots)


@functools.lru_cache(maxsize=4)
def png(size):
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter: none
        for x in range(size):
            d = _bubble((x + 0.5) / size, (y + 0.5) / size) * size  # in pixels
            a = min(1.0, max(0.0, 0.5 - d))  # how much of this pixel is bubble
            row += bytes(round(w * a + m * (1 - a)) for w, m in zip(WHITE, MAGENTA))
        rows.append(bytes(row))

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', zlib.compress(b''.join(rows), 9))
            + chunk(b'IEND', b''))
