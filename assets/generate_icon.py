"""Generate the Auto Forensics application icon.

Run once to produce assets/icon.ico and assets/icon.png:
    python assets/generate_icon.py
"""

import math
import struct
import zlib
from pathlib import Path

_HERE = Path(__file__).parent


def _draw_pixel(
    buf: bytearray,
    size: int,
    x: int,
    y: int,
    r: int,
    g: int,
    b: int,
    a: int = 255,
) -> None:
    if 0 <= x < size and 0 <= y < size:
        idx = (y * size + x) * 4
        buf[idx] = r
        buf[idx + 1] = g
        buf[idx + 2] = b
        buf[idx + 3] = a


def _fill_circle(
    buf: bytearray,
    size: int,
    cx: float,
    cy: float,
    radius: float,
    r: int,
    g: int,
    b: int,
    a: int = 255,
) -> None:
    x0 = max(0, int(cx - radius - 1))
    x1 = min(size, int(cx + radius + 2))
    y0 = max(0, int(cy - radius - 1))
    y1 = min(size, int(cy + radius + 2))
    r2 = radius * radius
    for py in range(y0, y1):
        for px in range(x0, x1):
            dx = px + 0.5 - cx
            dy = py + 0.5 - cy
            if dx * dx + dy * dy <= r2:
                _draw_pixel(buf, size, px, py, r, g, b, a)


def _fill_rect(
    buf: bytearray,
    size: int,
    x: int,
    y: int,
    w: int,
    h: int,
    r: int,
    g: int,
    b: int,
    a: int = 255,
) -> None:
    for py in range(y, min(y + h, size)):
        for px in range(x, min(x + w, size)):
            _draw_pixel(buf, size, px, py, r, g, b, a)


def _draw_line(
    buf: bytearray,
    size: int,
    x0: int,
    y0: int,
    x1: int,
    y1: int,
    thickness: int,
    r: int,
    g: int,
    b: int,
    a: int = 255,
) -> None:
    dx = x1 - x0
    dy = y1 - y0
    length = max(abs(dx), abs(dy), 1)
    for i in range(length + 1):
        t = i / length
        px = int(x0 + dx * t)
        py = int(y0 + dy * t)
        for ox in range(-(thickness // 2), (thickness + 1) // 2):
            for oy in range(-(thickness // 2), (thickness + 1) // 2):
                _draw_pixel(buf, size, px + ox, py + oy, r, g, b, a)


def _render(size: int) -> bytearray:
    """Render the icon at *size* x *size* pixels into an RGBA bytearray."""
    buf = bytearray(size * size * 4)
    s = size / 256.0  # scale factor

    # ── Background: dark navy circle ────────────────────────────────────────
    c = size / 2
    _fill_circle(buf, size, c, c, c * 0.98, 15, 23, 42)

    # ── Outer ring (teal) ───────────────────────────────────────────────────
    outer_r = c * 0.88
    ring_w = max(2, int(6 * s))
    for i in range(0, 360, 1):
        rad = math.radians(i)
        rx = c + outer_r * math.cos(rad)
        ry = c + outer_r * math.sin(rad)
        for t in range(-ring_w, ring_w + 1):
            tr = math.radians(i + t * 0.5)
            px2 = int(c + outer_r * math.cos(tr))
            py2 = int(c + outer_r * math.sin(tr))
            _draw_pixel(buf, size, px2, py2, 0, 210, 190)

    # ── Magnifying glass handle ──────────────────────────────────────────────
    lens_cx = c * 0.85
    lens_cy = c * 0.85
    lens_r = c * 0.35
    handle_len = int(c * 0.38)
    handle_thick = max(3, int(10 * s))
    hx0 = int(lens_cx + lens_r * 0.7)
    hy0 = int(lens_cy + lens_r * 0.7)
    hx1 = hx0 + handle_len
    hy1 = hy0 + handle_len
    _draw_line(
        buf, size, hx0, hy0, hx1, hy1, handle_thick, 0, 200, 180
    )

    # ── Magnifying glass ring ────────────────────────────────────────────────
    ring2_thick = max(3, int(9 * s))
    for i in range(360):
        for ri in range(-ring2_thick, ring2_thick + 1):
            rr = lens_r + ri * 0.5
            rad = math.radians(i)
            px2 = int(lens_cx + rr * math.cos(rad))
            py2 = int(lens_cy + rr * math.sin(rad))
            _draw_pixel(buf, size, px2, py2, 0, 210, 190)

    # ── Binary rain streaks inside lens ─────────────────────────────────────
    stripe_r = 0
    stripe_g = 190
    stripe_b = 160
    col_w = max(1, int(8 * s))
    cols = [int(lens_cx - lens_r * 0.55), int(lens_cx), int(lens_cx + lens_r * 0.55)]
    heights = [0.55, 0.70, 0.45]
    for col_x, h_frac in zip(cols, heights):
        bar_h = int(lens_r * h_frac)
        bar_y = int(lens_cy - bar_h // 2)
        for py in range(bar_y, bar_y + bar_h):
            px2 = col_x - col_w // 2
            dx2 = py - bar_y
            dy2 = bar_h
            alpha = int(255 * (1.0 - abs(dx2 / dy2 - 0.5) * 1.8))
            alpha = max(0, min(255, alpha))
            ddx = int((lens_cx - col_x) * 0.1)
            ddy = int((lens_cy - py) * 0.1)
            dist2 = (col_x - lens_cx) ** 2 + (py - lens_cy) ** 2
            if dist2 < (lens_r * 0.75) ** 2:
                for bx in range(col_w):
                    _draw_pixel(
                        buf, size, px2 + bx, py, stripe_r, stripe_g, stripe_b, alpha
                    )

    # ── Small dot cluster (findings) ────────────────────────────────────────
    dots = [
        (c * 0.30, c * 0.38, 0.030),
        (c * 0.45, c * 0.28, 0.022),
        (c * 0.22, c * 0.55, 0.018),
        (c * 0.55, c * 0.40, 0.015),
    ]
    for dx2, dy2, dr in dots:
        _fill_circle(buf, size, dx2, dy2, dr * size, 255, 80, 80)

    return buf


def _rgba_to_png(buf: bytearray, size: int) -> bytes:
    """Minimal PNG encoder (no external deps)."""

    def _chunk(tag: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return length + tag + data + crc

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    # RGBA → RGB (strip alpha) for simpler PNG; keep alpha for ICO
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter byte
        for x in range(size):
            idx = (y * size + x) * 4
            row += buf[idx : idx + 3]
        rows.append(bytes(row))
    idat = zlib.compress(b"".join(rows), 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def _rgba_to_ico(buffers: list[tuple[bytearray, int]]) -> bytes:
    """Pack multiple RGBA images into a .ico file using PNG compression."""
    num = len(buffers)
    header = struct.pack("<HHH", 0, 1, num)
    entries = bytearray()
    images = []
    offset = 6 + num * 16
    for buf, size in buffers:
        png_data = _rgba_to_png_rgba(buf, size)
        w = size if size < 256 else 0
        h = size if size < 256 else 0
        entries += struct.pack(
            "<BBBBHHII",
            w, h,    # width, height (0 = 256)
            0,       # color count
            0,       # reserved
            1,       # planes
            32,      # bit count
            len(png_data),
            offset,
        )
        images.append(png_data)
        offset += len(png_data)
    return header + bytes(entries) + b"".join(images)


def _rgba_to_png_rgba(buf: bytearray, size: int) -> bytes:
    """PNG with RGBA channel (needed for ICO transparency)."""

    def _chunk(tag: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return length + tag + data + crc

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # color type 6 = RGBA
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter type none
        for x in range(size):
            idx = (y * size + x) * 4
            row += buf[idx : idx + 4]
        rows.append(bytes(row))
    idat = zlib.compress(b"".join(rows), 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


def generate(dest_dir: Path = _HERE) -> None:
    sizes = [16, 32, 48, 64, 128, 256]
    buffers = [(b := _render(s), s) for s in sizes]  # noqa: F841

    # ICO
    ico_path = dest_dir / "icon.ico"
    ico_data = _rgba_to_ico([(b, s) for b, s in buffers])
    ico_path.write_bytes(ico_data)
    print(f"Wrote {ico_path}")

    # PNG (largest size for Linux/web)
    png_path = dest_dir / "icon.png"
    large_buf, large_size = buffers[-1]
    png_data = _rgba_to_png_rgba(large_buf, large_size)
    png_path.write_bytes(png_data)
    print(f"Wrote {png_path}")


if __name__ == "__main__":
    generate()
