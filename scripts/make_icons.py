"""Generates the PNG icons (192/512) without external dependencies. Run: python scripts/make_icons.py"""
import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "web" / "icons"
BG = (0x0E, 0x8F, 0x86)
FG = (255, 255, 255)
SS = 3  # supersampling for smooth edges


def inside(u: float, v: float, full_bleed: bool) -> tuple[int, int, int, int]:
    """u, v in 0..100 (same coordinates as icon.svg)."""
    if not full_bleed:
        r = 22
        cx = min(max(u, r), 100 - r)
        cy = min(max(v, r), 100 - r)
        if (u - cx) ** 2 + (v - cy) ** 2 > r * r:
            return (0, 0, 0, 0)
    # wifi arcs around (50,70), radii 36/24/12, ±45° from vertical
    dx, dy = u - 50, v - 70
    d = math.hypot(dx, dy)
    if d <= 5.5:
        return (*FG, 255)
    if dy < 0:
        ang = math.degrees(math.atan2(abs(dx), -dy))
        for rad in (36, 24, 12):
            if abs(d - rad) <= 3 and ang <= 45:
                return (*FG, 255)
        # rounded ends
        for rad in (36, 24, 12):
            for sx in (-1, 1):
                ex, ey = 50 + sx * rad * math.sin(math.radians(45)), 70 - rad * math.cos(math.radians(45))
                if math.hypot(u - ex, v - ey) <= 3:
                    return (*FG, 255)
    return (*BG, 255)


def render(size: int, full_bleed: bool) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    u = (x + (sx + 0.5) / SS) / size * 100
                    v = (y + (sy + 0.5) / SS) / size * 100
                    p = inside(u, v, full_bleed)
                    for i in range(4):
                        acc[i] += p[i] * (p[3] / 255 if i < 3 else 1)
            a = acc[3] / (SS * SS)
            if a:
                row += bytes(round(acc[i] / (SS * SS) / (a / 255)) for i in range(3)) + bytes([round(a)])
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    # Full-bleed background: works both as a normal and a "maskable" icon.
    for s in (192, 512):
        (OUT / f"icon-{s}.png").write_bytes(render(s, full_bleed=True))
        print("skrev", OUT / f"icon-{s}.png")
