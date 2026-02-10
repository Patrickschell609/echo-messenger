#!/usr/bin/env python3
"""Generate ECHO Messenger icon — clean ripple arcs, no glow."""

from PIL import Image, ImageDraw
import math
import os

def make_icon(size):
    s = size * 4
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = s // 2, s // 2
    radius = s // 2

    # Dark circle background
    for r in range(radius, 0, -1):
        t = r / radius
        c = int(20 + 8 * (1 - t))  # darker center, slightly lighter edge
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(c, c + 3, c + 8, 255))

    # Subtle border
    bw = max(s // 90, 2)
    draw.ellipse([bw, bw, s - bw - 1, s - bw - 1], outline=(74, 158, 255, 35), width=bw)

    # === ECHO ARCS ===
    origin_x = cx - int(s * 0.10)
    origin_y = cy
    blue = (74, 158, 255)

    arcs = [
        (0.17, 255, 0.035, 120),
        (0.28, 170, 0.028, 110),
        (0.39, 90,  0.022, 100),
    ]

    for rad_f, alpha, thick_f, span in arcs:
        r = int(s * rad_f)
        w = max(int(s * thick_f), 3)
        half = span // 2
        bbox = [origin_x - r, origin_y - r, origin_x + r, origin_y + r]
        color = (*blue, alpha)
        draw.arc(bbox, start=-half, end=half, fill=color, width=w)

        # Round caps
        for angle in [-half, half]:
            rad = math.radians(angle)
            ex = origin_x + r * math.cos(rad)
            ey = origin_y - r * math.sin(rad)
            cr = w // 2
            draw.ellipse([ex - cr, ey - cr, ex + cr, ey + cr], fill=color)

    # === CENTER DOT — clean, no glow ===
    dot_r = int(s * 0.050)
    draw.ellipse(
        [origin_x - dot_r, origin_y - dot_r, origin_x + dot_r, origin_y + dot_r],
        fill=(*blue, 255)
    )
    # Small bright center
    hi_r = max(dot_r // 3, 2)
    draw.ellipse(
        [origin_x - hi_r, origin_y - hi_r, origin_x + hi_r, origin_y + hi_r],
        fill=(180, 215, 255, 255)
    )

    return img.resize((size, size), Image.LANCZOS)


icon_dir = "/home/oday/Documents/echo-messenger/echo-app/src-tauri/icons"
print("Generating icons...")

for name, sz in [("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256), ("icon.png", 512)]:
    make_icon(sz).save(f"{icon_dir}/{name}")

make_icon(32).save(f"{icon_dir}/icon.ico", format='ICO', sizes=[(32, 32)])
make_icon(128).save(f"{icon_dir}/icon.icns", format='PNG')

print("Done!")
for f in sorted(os.listdir(icon_dir)):
    print(f"  {f}: {os.path.getsize(os.path.join(icon_dir, f)):,} bytes")
