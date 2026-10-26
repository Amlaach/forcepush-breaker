"""
Official Logo & Multi-Platform Icon Pipeline for UnForce (ForcePush-Breaker).
Synchronizes the single official repository emblem (`assets/logo.png`) across:
  - assets/logo.png              (512x512 rounded-rect GitHub Repo Hero Logo)
  - desktop/assets/icon.png      (256x256 RGBA Desktop Window & Linux/macOS Icon)
  - desktop/assets/icon.ico      (Multi-resolution 256/128/64/48/32/16 Windows .exe Icon)
  - gitghost/static/logo_data.js (Inline Base64 Data-URI so Titlebar/Sidebar/Splash match 100%)
"""

from __future__ import annotations

import base64
import io
import struct
import sys
from pathlib import Path


def _build_ico_from_png_frames(frames: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(frames))
    dir_entries = []
    offset = 6 + 16 * len(frames)
    for sz, png_bytes in frames:
        w_byte = 0 if sz >= 256 else sz
        h_byte = 0 if sz >= 256 else sz
        entry = struct.pack(
            "<BBBBHHII",
            w_byte,
            h_byte,
            0,
            0,
            1,
            32,
            len(png_bytes),
            offset,
        )
        dir_entries.append(entry)
        offset += len(png_bytes)
    return header + b"".join(dir_entries) + b"".join(p for _, p in frames)


def generate_from_source(source_image_path: Path, root: Path) -> None:
    from PIL import Image, ImageChops, ImageDraw

    repo_assets = root / "assets"
    desktop_assets = root / "desktop" / "assets"
    static_dir = root / "gitghost" / "static"
    repo_assets.mkdir(parents=True, exist_ok=True)
    desktop_assets.mkdir(parents=True, exist_ok=True)
    static_dir.mkdir(parents=True, exist_ok=True)

    img = Image.open(source_image_path).convert("RGBA")
    w, h = img.size
    side = min(w, h)
    # Crop slightly inward (92%) so artwork fills the icon edge-to-edge crisply
    crop_side = int(side * 0.94)
    left = (w - crop_side) // 2
    top = (h - crop_side) // 2
    img = img.crop((left, top, left + crop_side, top + crop_side))

    def render_rounded(size: int) -> Image.Image:
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        # Supersampled 4x rounded-rectangle alpha mask + subtle neon cyan border
        ss = size * 4
        mask = Image.new("L", (ss, ss), 0)
        draw = ImageDraw.Draw(mask)
        radius = int(ss * 0.215)
        pad = int(ss * 0.015)
        draw.rounded_rectangle((pad, pad, ss - 1 - pad, ss - 1 - pad), radius=radius, fill=255)
        mask_aa = mask.resize((size, size), Image.Resampling.LANCZOS)

        # Subtle crisp neon rim so icon stands out on dark Windows 11 taskbars
        rim_layer = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        rim_draw = ImageDraw.Draw(rim_layer)
        stroke_w = max(4, int(ss * 0.018))
        rim_draw.rounded_rectangle(
            (pad + stroke_w // 2, pad + stroke_w // 2, ss - 1 - pad - stroke_w // 2, ss - 1 - pad - stroke_w // 2),
            radius=radius,
            outline=(0, 240, 200, 215),
            width=stroke_w,
        )
        rim_aa = rim_layer.resize((size, size), Image.Resampling.LANCZOS)

        out = resized.copy()
        existing_a = out.getchannel("A")
        out.putalpha(ImageChops.multiply(existing_a, mask_aa))
        out = Image.alpha_composite(out, rim_aa)
        return out

    # 1. Official GitHub Repo Logo (512x512)
    logo_512 = render_rounded(512)
    logo_512_path = repo_assets / "logo.png"
    logo_512.save(logo_512_path, format="PNG", optimize=True)

    # 2. Desktop Window & Linux/macOS Icon (256x256)
    icon_256 = render_rounded(256)
    icon_256_path = desktop_assets / "icon.png"
    icon_256.save(icon_256_path, format="PNG", optimize=True)

    # 3. Multi-Resolution Windows .exe ICO (256, 128, 64, 48, 32, 16)
    ico_sizes = [256, 128, 64, 48, 32, 16]
    frames: list[tuple[int, bytes]] = []
    for sz in ico_sizes:
        frame_img = render_rounded(sz)
        buf = io.BytesIO()
        frame_img.save(buf, format="PNG", optimize=True)
        frames.append((sz, buf.getvalue()))
    (desktop_assets / "icon.ico").write_bytes(_build_ico_from_png_frames(frames))

    # 4. Compact UI Inline Logo Data-URI (96x96 WebP/PNG) for Titlebar, Sidebar & Splash
    ui_logo = render_rounded(96)
    ui_buf = io.BytesIO()
    try:
        ui_logo.save(ui_buf, format="WEBP", quality=90, lossless=False)
        mime = "image/webp"
    except Exception:
        ui_buf = io.BytesIO()
        ui_logo.save(ui_buf, format="PNG", optimize=True)
        mime = "image/png"

    b64 = base64.b64encode(ui_buf.getvalue()).decode("ascii")
    data_uri = f"data:{mime};base64,{b64}"
    (static_dir / "logo_data.js").write_text(
        f'window.UNFORCE_LOGO_DATA_URI = "{data_uri}";\n',
        encoding="utf-8",
    )
    print(f"Unified logo & icons generated from {source_image_path.name} -> {logo_512_path}, {desktop_assets / 'icon.ico'}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    cli_src = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else (root / "assets" / "logo.png")
    try:
        import PIL  # noqa: F401
    except ImportError:
        if (root / "desktop" / "assets" / "icon.ico").is_file() and (root / "assets" / "logo.png").is_file():
            print("Pillow not installed; using pre-built unified repository & desktop icons.")
            return
        raise
    if not cli_src.is_file():
        raise FileNotFoundError(f"Logo source not found: {cli_src}")
    generate_from_source(cli_src, root)


if __name__ == "__main__":
    main()
