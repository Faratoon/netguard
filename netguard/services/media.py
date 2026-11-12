"""Image management: device photos, blocked-page screenshots and network topology maps."""
from __future__ import annotations

import html
import io
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
MAX_BYTES = 10 * 1024 * 1024


@dataclass
class StoredImage:
    filename: str
    path: Path
    title: str | None = None
    kind: str = "device_photo"
    width: int | None = None
    height: int | None = None


def save_image(
    data: bytes,
    media_dir: Path,
    filename: str | None = None,
    kind: str = "device_photo",
    title: str | None = None,
    make_thumbnail: bool = True,
) -> StoredImage:
    """Store an image, validate it and (optionally) build a thumbnail."""
    if not data:
        raise ValueError("empty upload")
    if len(data) > MAX_BYTES:
        raise ValueError("image too large (max 10 MB)")

    ext = Path(filename or "upload.png").suffix.lower() or ".png"
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"unsupported image type: {ext}")

    media_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}{ext}"
    target = media_dir / stored_name
    target.write_bytes(data)

    width = height = None
    try:
        from PIL import Image

        with Image.open(target) as img:
            width, height = img.size
            if make_thumbnail and ext != ".svg":
                img = img.convert("RGB")
                thumb = img.copy()
                thumb.thumbnail((320, 320))
                thumb.save(media_dir / f"thumb-{stored_name}", "PNG")
    except Exception:
        # PIL not available or SVG file - keep the original untouched.
        pass

    return StoredImage(stored_name, target, title, kind, width, height)


def delete_image(media_dir: Path, filename: str) -> bool:
    target = media_dir / filename
    thumb = media_dir / f"thumb-{filename}"
    removed = False
    for path in (target, thumb):
        if path.exists():
            path.unlink()
            removed = True
    return removed


def capture_blocked_page(url: str, timeout_ms: int = 15000) -> bytes | None:
    """Screenshot a blocked page (evidence for parents). Requires playwright."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, timeout=timeout_ms)
            data = page.screenshot(full_page=False)
            browser.close()
            return data
    except Exception:
        return None


def build_topology_svg(devices: list[dict[str, Any]], router: dict[str, Any] | None = None) -> bytes:
    """Render a simple SVG topology map of the router and its clients."""
    router = router or {}
    width, height = 900, 520
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs><style>'
        '.t{font-family:sans-serif;font-size:13px;fill:#e6edf3}'
        '.s{font-family:sans-serif;font-size:11px;fill:#8b949e}'
        '</style></defs>',
        f'<rect width="{width}" height="{height}" fill="#0d1117"/>',
    ]

    cx, cy = width / 2, 110
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="46" fill="#1f6feb" opacity="0.25"/>')
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="30" fill="#1f6feb"/>')
    parts.append(
        f'<text class="t" x="{cx}" y="{cy + 5}" text-anchor="middle">'
        f'{html.escape(str(router.get("model", "Router")))}</text>'
    )
    parts.append(
        f'<text class="s" x="{cx}" y="{cy + 66}" text-anchor="middle">'
        f'{html.escape(str(router.get("wan_ip") or "no WAN"))} &middot; '
        f'{html.escape(str(router.get("firmware", "")))}</text>'
    )

    count = len(devices)
    if count:
        radius_x, radius_y = 330, 150
        for index, dev in enumerate(devices):
            angle = (2 * 3.14159 / count) * index - 3.14159 / 2
            x = cx + radius_x * __import__("math").cos(angle)
            y = cy + 190 + radius_y * __import__("math").sin(angle) * 0.9
            parts.append(f'<line x1="{cx}" y1="{cy + 30}" x2="{x:.0f}" y2="{y:.0f}" stroke="#30363d" stroke-width="1.5"/>')
            blocked = dev.get("is_blocked") or dev.get("is_quarantined")
            fill = "#f85149" if blocked else "#238636"
            parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="22" fill="{fill}" opacity="0.9"/>')
            label = html.escape(str(dev.get("friendly_name") or dev.get("hostname") or dev.get("mac", "")))
            parts.append(f'<text class="t" x="{x:.0f}" y="{y + 4:.0f}" text-anchor="middle">{label[:16]}</text>')
            parts.append(
                f'<text class="s" x="{x:.0f}" y="{y + 34:.0f}" text-anchor="middle">'
                f'{html.escape(str(dev.get("ip") or ""))}</text>'
            )
    parts.append("</svg>")
    return "".join(parts).encode("utf-8")


def image_to_bytes(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(path)
    return path.read_bytes()


def png_placeholder(text: str, size: int = 320) -> bytes:
    """Generate a simple PNG placeholder card (no external fonts required)."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (size, size), (13, 17, 23))
    draw = ImageDraw.Draw(img)
    draw.rectangle([8, 8, size - 8, size - 8], outline=(48, 54, 61), width=2)
    draw.text((20, size // 2), text[:30], fill=(139, 148, 158))
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    return buffer.getvalue()
