#!/usr/bin/env python3
"""
Generate PWA icons from a source image (TextileBazar logo)
"""

from PIL import Image
import os

# ================= CONFIG =================

SOURCE_IMAGE = "textilebazar.png"  # <-- rename your uploaded image to this
OUTPUT_DIR = "static/icons"

ICON_SIZES = [
    16, 32, 72, 96, 128, 144,
    152, 192, 384, 512
]

MASKABLE_PADDING_RATIO = 0.8  # 80% safe area

# ==========================================


def load_source_image():
    """Load the original logo image"""
    if not os.path.exists(SOURCE_IMAGE):
        raise FileNotFoundError(
            f"Source image not found: {SOURCE_IMAGE}"
        )
    return Image.open(SOURCE_IMAGE).convert("RGBA")


def resize_icon(img, size):
    """Resize image to exact square icon"""
    return img.resize((size, size), Image.LANCZOS)


def create_maskable_icon(img, size):
    """Create maskable icon with padding"""
    base = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    safe_size = int(size * MASKABLE_PADDING_RATIO)
    resized = img.resize((safe_size, safe_size), Image.LANCZOS)

    x = (size - safe_size) // 2
    y = (size - safe_size) // 2

    base.paste(resized, (x, y), resized)
    return base


def generate_icons():
    """Generate all PWA icons"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    source_img = load_source_image()

    print("🚀 Generating TextileBazar PWA icons...\n")

    for size in ICON_SIZES:
        icon = resize_icon(source_img, size)
        path = f"{OUTPUT_DIR}/icon-{size}x{size}.png"
        icon.save(path, "PNG")
        print(f"✓ icon-{size}x{size}.png")

    # Maskable icon (Android recommended)
    maskable = create_maskable_icon(source_img, 192)
    maskable.save(f"{OUTPUT_DIR}/icon-maskable-192x192.png", "PNG")
    print("✓ icon-maskable-192x192.png")

    print("\n✅ All icons generated successfully!")
    print("📁 Output folder:", OUTPUT_DIR)


if __name__ == "__main__":
    generate_icons()