#!/usr/bin/env python3
"""
Generate app icons for ImageGuard PWA
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, output_path):
    """Create an app icon with the shield emoji design"""
    # Create image with gradient background
    img = Image.new('RGB', (size, size), color='white')
    draw = ImageDraw.Draw(img)

    # Create gradient background
    for y in range(size):
        # Purple gradient
        r = int(102 + (118 - 102) * (y / size))
        g = int(126 + (75 - 126) * (y / size))
        b = int(234 + (162 - 234) * (y / size))
        draw.line([(0, y), (size, y)], fill=(r, g, b))

    # Draw shield shape
    shield_margin = size // 6
    shield_width = size - (2 * shield_margin)
    shield_height = size - (2 * shield_margin)

    # Shield points
    top_center = (size // 2, shield_margin)
    left_top = (shield_margin, shield_margin + shield_height // 4)
    left_bottom = (shield_margin + shield_width // 4, shield_margin + shield_height)
    bottom_center = (size // 2, shield_margin + shield_height)
    right_bottom = (size - shield_margin - shield_width // 4, shield_margin + shield_height)
    right_top = (size - shield_margin, shield_margin + shield_height // 4)

    # Draw shield
    shield_points = [
        top_center,
        right_top,
        right_bottom,
        bottom_center,
        left_bottom,
        left_top,
        top_center
    ]

    draw.polygon(shield_points, fill='white', outline='white')

    # Draw checkmark or image icon inside shield
    check_size = shield_width // 3
    check_x = size // 2 - check_size // 2
    check_y = shield_margin + shield_height // 3

    # Draw simple image icon (rectangle with circle)
    icon_margin = shield_margin + shield_width // 4
    icon_size = shield_width // 2

    # Draw image frame
    draw.rectangle(
        [icon_margin, icon_margin + shield_height // 6,
         icon_margin + icon_size, icon_margin + shield_height // 6 + icon_size],
        outline=(102, 126, 234),
        width=max(2, size // 64)
    )

    # Draw circle (sun/moon in image)
    circle_center_x = icon_margin + icon_size // 3
    circle_center_y = icon_margin + shield_height // 6 + icon_size // 3
    circle_radius = icon_size // 6

    draw.ellipse(
        [circle_center_x - circle_radius, circle_center_y - circle_radius,
         circle_center_x + circle_radius, circle_center_y + circle_radius],
        fill=(102, 126, 234)
    )

    # Draw mountain/triangle
    mountain_points = [
        (icon_margin + icon_size // 2, icon_margin + shield_height // 6 + icon_size),
        (icon_margin + icon_size * 0.8, icon_margin + shield_height // 6 + icon_size),
        (icon_margin + icon_size * 0.65, icon_margin + shield_height // 6 + icon_size * 0.6)
    ]
    draw.polygon(mountain_points, fill=(102, 126, 234))

    # Save icon
    img.save(output_path, 'PNG')
    print(f"Created icon: {output_path} ({size}x{size})")

if __name__ == '__main__':
    static_dir = os.path.join(os.path.dirname(__file__), 'ipi', 'static')
    os.makedirs(static_dir, exist_ok=True)

    # Generate icons
    create_icon(192, os.path.join(static_dir, 'icon-192.png'))
    create_icon(512, os.path.join(static_dir, 'icon-512.png'))

    print("\n✅ Icons generated successfully!")
