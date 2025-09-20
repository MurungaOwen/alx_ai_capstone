#!/usr/bin/env python3
"""
Script to create simple icon files for the Chrome extension
Creates basic shield icons in different sizes
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_shield_icon(size, output_path):
    """Create a shield icon with the specified size"""
    
    # Create a new image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Define colors
    shield_color = (34, 139, 34)  # Forest green
    outline_color = (25, 25, 25)  # Dark gray
    highlight_color = (144, 238, 144)  # Light green
    
    # Calculate dimensions
    margin = max(2, size // 16)
    shield_width = size - (2 * margin)
    shield_height = int(shield_width * 1.2)
    
    # Center the shield
    x_offset = (size - shield_width) // 2
    y_offset = (size - shield_height) // 2
    
    # Draw shield shape (rounded rectangle with pointed bottom)
    top_left = (x_offset, y_offset)
    top_right = (x_offset + shield_width, y_offset)
    bottom_center = (x_offset + shield_width // 2, y_offset + shield_height)
    
    # Create shield path
    shield_points = []
    
    # Top edge (rounded corners)
    corner_radius = max(2, size // 8)
    for i in range(shield_width + 1):
        x = x_offset + i
        if i < corner_radius:
            y = y_offset + corner_radius - int((corner_radius**2 - (corner_radius - i)**2)**0.5)
        elif i > shield_width - corner_radius:
            y = y_offset + corner_radius - int((corner_radius**2 - (i - (shield_width - corner_radius))**2)**0.5)
        else:
            y = y_offset
        shield_points.append((x, y))
    
    # Right edge
    for i in range(1, shield_height - corner_radius):
        shield_points.append((x_offset + shield_width, y_offset + i))
    
    # Bottom point (triangle)
    triangle_height = shield_height // 4
    for i in range(shield_width // 2 + 1):
        x = x_offset + shield_width - i
        y = y_offset + shield_height - triangle_height + int(triangle_height * i / (shield_width // 2))
        shield_points.append((x, y))
    
    for i in range(shield_width // 2):
        x = x_offset + i
        y = y_offset + shield_height - triangle_height + int(triangle_height * (shield_width // 2 - i) / (shield_width // 2))
        shield_points.append((x, y))
    
    # Left edge
    for i in range(shield_height - corner_radius - triangle_height, 0, -1):
        shield_points.append((x_offset, y_offset + i))
    
    # Draw filled shield
    draw.polygon(shield_points, fill=shield_color, outline=outline_color, width=max(1, size // 32))
    
    # Add highlight
    highlight_points = []
    highlight_margin = max(1, size // 16)
    for i in range(len(shield_points) // 3):  # Top third for highlight
        x, y = shield_points[i]
        highlight_points.append((x + highlight_margin, y + highlight_margin))
    
    if highlight_points:
        draw.polygon(highlight_points, fill=highlight_color)
    
    # Add checkmark or security symbol
    if size >= 32:
        # Draw a checkmark
        check_size = size // 4
        check_x = x_offset + shield_width // 2
        check_y = y_offset + shield_height // 2
        
        check_points = [
            (check_x - check_size // 2, check_y),
            (check_x - check_size // 4, check_y + check_size // 2),
            (check_x + check_size // 2, check_y - check_size // 2)
        ]
        
        draw.line(check_points[0] + check_points[1], fill='white', width=max(2, size // 16))
        draw.line(check_points[1] + check_points[2], fill='white', width=max(2, size // 16))
    
    # Save the image
    img.save(output_path, 'PNG')
    print(f"Created {output_path} ({size}x{size})")

def main():
    """Create all required icon sizes"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Icon sizes required by Chrome extensions
    sizes = [16, 32, 48, 128]
    
    for size in sizes:
        output_path = os.path.join(script_dir, f'icon-{size}.png')
        try:
            create_shield_icon(size, output_path)
        except Exception as e:
            print(f"Error creating {size}x{size} icon: {e}")
            # Create a simple colored square as fallback
            img = Image.new('RGBA', (size, size), (34, 139, 34, 255))
            img.save(output_path, 'PNG')
            print(f"Created fallback {output_path} ({size}x{size})")

if __name__ == "__main__":
    main()