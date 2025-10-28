from PIL import Image, ImageDraw, ImageFont
import os

def create_icon():
    # Create a 256x256 image with transparency
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a shield shape
    margin = 20
    shield_points = [
        (margin, size//3),  # Top left
        (size//2, margin),  # Top middle
        (size-margin, size//3),  # Top right
        (size-margin, size*2//3),  # Bottom right
        (size//2, size-margin),  # Bottom middle
        (margin, size*2//3),  # Bottom left
    ]
    
    # Draw shield gradient
    for i in range(margin, size-margin):
        alpha = int(255 * (1 - i/size))  # Gradient transparency
        draw.line([(margin, i), (size-margin, i)], fill=(48, 209, 88, alpha))
        
    # Draw shield outline
    draw.polygon(shield_points, outline=(255, 255, 255, 255), width=4)
    
    # Draw a key symbol
    key_color = (255, 255, 255, 255)  # White with full opacity
    key_center = (size//2, size//2)
    key_size = size//4
    
    # Draw key head (circle)
    draw.ellipse([
        key_center[0]-key_size//2,
        key_center[1]-key_size//2,
        key_center[0]+key_size//2,
        key_center[1]+key_size//2
    ], outline=key_color, width=4)
    
    # Draw key stem
    draw.rectangle([
        key_center[0]-key_size//6,
        key_center[1]+key_size//2,
        key_center[0]+key_size//6,
        key_center[1]+key_size
    ], fill=key_color)
    
    # Draw key teeth
    tooth_width = key_size//6
    tooth_height = key_size//4
    for i in range(2):
        x = key_center[0] + (i-0.5)*tooth_width
        y = key_center[1] + key_size*3//4
        draw.rectangle([x, y, x+tooth_width, y+tooth_height], fill=key_color)
    
    # Save in multiple sizes for the ico file
    sizes = [(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)]
    icons = []
    for s in sizes:
        icons.append(image.resize(s, Image.Resampling.LANCZOS))
    
    # Save as ICO file
    icons[0].save(
        'secure_credentials/assets/icon.ico',
        format='ICO',
        sizes=sizes,
        append_images=icons[1:]
    )

if __name__ == '__main__':
    # Create assets directory if it doesn't exist
    os.makedirs('secure_credentials/assets', exist_ok=True)
    create_icon()
    print("Icon created successfully in secure_credentials/assets/icon.ico") 