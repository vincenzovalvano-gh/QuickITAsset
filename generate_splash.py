from PIL import Image, ImageDraw, ImageFont
import os

def create_splash():
    width = 400
    height = 200
    background_color = (240, 240, 240, 255)
    text_color = (50, 50, 50, 255)
    
    img = Image.new('RGBA', (width, height), background_color)
    draw = ImageDraw.Draw(img)
    
    # Draw a border
    draw.rectangle([0, 0, width-1, height-1], outline=(100, 100, 100, 255), width=2)
    
    # Draw "QuickAsset" text
    # Since we might not have a specific font, we'll use the default one or try to load arial
    try:
        font_large = ImageFont.truetype("arial.ttf", 40)
        font_small = ImageFont.truetype("arial.ttf", 16)
    except IOError:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    text = "QuickAsset"
    
    # Calculate text position to center it
    # getbbox returns (left, top, right, bottom)
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (width - text_width) // 2
    y = (height - text_height) // 2 - 20
    
    draw.text((x, y), text, font=font_large, fill=text_color)
    
    # Draw "Loading..."
    loading_text = "Loading..."
    bbox_small = draw.textbbox((0, 0), loading_text, font=font_small)
    text_width_small = bbox_small[2] - bbox_small[0]
    
    x_small = (width - text_width_small) // 2
    y_small = y + text_height + 20
    
    draw.text((x_small, y_small), loading_text, font=font_small, fill=(100, 100, 100, 255))

    img.save('splash.png')
    print("splash.png created successfully.")

if __name__ == "__main__":
    create_splash()
