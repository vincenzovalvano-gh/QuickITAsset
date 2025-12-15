from PIL import Image, ImageDraw, ImageFont
import os

def create_exit_splash():
    width = 400
    height = 200
    background_color = (240, 240, 240, 255)
    text_color = (50, 50, 50, 255)
    
    img = Image.new('RGBA', (width, height), background_color)
    draw = ImageDraw.Draw(img)
    
    # Draw a border
    draw.rectangle([0, 0, width-1, height-1], outline=(100, 100, 100, 255), width=2)
    
    # Draw "Goodbye" text
    try:
        font_large = ImageFont.truetype("arial.ttf", 40)
        font_small = ImageFont.truetype("arial.ttf", 16)
    except IOError:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    text = "Goodbye!"
    subtext = "Closing QuickITAsset..."
    
    # Calculate text position to center it
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (width - text_width) // 2
    y = (height - text_height) // 2 - 20
    
    draw.text((x, y), text, font=font_large, fill=text_color)
    
    # Subtext
    bbox_sub = draw.textbbox((0, 0), subtext, font=font_small)
    sub_width = bbox_sub[2] - bbox_sub[0]
    
    x_sub = (width - sub_width) // 2
    y_sub = y + text_height + 10
    
    draw.text((x_sub, y_sub), subtext, font=font_small, fill=text_color)
    
    img.save("splash_exit.png")
    print("splash_exit.png created successfully.")

if __name__ == "__main__":
    create_exit_splash()
