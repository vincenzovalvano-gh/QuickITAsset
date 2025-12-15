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
    
    # Draw "QuickITAsset" text
    # Since we might not have a specific font, we'll use the default one or try to load arial
    try:
        font_large = ImageFont.truetype("arial.ttf", 40)
        font_small = ImageFont.truetype("arial.ttf", 16)
    except IOError:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    text = "QuickITAsset"
    
    # Calculate text position to center it
    # getbbox returns (left, top, right, bottom)
    bbox = draw.textbbox((0, 0), text, font=font_large)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    # Try to load and place icon
    icon_width = 0
    spacing = 15
    try:
        if os.path.exists("app.ico"):
            icon = Image.open("app.ico").convert("RGBA")
            # Resize icon to match text height roughly or a bit larger
            icon_size = 48
            icon = icon.resize((icon_size, icon_size), Image.Resampling.LANCZOS)
            icon_width = icon_size
            
            # Calculate total content width
            total_width = icon_width + spacing + text_width
            
            # Starting X position to center the whole block (icon + text)
            start_x = (width - total_width) // 2
            
            # Y position for text (centered vertically roughly)
            y = (height - text_height) // 2 - 20
            
            # Y position for icon (centered relative to text)
            # text_height is approx 40-50px. icon is 48.
            icon_y = y + (text_height - icon_size) // 2
            
            img.paste(icon, (start_x, icon_y), icon)
            
            # Text X position
            x = start_x + icon_width + spacing
        else:
            x = (width - text_width) // 2
            y = (height - text_height) // 2 - 20
    except Exception as e:
        print(f"Error adding icon: {e}")
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
