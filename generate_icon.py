from PIL import Image, ImageDraw

def create_icon():
    size = (256, 256)
    # Create a new image with a transparent background
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Colors
    computer_color = (50, 50, 50, 255)
    screen_color = (100, 150, 255, 255)
    line_color = (100, 100, 100, 255)
    glass_rim_color = (200, 200, 200, 255)
    glass_handle_color = (139, 69, 19, 255)
    glass_lens_color = (200, 255, 255, 100)

    # Draw Network Connections (Lines)
    top_node = (128, 80)
    left_node = (70, 180)
    right_node = (186, 180)

    draw.line([top_node, left_node], fill=line_color, width=5)
    draw.line([top_node, right_node], fill=line_color, width=5)
    draw.line([left_node, right_node], fill=line_color, width=5)

    # Draw Computers (Simple Monitor shapes)
    def draw_computer(x, y, scale=1.0):
        w = 40 * scale
        h = 30 * scale
        # Stand
        draw.rectangle([x - w/4, y + h/2, x + w/4, y + h/2 + 10*scale], fill=computer_color)
        # Base
        draw.rectangle([x - w/2, y + h/2 + 10*scale, x + w/2, y + h/2 + 15*scale], fill=computer_color)
        # Monitor Frame
        draw.rectangle([x - w, y - h, x + w, y + h], fill=computer_color)
        # Screen
        draw.rectangle([x - w + 5*scale, y - h + 5*scale, x + w - 5*scale, y + h - 5*scale], fill=screen_color)

    draw_computer(top_node[0], top_node[1])
    draw_computer(left_node[0], left_node[1])
    draw_computer(right_node[0], right_node[1])

    # Draw Magnifying Glass
    # Lens
    lens_center = (160, 160)
    lens_radius = 60
    handle_len = 80
    
    # Handle (diagonal down-right)
    start_handle = (lens_center[0] + lens_radius * 0.7, lens_center[1] + lens_radius * 0.7)
    end_handle = (start_handle[0] + handle_len * 0.7, start_handle[1] + handle_len * 0.7)
    draw.line([start_handle, end_handle], fill=glass_handle_color, width=20)

    # Rim
    bbox = [lens_center[0] - lens_radius, lens_center[1] - lens_radius, 
            lens_center[0] + lens_radius, lens_center[1] + lens_radius]
    draw.ellipse(bbox, outline=glass_rim_color, width=10)
    
    # Glass (semi-transparent)
    draw.ellipse(bbox, fill=glass_lens_color)

    # Save as ICO
    img.save('app.ico', format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
    print("Icon created: app.ico")

if __name__ == "__main__":
    create_icon()
