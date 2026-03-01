"""
Image Codec Module
Converts binary data to/from RGB images for steganographic transmission.
"""

import math
from PIL import Image


def binary_to_image(data: bytes, output_path: str) -> dict:
    """
    Converts binary data to an RGB image.
    
    Each 3 bytes of data become one RGB pixel.
    The original data length is stored in the first 4 bytes (prepended).
    
    Args:
        data: Binary data to encode into the image
        output_path: Path to save the output PNG image
        
    Returns:
        dict with encoding metadata (size, dimensions, path)
    """
    print("\n   [IMAGE ENCODING - START]")
    print(f"   - Input data size: {len(data)} bytes")
    
    # Prepend original length (4 bytes, big-endian) for accurate recovery
    length_header = len(data).to_bytes(4, 'big')
    data_with_header = length_header + data
    
    print(f"   - Added 4-byte length header: {len(data)} (0x{length_header.hex()})")
    
    # Convert bytes to RGB pixel tuples
    pixels = []
    for i in range(0, len(data_with_header), 3):
        chunk = data_with_header[i:i+3]
        # Pad incomplete chunks with zeros
        chunk += b"\x00" * (3 - len(chunk))
        pixels.append(tuple(chunk))
    
    print(f"   - Generated {len(pixels)} RGB pixels")
    
    # Calculate square image dimensions
    size = math.ceil(math.sqrt(len(pixels)))
    
    # Create image and populate with pixel data
    img = Image.new("RGB", (size, size))
    # Pad with black pixels to fill the square
    padded_pixels = pixels + [(0, 0, 0)] * (size * size - len(pixels))
    img.putdata(padded_pixels)
    
    # Save as PNG (lossless compression required)
    img.save(output_path, format="PNG")
    
    print(f"   - Image dimensions: {size}x{size} pixels")
    print(f"   - Padding pixels added: {size * size - len(pixels)}")
    print(f"   - Output saved to: {output_path}")
    print("   [IMAGE ENCODING - COMPLETE]")
    
    return {
        "original_size": len(data),
        "total_pixels": len(pixels),
        "image_dimensions": (size, size),
        "output_path": output_path
    }


def image_to_binary(image_path: str) -> bytes:
    """
    Converts an RGB image back to binary data.
    
    Reads the length header from the first 4 bytes to determine
    the exact original data size (removes padding).
    
    Args:
        image_path: Path to the PNG image to decode
        
    Returns:
        Original binary data
    """
    print("\n   [IMAGE DECODING - START]")
    print(f"   - Reading image from: {image_path}")
    
    # Open and read image
    img = Image.open(image_path)
    img = img.convert("RGB")  # Ensure RGB mode
    
    width, height = img.size
    print(f"   - Image dimensions: {width}x{height} pixels")
    
    # Extract all pixels
    pixels = list(img.getdata())
    print(f"   - Total pixels read: {len(pixels)}")
    
    # Convert pixels back to bytes
    raw_bytes = b""
    for pixel in pixels:
        raw_bytes += bytes(pixel)
    
    # Extract length header (first 4 bytes)
    if len(raw_bytes) < 4:
        raise ValueError("Image data too small to contain length header")
    
    original_length = int.from_bytes(raw_bytes[:4], 'big')
    print(f"   - Length header decoded: {original_length} bytes")
    
    # Extract original data (skip header, trim padding)
    data = raw_bytes[4:4 + original_length]
    
    print(f"   - Extracted data size: {len(data)} bytes")
    print(f"   - Padding bytes removed: {len(raw_bytes) - 4 - original_length}")
    print("   [IMAGE DECODING - COMPLETE]")
    
    return data
