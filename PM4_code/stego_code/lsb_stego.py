# Image Steganography - LSB Scheme
import os # Handles files and directory operations
import base64 # Used to encode and decode data in Base64
import numpy as np # Used to work with data in images
from PIL import Image # Helps open, edit and save images
import struct

import crypt_code.encryption as enc # Accesses the encryption and decryption functions

"""
This code contains the LSB steganography and image processing related functions in Pixel Mask 3.0:
    - convert_png(): changes the format of a PNG image to JPG so LSB steganography operations can be performed
    - mask(): hides a message in an image using LSB steganography, if the image has the right format (JPG)
    - unmask(): extracts a message from an image using LSB steganography
Side note: It works without a delimiter now and embeds + extracts variable length messages now
"""

def convert_png(png, quality=95):
    parent_directory = os.path.join(os.path.expanduser('~'), 'Desktop')

    if not os.path.isfile(png):
        raise FileNotFoundError(f'ERROR: PNG image not found - {png}')

    output_folder = os.path.join(parent_directory, 'JPG_img')
    os.makedirs(output_folder, exist_ok=True)

    base_name = os.path.splitext(os.path.basename(png))[0]
    jpg_img = os.path.join(output_folder, base_name + '.jpg')

    with Image.open(png) as img:
        rgb_img = img.convert('RGB')
        rgb_img.save(jpg_img, 'JPEG', quality=quality)
    return f'Successfully converted {png} to {jpg_img}\n'


def mask(src, message):
    if src.lower().endswith('.png'): # Checks if the cover image is PNG, must be JPG
        return """ERROR: Image is in PNG but needs to be in JPG format, use command '2jpg' for conversion"""

    try:
        # Encrypts the message
        encrypted_message = enc.encrypt(message)

        # If encryption fails, returns an error message
        if isinstance(encrypted_message, str):
            return encrypted_message

        base64_message = base64.b64encode(encrypted_message).decode('utf-8')

        # Add a 4-byte (32-bit) length prefix
        length_header = struct.pack(">I", len(base64_message))
        full_payload = length_header + base64_message.encode()

        # Converts encrypted message into list of binary digits
        bin_message = []
        for byte in full_payload:
            bin_message.extend(format(byte, '08b'))

         # Number of pixels needed to store the message in binary
        req_pixels = len(bin_message) // 3

        # Opens image and converts into array of pixel values
        img = Image.open(src)
        width, height = img.size
        array = np.array(img)

        # Checks if message can fit in the image
        total_pixels = array.size // 3
        if req_pixels > total_pixels:
            return 'ERROR: Message is too large for the image\n'
        else: # Embeds binary message by modifying LSB of image's pixels
            index = 0
            for p in range(height):
                for q in range(width):
                    for channel in range(3):
                        if index < len(bin_message):
                            array[p][q][channel] = (array[p][q][channel] & ~1) | int(bin_message[index])
                            index += 1

        # Defines the output folder and file name for new stego image
        output_folder = os.path.join(enc.desktop, 'LSB_img')
        output_file = os.path.join(output_folder, 'lsb_img.png')

        # Creates the folder if it doesn't exist
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        # Reconverts the modified array to an image and saves it
        stego_img = Image.fromarray(array)
        stego_img.save(output_file)
    
        return """Image encoded and saved as lsb_img.png in the 'LSB_img' folder on your desktop"""
    except Exception as e:
        return f'ERROR: {str(e)}'


def unmask(src):
    try:
        # Opens the stego image and converts to array
        img = Image.open(src).convert('RGB')
        array = np.array(img)
        
        length_bits = []
        bit_count = 0

        for p in range(array.shape[0]):
            for q in range(array.shape[1]):
                for channel in range(array.shape[2]):
                        length_bits.append(array[p][q][channel] & 1)
                        bit_count += 1
                        if bit_count == 32:
                            break
                if bit_count == 32:
                    break
            if bit_count == 32:
                break

        # Converts the bits into bytes
        length_bytes = bytes(int(''.join(map(str, length_bits[i:i+8])), 2) for i in range(0, 32, 8))
        msg_length = struct.unpack(">I", length_bytes)[0]  # base64 string length

        # Step 2: Extract next msg_length * 8 bits
        message_bits = []
        bit_count = 0
        total_bits = msg_length * 8
        collected = 0
        for p in range(array.shape[0]):
            for q in range(array.shape[1]):
                for channel in range(array.shape[2]):
                    # Skip first 32 bits (already extracted)
                    if collected < 32:
                        collected += 1
                        continue
                    if bit_count < total_bits:
                        message_bits.append(array[p][q][channel] & 1)
                        bit_count += 1
                    else:
                        break
                if bit_count >= total_bits:
                    break
            if bit_count >= total_bits:
                break

        # Convert bits to bytes
        message_bytes = bytes(int(''.join(map(str, message_bits[i:i+8])), 2) for i in range(0, total_bits, 8))

        # Convert to string and decode
        base64_str = message_bytes.decode('utf-8')
        decrypted_message = enc.decrypt(base64_str)

        if isinstance(decrypted_message, str):
            return decrypted_message

        return 'Secret message: ' + decrypted_message
    
    except FileNotFoundError:
        return 'ERROR: Image file not found. Ensure the file path is correct'
    except ValueError as e:
        if 'Invalid padding bytes' in str(e):
            return 'ERROR: No valid hidden message found\n'
        else:
            return f'ERROR: {str(e)}\n'
    except Exception as e:
        return f'ERROR: An error occurred - {str(e)}\n'