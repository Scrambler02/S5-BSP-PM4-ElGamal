# Image Steganography - DCT Scheme
import os # Handles files and directory operations
import base64 # Used to encode and decode data in Base64
import numpy as np # Used to work with data in images
from PIL import Image # Helps open, edit and save images
from scipy.fftpack import dct # Accesses DCT conversion operation
import struct

import crypt_code.encryption as enc # Accesses the encryption and decryption functions

"""
This code contains the DCT steganography functions in Pixel Mask 3.0:
    - mask(): hides a message in an image using DCT steganography
    - unmask(): extracts a message from a NumPy file using DCT steganography
Side note: It embeds and extracts variable length messages now
"""

def mask(src, message):
    try:
        # Encrypts the message using the encrypt function
        encrypted_message = enc.encrypt(message)
        if isinstance(encrypted_message, str):
            return encrypted_message
        
        # Add a 4-byte (32-bit) length prefix
        base64_message = base64.b64encode(encrypted_message).decode('utf-8')
        length_header = struct.pack(">I", len(base64_message))
        full_payload = length_header + base64_message.encode()

        # Converts encrypted message (from bytes) to binary
        bin_message = []
        for byte in full_payload:
            bin_message.extend(format(byte, '08b')) # Each byte converted to 8 bit binary form

        # Opens the image and convert it to grayscale
        img = Image.open(src).convert('L')
        img_array = np.array(img, dtype=np.float32)  # Convertes image to NumPy array for processing

        # Executes DCT on the image array, for both rows and columns
        dct_output = dct(dct(dct(dct(img_array.T, norm='ortho').T, norm='ortho').T, type=3, norm='ortho').T, type=3, norm='ortho')

        # Rounds DCT coefficients and converts to integers for easier manipulation
        rounded_dct_output = np.round(dct_output, decimals=5).astype(np.int32)
        # Flattens the 2D DCT coefficients to 1D for same reason
        dct_flat = rounded_dct_output.flatten()
        
        # Embeds binary message by modifying LSB of DCT coefficients
        for i in range(len(bin_message)):
            coeff = dct_flat[i]  # Gets current DCT coefficient
            coeff = int(coeff)  # Converts to integer for bitwise operations
            coeff &= ~1  # Clears the LSB (sets it to 0)
            coeff |= int(bin_message[i])  # Alters the LSB to bit from binary message 
            dct_flat[i] = float(coeff) # Puts the modified coefficient back as a float

        # Reshapes modified DCT coefficients from 1D back to 2D array
        modified_dct = dct_flat.reshape(rounded_dct_output.shape)

        # Defines the path for the output folder and NumPy file
        output_folder = os.path.join(enc.desktop, 'DCT_file')
        output_file = os.path.join(output_folder, 'dct_file.npy')
        os.makedirs(output_folder) # Creates the folder

        # Saves the modified DCT coefficients as a NumPy file
        np.save(output_file, modified_dct)
        return """Image encoded and saved as dct_file.npy in the 'DCT_file' folder on your desktop"""
    except FileNotFoundError:
        return 'ERROR: Image not found. Ensure the file path is correct'
    except Exception as e:
        return f'ERROR: An error occured during dct masking - {str(e)}'


def unmask(src):
    try:
        # Loads the DCT coefficients from the NumPy file
        dct_coefficients = np.load(src)

        # Convert DCT coefficients to LSBs
        lsb_dct = (dct_coefficients.astype(int) & 1).astype(int)

        # Step 1: Extract first 32 bits for the base64 message length
        length_bits = []
        bit_count = 0

        for i in range(dct_coefficients.shape[0]):
            for j in range(dct_coefficients.shape[1]):
                length_bits.append(lsb_dct[i, j])
                bit_count += 1
                if bit_count == 32:
                    break
            if bit_count == 32:
                break

        # Convert bits to length (4 bytes, big-endian)
        length_bytes = bytes(int(''.join(map(str, length_bits[i:i+8])), 2) for i in range(0, 32, 8))
        msg_length = struct.unpack(">I", length_bytes)[0]  # base64 string length

        # Step 2: Extract next msg_length * 8 bits
        total_bits = msg_length * 8
        message_bits = []
        bit_count = 0
        collected = 0

        for i in range(dct_coefficients.shape[0]):
            for j in range(dct_coefficients.shape[1]):
                if collected < 32:
                    collected += 1
                    continue
                if bit_count < total_bits:
                    message_bits.append(lsb_dct[i, j])
                    bit_count += 1
                else:
                    break
            if bit_count >= total_bits:
                break

        # Convert message bits to bytes
        message_bytes = bytes(int(''.join(map(str, message_bits[i:i+8])), 2) for i in range(0, total_bits, 8))

        # Decode base64 string and decrypt
        base64_str = message_bytes.decode('utf-8')
        decrypted_message = enc.decrypt(base64_str)

        if isinstance(decrypted_message, str):
            return decrypted_message

        return 'Secret message: ' + decrypted_message

    except FileNotFoundError:
        return 'ERROR: DCT coefficients file not found. Ensure the file path is correct'
    except ValueError as e:
        if 'Invalid padding bytes' in str(e):
            return 'ERROR: No valid hidden message found'
        else:
            return f'ERROR: {str(e)}'
    except Exception as e:
        return f'ERROR: An error occurred - {str(e)}'