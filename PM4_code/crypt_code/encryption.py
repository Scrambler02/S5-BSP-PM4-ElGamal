# Cryptography Related Operations
import os # Handles files and directory operations
import base64 # Used to encode and decode data in Base64
from cryptography.hazmat.primitives import hashes # Provides hash functions
from cryptography.hazmat.backends import default_backend # Default cryptographic backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Used for encryption and decryption
from cryptography.hazmat.primitives import padding # Used for padding

"""
This code contains all cryptography related functions in Pixel Mask 3.0:
    - create_key(): generates the AES key and saves it to a specified folder (including desktop)
        Key is saved as 'key.txt' by default
    - load_key(): loads the key's contents from specified folder and passes it to the other functions
    - encrypt(): encrypts messages using the key, can be used on its own or in lsb/dct.mask(steganography.py)
    - decrypt(): decrypts messages using the key, can be used on its own or in lsb/dct.unmask(steganography.py)
"""

# Path to desktop directory, gets used as the default directory in the functions
desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
aes_key = None # Global variable that stores the AES key after it's been loaded


def create_key(secret_value, folder_name, parent_directory=desktop, filename='key.txt'):
    # If 'desktop' is entered as folder name, the desktop path is used
    if folder_name.lower() == 'desktop':
        directory = parent_directory
    else:
        directory = os.path.join(parent_directory, folder_name)

    # Creates the folder if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Generates the AES key, hashes the secret value with SHA-256 and uses only the first 16 bytes
    aes_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    aes_key.update(secret_value)
    aes_key = aes_key.finalize()[:16]
    
    # Creates the full path to store the key file
    file_path = os.path.join(directory, filename)
    
    # Writes the AES key into the file
    with open(file_path, 'wb') as f:
        f.write(aes_key)
    
    # Returns the key's file path
    return file_path


def load_key(key_file):
    global aes_key
    if key_file:
        with open(key_file, 'rb') as f:
            aes_key = f.read()
    else:
        raise FileNotFoundError(f'ERROR: Key file not loaded')
    

def load_ame_key(key_file):
    if key_file:
        with open(key_file, 'r') as f:
            ame_key = eval(f.read())
    else:
        raise FileNotFoundError(f'ERROR: Key file not loaded')
    return ame_key

    

def load_dkey(key_file):
    if key_file:
        with open(key_file, 'r') as f:
            ame_key = f.read()
    else:
        raise FileNotFoundError(f'ERROR: Key file not loaded')
    return ame_key


def encrypt(message):
    global aes_key
    if aes_key is None: # If key isn't found FileNotFoundError is raised
        raise FileNotFoundError('ERROR: No key loaded - Please load the key first')
    
    try:
        # Pads the message to be a multiple of the block size (AES block size is 128 bits = 16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        # Creates random 16-byte initialization vector
        iv = os.urandom(16) # Adds randomness to encryption

        # Creates the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypts the message
        ct = encryptor.update(padded_message) + encryptor.finalize()
        
        # Combines IV and ciphertext to create encrypted message
        encrypted_message = iv + ct

        return encrypted_message # Returns the encrypted message
    except Exception as e:
        return str(e) # Returns any error message
    

def decrypt(enc_message_base64):
    global aes_key
    if aes_key is None: # If key isn't found FileNotFoundError is raised
        raise FileNotFoundError('ERROR: No key loaded - Please load the key first')

    try:
        # Decodes the Base64 message
        dec_message_base64 = base64.b64decode(enc_message_base64)

        # Separates message into IV and ciphertext
        iv = dec_message_base64[:16]
        ct = dec_message_base64[16:]

        # Create AES cipher in CBC mode using the AES key
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypts the message
        decrypted_padded_message = decryptor.update(ct) + decryptor.finalize()

        # Removes padding from the decrypted message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

        # Returns the decrypted message
        return decrypted_message.decode('utf-8')
    except FileNotFoundError:
        return 'ERROR: Key file not found in the specified path\n'
    except ValueError as e: # Handles padding errors
        if 'Invalid padding bytes' in str(e):
            return 'ERROR: No valid hidden message found or invalid padding\n'
        else:
            return f'ERROR: {str(e)}'
    except Exception as e:
        return f'ERROR: An error occurred - {str(e)}\n'