# Anamorphic Encryption - XOR-RSA Scheme
import os
import struct
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

"""
This code provides anamorphic encryption with XOR and RSA:
    - aEncrypt(): hides two messages (cover + secret) in one ciphertext
    - aDecrypt(): reveals one message using the ciphertext + key
    - rsa_keys(): generates RSA public + private keys
    - wrap_key()/unwrap_key(): securely encrypts anamorphic keys with RSA
"""



# XOR two byte strings
def xor(a, b):
    if len(a) != len(b):
        raise ValueError('ERROR: Different lengths')
    # XOR each byte of a with each byte of b
    res = bytes(x ^ y for x, y in zip(a,b))
    return res

# Add the message length (4 bytes) before the message
def pack(msg):
    packed_msg = struct.pack('>I', len(msg)) + msg
    return packed_msg

# Read the message length first, then return the message
def unpack(bundle):
    if len(bundle) < 4:
        raise ValueError('ERROR: Too short')
    # Read the first 4 bytes -> they hold the message length value
    len_tuple = struct.unpack('>I', bundle[:4])
    len_msg = len_tuple[0]
    # Extract the message bytes using the length
    unpacked_msg = bundle[4:4 + len_msg]
    return unpacked_msg


# ======== ANAMORPHIC ENCRYPTION ======== #


# Encrypt two messages (cover + secret) using XOR keys
def aEncrypt(m1, m2):
    # pack both messages -> add length info in front
    b1 = pack(m1.encode())
    b2 = pack(m2.encode())

    # Make both messages the same length by padding with random bytes
    total_len = max(len(b1), len(b2))
    b1 += os.urandom(total_len - len(b1))
    b2 += os.urandom(total_len - len(b2))

    # Generate random key -> same length as messages
    k1 = os.urandom(total_len)
    ct = xor(b1, k1) # Ciphertext = first message XOR random key
    k2 = xor(ct, b2) # Second key = ciphertext XOR second message

    # Encode ciphertext in base64 -> easier to store/share
    ct_b64 = base64.b64encode(ct)

    return ct_b64, k1, k2

# Decrypt a message using ciphertext + key
def aDecrypt(ct_b64, key):
    # Decode base64 back to bytes
    ct = base64.b64decode(ct_b64)
    # Recover message using XOR with the right key
    msg = xor(ct, key)
    # Remove the message length value and decode back to string
    unpacked_msg = unpack(msg).decode()
    return unpacked_msg


# ======== RSA KEY GENERATION ======== #


# RSA public + private key generation
def rsa_keys():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048) # private key
    pk = sk.public_key() # public key
    return pk, sk


# ======== RSA WRAPPING ======== #


# OAEP with SHA-256 is a secure padding scheme for RSA
OAEP_SHA256 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

# Encrypt a key using RSA public key
def wrap_key(pk, ame_key):
    return pk.encrypt(ame_key, OAEP_SHA256)

# Decrypt a key using RSA private key
def unwrap_key(sk, wrapped_ame_key):
    return sk.decrypt(wrapped_ame_key, OAEP_SHA256)


# ======== TEST RUN ======== #


# if __name__ == '__main__':
#     m = 'Hello there!'
#     sm = 'We attack soon!'

#     ct_b64, k1, k2 = aEncrypt(m, sm)
#     ct_b642 = base64.b64decode(ct_b64)
#     print('Ciphertext: ', ct_b642)
#     print('Secret key: ', k1)
#     print('Double key: ', k2)

#     cover_msg = aDecrypt(ct_b64, k1)
#     print('Cover message: ', cover_msg)

#     pk, sk = rsa_keys()

#     wrapped_k2 = wrap_key(pk, k2)
#     print('Wrapped k2: ', wrapped_k2)

#     unwrapped_k2 = unwrap_key(sk, wrapped_k2)

#     secret_msg = aDecrypt(ct_b64, unwrapped_k2)
#     print('Secret message: ', secret_msg)