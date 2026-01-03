# Custom Character - Integer Mapping
# Covers all uppercase, lowercase, space and some punctuations
char_to_int = {
    'A': 1,  'B': 2,  'C': 3,  'D': 4,  'E': 5,  'F': 6,  'G': 7,  'H': 8,  'I': 9,  'J': 10,
    'K': 11, 'L': 12, 'M': 13, 'N': 14, 'O': 15, 'P': 16, 'Q': 17, 'R': 18, 'S': 19, 'T': 20,
    'U': 21, 'V': 22, 'W': 23, 'X': 24, 'Y': 25, 'Z': 26,
    'a': 27, 'b': 28, 'c': 29, 'd': 30, 'e': 31, 'f': 32, 'g': 33, 'h': 34, 'i': 35, 'j': 36,
    'k': 37, 'l': 38, 'm': 39, 'n': 40, 'o': 41, 'p': 42, 'q': 43, 'r': 44, 's': 45, 't': 46,
    'u': 47, 'v': 48, 'w': 49, 'x': 50, 'y': 51, 'z': 52, 
    ' ': 53, '.': 54, '?': 55, '!': 56, "'": 57, ',': 58,
    '0': 59, '1': 60, '2': 61, '3': 62, '4': 63, '5': 64, '6': 65, '7': 66, '9': 67, '5': 68
}

# Reverse mapping: integer back to character
int_to_char = {v: k for k, v in char_to_int.items()}

# Encode string into single integer using base-68 representation
def encode_msg_to_int(msg: str):
    base = 68
    total = 0
    for char in msg:
        if char not in char_to_int:
            raise ValueError(f"ERROR: Invalid character during encoding - {char}")
        total = total * base + char_to_int[char]
    return total

# Decode integer back into string using base-68 representation
def decode_msg_to_int(encoded_int):
    base = 68
    msg_chars = []
    while encoded_int > 0:
        encoded_int, remainder = divmod(encoded_int, base)
        if remainder not in int_to_char:
            raise ValueError(f"ERROR: Invalid integer during decoding - {remainder}")
        msg_chars.append(int_to_char[remainder])
    return ''.join(reversed(msg_chars))