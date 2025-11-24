# Anamorphic Encryption - ElGamal Scheme
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from char_int_elgamal import encode_msg_to_int, decode_msg_to_int
import secrets
import math


# ======== HELPER FUNCTIONS ======== #


# Pseudo-random function
def F(sk_a, IV, st, q):
    prg_input = st.to_bytes(16, 'little')  # AES block size = 16 bytes
    iv_bytes = IV.to_bytes(16, 'little')
    
    aes = AES.new(sk_a, AES.MODE_CBC, iv=iv_bytes)
    encrypted = aes.encrypt(prg_input)
    
    r_prime = (int.from_bytes(encrypted, 'little') % (q - 1)) + 1
    return r_prime

def g_generator(p):
    while True:
        h = secrets.randbelow(p-3) + 2
        g = pow(h, 2, p)
        if g != 1:
            return g


# ======== KEY GENERATION ======== #


# Standard public/private + double key generation
def create_keys(p, q, g):
    sk_a = get_random_bytes(16) # double key
    sk = secrets.randbelow(q) # secret key
    pk = pow(g, sk, p) # public key
    return pk, sk, sk_a


# ======== ANAMORPHIC ENCRYPTION ======== #


def aEncrypt(p, q, g, m, m_a, pk, sk_a, IV, st):
    # Generate pseudo-random r' to compute r
    r_prime = F(sk_a, IV, st, q)
    r = (r_prime + m_a) % q

    # Calculate ElGamal ciphertext
    pk_r = pow(pk, r, p)
    ct0 = (m * pk_r) % p
    ct1 = pow(g, r, p)
    ct = (ct0, ct1)

    # Increment state for next message
    st += 1

    return ct, st


def baby_step_giant_step(p, g, h, bound):
    if h == 1:
        return 0  # g^0 == 1
    
    # limit bound to at least 1
    if bound <= 1:
        return None

    # n = ceil(sqrt(q))
    n = math.isqrt(bound)
    if n * n < bound:
        n += 1

    # Baby steps: store g^j -> j for j in [0, n-1]
    baby = {}
    cur = 1
    for j in range(n):
        # If collision, keep the smallest j
        if cur not in baby:
            baby[cur] = j
        cur = (cur * g) % p

    # Compute g^n and its modular inverse modulo p
    g_n = pow(g, n, p)
    # modular inverse of g_n modulo p
    g_n_inv = pow(g_n, p - 2, p)

    # giant steps: i from 0..ceil(bound/n)-1
    gamma = h
    max_i = (bound + n - 1) // n  # ceiling(bound / n)
    for i in range(max_i):
        if gamma in baby:
            j = baby[gamma]
            x = i * n + j
            if x < bound:
                return x
            else:
                return None
        gamma = (gamma * g_n_inv) % p

    return None


# Anamorphic decryption
def aDecrypt(p, g, sk_a, ct, IV, st, q, bound):
    r_prime = F(sk_a, IV, st, q)

    # compute inverse of g^r_prime
    g_rprime = pow(g, r_prime, p)
    g_rprime_inv = pow(g_rprime, p - 2, p)
    g_m_a = (ct[1] * g_rprime_inv) % p

    m_a = baby_step_giant_step(p, g, g_m_a, bound)
    return m_a


# Standard decryption
def Decrypt(p, ct, sk):
    s = pow(ct[1], sk, p) # s = g^r^x = y^r
    s_inverse = pow(s, -1, p)
    cover_msg = (ct[0] * s_inverse) % p
    return cover_msg


# ===== Parameter initialization ===== #

p = 25283138329189278652587895589109525736072750946542698825287111445816073512149787631506175333955884685211183346377467560941062660497423325529940869143458703 
q = 12641569164594639326293947794554762868036375473271349412643555722908036756074893815753087666977942342605591673188733780470531330248711662764970434571729351
g = g_generator(p)

pk, sk, sk_a = create_keys(p, q, g)

st = 0
IV = 0

bound = 2**36