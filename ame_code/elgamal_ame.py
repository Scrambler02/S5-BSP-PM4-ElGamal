# Anamorphic Encryption - ElGamal Scheme
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .char_int_elgamal import encode_msg_to_int, decode_msg_to_int
from itertools import zip_longest
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
    
    # Limit bound to at least 1
    if bound <= 1:
        return None

    # Block size n ≈ sqrt(bound) for BSGS
    n = math.isqrt(bound)
    if n * n < bound:
        n += 1

    # Baby-steps: store g^j -> for all j in [0, n-1]
    baby = {}
    current = 1
    for j in range(n):
        # If collision, keep the smallest j
        if current not in baby:
            baby[current] = j
        current = (current * g) % p

    # Compute g^n
    g_n = pow(g, n, p)
    # Modular inverse of g_n modulo p
    g_n_inv = pow(g_n, p - 2, p)

    # Giant-steps: look for i, j s.t. x = i * n + j solves g^x = h
    gamma = h
    max_i = (bound + n - 1) // n  # Compute how many giant steps we need

    for i in range(max_i):
        # Check if current gamma matches any baby table value 
        if gamma in baby:
            j = baby[gamma]     # Retrieve corresponding baby-step exponent j
            x = i * n + j       # Reconstruct the full exponent x = i*n + j
            if x < bound:       # Only accept x if it is within the allowed bound
                return x
            else:
                return None
        # Move to next giant step -> multiply gamma by g^-n
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

st = 0
IV = 0

p = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007 
q = 89884656743115795385419578396893726598930148024378005853222211842098590108079259684473916897932462770751090282742990251823220274099619550025396438501677908319614776568119538254367879957411287431287503712651038723856294775478968889212221213308667363814649693834354602803025135405421453846466009564097233813503
g = g_generator(p)

pk, sk, sk_a = create_keys(p, q, g)

bound = 2**36

# ===== Message encryption test ===== #

def encode(m: str, m_a: str, pk, sk_a, IV, st):
    int_array = [encode_msg_to_int(word) for word in m.split()]
    a_int_array = [encode_msg_to_int(word_a) for word_a in m_a.split()]

    pairs = zip_longest(int_array, a_int_array, fillvalue=0)

    cts = []
    st_local = st
    for m_int, m_a_int in pairs:
        ct, st_local = aEncrypt(p, q, g, m_int, m_a_int, pk, sk_a, IV, st_local)
        cts.append(ct)

    return cts, st_local

def decode(cts, st_start, sk=None, sk_a=None, IV=None):
    decoded_cover = ""
    decoded_anam = ""
    st_local = st_start

    if sk != None:
        for ct in cts:
            m = Decrypt(p, ct, sk)
            decoded_cover += decode_msg_to_int(m) + " "
            st_local += 1
        return decoded_cover.strip()
    elif sk_a != None:
        for ct in cts:
            m_a = aDecrypt(p, g, sk_a, ct, IV, st_local, q, bound)
            decoded_anam += (decode_msg_to_int(m_a) if m_a is not None else "[?]") + " "
            st_local += 1
        return decoded_anam.strip()
    else:
        raise ValueError("ERROR: No key loaded")
