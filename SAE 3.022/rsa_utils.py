# rsa_utils.py
import random
import sympy
import base64

# ---------------------------
# Outils RSA (sans crypto lib)
# ---------------------------

def generate_prime(bits=64):
    # bits=256 => n ~ 512 bits (ok pour demo)
    while True:
        n = random.getrandbits(bits)
        n |= 1
        n |= (1 << (bits - 1))
        if sympy.isprime(n):
            return n

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Pas d'inverse modulaire")
    return x % m

def generate_rsa_key(bits=256):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while True:
        try:
            d = modinv(e, phi)
            break
        except:
            p = generate_prime(bits)
            q = generate_prime(bits)
            n = p * q
            phi = (p - 1) * (q - 1)

    return n, e, d

def rsa_encrypt_int(pub_n, pub_e, m_int):
    return pow(m_int, pub_e, pub_n)

def rsa_decrypt_int(priv_n, priv_d, c_int):
    return pow(c_int, priv_d, priv_n)

# ---------------------------
# XOR "symétrique" simple
# ---------------------------

def xor_bytes(data, key):
    out = bytearray(len(data))
    klen = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % klen]
    return bytes(out)

# ---------------------------
# conversions / base64
# ---------------------------

def bytes_to_int(b):
    return int.from_bytes(b, "big")

def int_to_bytes_fixed(x, size):
    return x.to_bytes(size, "big")

def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s.encode())
