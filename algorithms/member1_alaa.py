# ============================================================================
# algorithms/member1_alaa.py  -  Alaa (Member 1)
# ============================================================================
# The 3 simplest algorithms:
#   1. Caesar Cipher
#   2. Multiplicative Cipher
#   3. Vernam Cipher (One-Time Pad)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

# ==================== SHARED HELPERS ====================

def _gcd(a, b):
    """Greatest common divisor (Euclid). Used to validate coprime keys."""
    while b:
        a, b = b, a % b
    return abs(a)


def _egcd(a, b):
    """Extended Euclidean Algorithm. Returns (g, x, y) with a*x + b*y = g."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _mod_inverse(a, m):
    """Modular multiplicative inverse of a modulo m. Requires gcd(a, m) == 1."""
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m} (they are not coprime).")
    return x % m


# ==================== CAESAR CIPHER ====================
# E(x) = (x + key) mod 26     D(x) = (x - key) mod 26
# Shifts every alphabetic character forward by `key` positions.
# Non-letters are passed through unchanged. Case is preserved.


def caesar_encrypt(plaintext, key):
    """Encrypt `plaintext` with a Caesar shift of `key`."""
    key = int(key)
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base                     # 0..25 position of letter
            result.append(chr(base + (i + key) % 26))  # shift forward, wrap around
        else:
            result.append(ch)                       # keep spaces/punctuation as-is
    return ''.join(result)


def caesar_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with a Caesar shift of `key` (shift backward)."""
    # Decryption is just encryption with the negative shift.
    return caesar_encrypt(ciphertext, -int(key))


# ==================== MULTIPLICATIVE CIPHER ====================
# E(x) = (key * x) mod 26     D(x) = (key_inv * x) mod 26
# Requires gcd(key, 26) == 1 so that a modular inverse exists.
# Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25


def multiplicative_encrypt(plaintext, key):
    """Encrypt `plaintext` with Multiplicative key `key`."""
    key = int(key)
    if _gcd(key, 26) != 1:
        raise ValueError(
            f"Multiplicative key {key} is invalid: gcd({key}, 26) = {_gcd(key, 26)} != 1. "
            "Pick a key coprime to 26 (e.g. 3, 5, 7, 11, 15, 17, 19, 23, 25)."
        )
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            result.append(chr(base + (key * i) % 26))  # multiply then wrap
        else:
            result.append(ch)
    return ''.join(result)


def multiplicative_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Multiplicative key `key`."""
    key = int(key)
    if _gcd(key, 26) != 1:
        raise ValueError(
            f"Multiplicative key {key} is invalid: gcd({key}, 26) != 1. "
            "Pick a key coprime to 26 (e.g. 3, 5, 7, 11, 15, 17, 19, 23, 25)."
        )
    inv = _mod_inverse(key, 26)          # key^-1 mod 26
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            result.append(chr(base + (inv * i) % 26))  # multiply by inverse
        else:
            result.append(ch)
    return ''.join(result)


# ==================== VERNAM CIPHER (One-Time Pad) ====================
# XOR each byte of the plaintext with the corresponding byte of the key
# (key repeats cyclically). Ciphertext is emitted as hex so it stays printable.
# Encrypt and Decrypt are identical operations (XOR is self-inverse).


def vernam_encrypt(plaintext, key):
    """Encrypt `plaintext` with Vernam key `key`. Returns hex ciphertext."""
    if not key:
        raise ValueError("Vernam key must not be empty.")
    key_bytes = key.encode('utf-8')
    plain_bytes = plaintext.encode('utf-8')
    out = bytearray()
    for i, b in enumerate(plain_bytes):
        out.append(b ^ key_bytes[i % len(key_bytes)])  # XOR with cycling key byte
    return out.hex()


def vernam_decrypt(ciphertext, key):
    """Decrypt Vernam hex `ciphertext` with key `key`. Returns plaintext."""
    if not key:
        raise ValueError("Vernam key must not be empty.")
    key_bytes = key.encode('utf-8')
    try:
        cipher_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        raise ValueError("Vernam ciphertext must be a valid hex string.")
    out = bytearray()
    for i, b in enumerate(cipher_bytes):
        out.append(b ^ key_bytes[i % len(key_bytes)])  # XOR again to recover plaintext
    return out.decode('utf-8')
