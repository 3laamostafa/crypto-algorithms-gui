# ============================================================================
# algorithms/member1_alaa.py  -  Alaa (Member 1)
# ============================================================================
# Algorithms:
#   1. Caesar Cipher
#   2. Multiplicative Cipher
#   3. Vernam Cipher (Character-based XOR / One-Time Pad)
# ============================================================================

from math import gcd


def _mod_inverse(k, m=26):
    """Calculate modular multiplicative inverse of k mod m."""
    if gcd(k, m) != 1:
        return None
    for x in range(1, m):
        if (k * x) % m == 1:
            return x
    return None


# ==================== 1. CAESAR CIPHER ====================
# Formula:
# Encryption: C = (P + shift) mod 26
# Decryption: P = (C - shift) mod 26

def caesar_encrypt(text, shift):
    """Encrypt text using Caesar Cipher."""
    shift = int(shift)
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (position + shift) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


def caesar_decrypt(text, shift):
    """Decrypt text using Caesar Cipher."""
    shift = int(shift)
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (position - shift) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


# ==================== 2. MULTIPLICATIVE CIPHER ====================
# Formula:
# Encryption: C = (P * key) mod 26
# Decryption: P = (C * key^-1) mod 26
# Condition: gcd(key, 26) == 1

def multiplicative_encrypt(text, key):
    """Encrypt text using Multiplicative Cipher."""
    key = int(key)
    if gcd(key, 26) != 1:
        raise ValueError(
            f"Key '{key}' is invalid! gcd({key}, 26) = {gcd(key, 26)} != 1.\n"
            "Key must be coprime to 26 (valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)."
        )
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (position * key) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


def multiplicative_decrypt(text, key):
    """Decrypt text using Multiplicative Cipher."""
    key = int(key)
    x = _mod_inverse(key, 26)
    if x is None:
        raise ValueError(
            f"Key '{key}' has no modular inverse mod 26! gcd({key}, 26) != 1.\n"
            "Key must be coprime to 26 (e.g., 3, 5, 7, 11, 15, 17, 19, 23, 25)."
        )
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (position * x) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


# ==================== 3. VERNAM CIPHER ====================
# Formula (lecture): C_i = (P_i XOR K_i) + 'A'   where P_i, K_i are 0..25 (5-bit values)
# The XOR of two 5-bit values can reach 31, so a ciphertext symbol is one of
# A-Z or  [ \ ] ^ _ `  (values 26..31).  Using "mod 26" here would make some
# letters impossible to decrypt, so no modulo is applied.

_VERNAM_SYMBOLS = "[\\]^_`"


def _vernam_key(key):
    if not key:
        raise ValueError("Vernam key cannot be empty!")
    key = ''.join(c.upper() for c in key if 'A' <= c.upper() <= 'Z')
    if not key:
        raise ValueError("Vernam key must contain at least one letter (A-Z)!")
    return key


def vernam_encrypt(plaintext, key):
    """Encrypt plaintext using Vernam Cipher with cyclic key."""
    key = _vernam_key(key)
    plaintext = plaintext.upper()
    if any(ch in _VERNAM_SYMBOLS for ch in plaintext):
        raise ValueError(
            "Plaintext contains one of the symbols  [ \\ ] ^ _ `  which are reserved "
            "for Vernam ciphertext. Please remove them."
        )

    cipher = []
    k_idx = 0
    for p in plaintext:
        if 'A' <= p <= 'Z':
            p_val = ord(p) - ord('A')
            k_val = ord(key[k_idx % len(key)]) - ord('A')
            cipher.append(chr((p_val ^ k_val) + ord('A')))
            k_idx += 1
        else:
            cipher.append(p)
    return "".join(cipher)


def vernam_decrypt(ciphertext, key):
    """Decrypt ciphertext using Vernam Cipher (XOR is self-inverse)."""
    key = _vernam_key(key)
    ciphertext = ciphertext.upper()

    plain = []
    k_idx = 0
    for c in ciphertext:
        if 'A' <= c <= 'Z' or c in _VERNAM_SYMBOLS:
            c_val = ord(c) - ord('A')
            k_val = ord(key[k_idx % len(key)]) - ord('A')
            plain.append(chr((c_val ^ k_val) + ord('A')))
            k_idx += 1
        else:
            plain.append(c)
    return "".join(plain)