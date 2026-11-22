# ============================================================================
# algorithms/member3_ali_ayman.py  -  Ali Ayman (Member 3)
# ============================================================================
#   1. Affine Cipher      (E(x) = (a*x + b) mod 26, requires gcd(a, 26) == 1)
#   2. DNA Encryption     (DNA-inspired bit-complement substitution)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

# ==================== SHARED HELPERS ====================

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _mod_inverse(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m} (not coprime).")
    return x % m


def _clean(text):
    return ''.join(ch.upper() for ch in text if ch.isalpha())


def _to_num(ch):
    return _ALPHABET.index(ch)


def _to_ch(n):
    return _ALPHABET[n % 26]


# ==================== AFFINE CIPHER ====================
# E(x) = (a * x + b) mod 26
# D(x) = a_inv * (x - b) mod 26
# Requires gcd(a, 26) == 1. Valid 'a': 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.


def affine_encrypt(plaintext, a, b):
    """Encrypt `plaintext` with Affine keys a, b."""
    a = int(a)
    b = int(b)
    if _gcd(a, 26) != 1:
        raise ValueError(
            f"Affine key a={a} is invalid: gcd({a}, 26) = {_gcd(a, 26)} != 1. "
            "Pick a coprime to 26 (e.g. 3, 5, 7, 11, 15, 17, 19, 23, 25)."
        )
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            result.append(chr(base + (a * i + b) % 26))  # E(x) = (ax + b) mod 26
        else:
            result.append(ch)
    return ''.join(result)


def affine_decrypt(ciphertext, a, b):
    """Decrypt `ciphertext` with Affine keys a, b."""
    a = int(a)
    b = int(b)
    if _gcd(a, 26) != 1:
        raise ValueError(
            f"Affine key a={a} is invalid: gcd({a}, 26) != 1."
        )
    a_inv = _mod_inverse(a, 26)  # a^-1 mod 26
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            # D(x) = a_inv * (x - b) mod 26
            result.append(chr(base + (a_inv * (i - b)) % 26))
        else:
            result.append(ch)
    return ''.join(result)


# ==================== DNA ENCRYPTION ====================
# DNA-inspired substitution built on the complementary base-pairing rule
# (A<->T, C<->G). Since 2^5 = 32 covers the 26-letter alphabet, each letter
# index is treated as a 5-bit value; every bit is flipped (the "DNA complement"),
# and the result is folded back into the 26-letter range.
#
# The complement map P(n) = (31 - n) % 26 is a bijection on 0..25 and is its own
# inverse (P(P(n)) == n), so encrypt then decrypt cleanly returns the original.
# A Vigenere-style key shift is mixed in so the supplied key affects output.
#
# E(i) = P((i + k) mod 26)     D(j) = (P(j) - k) mod 26


def _dna_complement(n):
    """5-bit DNA complement of letter index n (0..25). Self-inverse bijection."""
    return (31 - n) % 26


def dna_encrypt(plaintext, key):
    """Encrypt `plaintext` with DNA key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("DNA key must not be empty.")
    result = []
    key_len = len(key)
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            k = _to_num(key[ki % key_len])
            ki += 1
            mixed = (i + k) % 26            # mix in key letter
            n = _dna_complement(mixed)      # DNA complement (bit flip)
            result.append(chr(base + n))
        else:
            result.append(ch)
    return ''.join(result)


def dna_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with DNA key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("DNA key must not be empty.")
    result = []
    key_len = len(key)
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            mixed = _dna_complement(i)      # undo DNA complement (self-inverse)
            k = _to_num(key[ki % key_len])
            ki += 1
            original = (mixed - k) % 26     # undo key shift
            result.append(chr(base + original))
        else:
            result.append(ch)
    return ''.join(result)
