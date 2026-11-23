# ============================================================================
# algorithms/member5_omar.py  -  Omar (Member 5)
# ============================================================================
#   1. RSA              (asymmetric: E = m^e mod n, D = c^d mod n)
#   2. 14th Algorithm   (Atbash Cipher - A<->Z, B<->Y, ... a reflection cipher)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

import math

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


def _is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


# ==================== RSA ====================
# Key generation: pick two primes p, q. n = p*q, phi = (p-1)*(q-1).
# Choose e coprime to phi, compute d = e^-1 mod phi.
# Public key = (e, n), Private key = (d, n).
# E(c) = m^e mod n     D(m) = c^d mod n
#
# For classroom clarity we work with small primes and one character at a time
# (m = letter index). Real RSA uses padding and big integers.


def rsa_generate_keys(p, q):
    """Generate RSA keys from two primes p, q. Returns ((e,n),(d,n))."""
    p = int(p)
    q = int(q)
    if not (_is_prime(p) and _is_prime(q)):
        raise ValueError("RSA p and q must both be prime numbers.")
    if p == q:
        raise ValueError("RSA p and q must be distinct primes.")
    n = p * q
    phi = (p - 1) * (q - 1)
    # Pick the smallest valid e > 1.
    e = 3
    while e < phi and _gcd(e, phi) != 1:
        e += 2
    if e >= phi:
        raise ValueError("Could not find a valid public exponent e for these primes.")
    d = _mod_inverse(e, phi)
    return (e, n), (d, n)


def _rsa_char_encrypt(ch, e, n):
    m = _ALPHABET.index(ch.upper())
    return pow(m, e, n)


def _rsa_char_decrypt(val, d, n):
    m = pow(val, d, n)
    return _ALPHABET[m]


def rsa_encrypt(plaintext, public_key):
    """Encrypt `plaintext` with RSA public key (e, n). Returns space-separated ints."""
    e, n = public_key
    e = int(e)
    n = int(n)
    if not plaintext:
        return ""
    blocks = []
    for ch in plaintext:
        if ch.isalpha():
            blocks.append(str(_rsa_char_encrypt(ch, e, n)))
        else:
            blocks.append(ch)  # preserve spaces/punctuation as-is
    return ' '.join(blocks)


def rsa_decrypt(ciphertext, private_key):
    """Decrypt RSA `ciphertext` (space-separated ints) with private key (d, n)."""
    d, n = private_key
    d = int(d)
    n = int(n)
    if not ciphertext:
        return ""
    tokens = ciphertext.split()
    out = []
    for tok in tokens:
        if tok.isalpha() and len(tok) == 1:  # preserved non-letter char
            out.append(tok)
        else:
            try:
                val = int(tok)
            except ValueError:
                raise ValueError(f"RSA ciphertext contains invalid token: '{tok}'")
            out.append(_rsa_char_decrypt(val, d, n))
    return ''.join(out)


# ==================== 14TH ALGORITHM: ATBASH CIPHER ====================
# A classic reflection/mirror cipher: each letter maps to its mirror in the
# alphabet: A<->Z, B<->Y, C<->X, ... M<->N.
# E(x) = (25 - x) mod 26     D(x) = (25 - x) mod 26  (self-inverse)
# Encrypt and Decrypt are identical.


_ATBASH_MAP = {ch: _ALPHABET[25 - i] for i, ch in enumerate(_ALPHABET)}


def atbash_encrypt(plaintext, key=None):
    """Encrypt `plaintext` with Atbash. `key` is accepted for API compatibility
    but Atbash is keyless."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            upper = ch.upper()
            mapped = _ATBASH_MAP[upper]
            result.append(mapped if ch.isupper() else mapped.lower())
        else:
            result.append(ch)
    return ''.join(result)


def atbash_decrypt(ciphertext, key=None):
    """Decrypt `ciphertext` with Atbash (same as encrypt - it is self-inverse)."""
    return atbash_encrypt(ciphertext)
