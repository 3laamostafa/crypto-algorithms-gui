# ============================================================================
# algorithms/member2_ali2.py  -  Ali 2 (Member 2)
# ============================================================================
#   1. Hill Cipher        (matrix-based polygraphic substitution)
#   2. Playfair Cipher    (digraph substitution with a 5x5 key table)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

import math

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ==================== SHARED HELPERS ====================

def _clean(text):
    """Uppercase and keep only letters A-Z."""
    return ''.join(ch.upper() for ch in text if ch.isalpha())


def _to_num(ch):
    """A->0, B->1, ..., Z->25."""
    return _ALPHABET.index(ch)


def _to_ch(n):
    """0->A, 1->B, ..., 25->Z."""
    return _ALPHABET[n % 26]


# ==================== HILL CIPHER ====================
# Works on blocks of size N (here N = 2, using a 2x2 key matrix).
# E(C) = K * P mod 26     D(P) = K_inv * C mod 26
# Requires det(K) coprime to 26 so K has an inverse modulo 26.


def _hill_matrix_inv(key_matrix):
    """Inverse of a 2x2 matrix modulo 26."""
    a, b = key_matrix[0]
    c, d = key_matrix[1]
    det = a * d - b * c
    det_mod = det % 26
    if _gcd(det_mod, 26) != 1:
        raise ValueError(
            f"Hill key matrix determinant {det_mod} is not coprime to 26 "
            f"(gcd = {_gcd(det_mod, 26)}). Pick a key with det coprime to 26."
        )
    det_inv = _mod_inverse(det_mod, 26)
    # adjugate * det_inv mod 26
    return [
        [(d * det_inv) % 26, (-b * det_inv) % 26],
        [(-c * det_inv) % 26, (a * det_inv) % 26],
    ]


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
        raise ValueError(f"No modular inverse for {a} mod {m}.")
    return x % m


def _hill_parse_key(key):
    """Parse a 4-letter key into a 2x2 matrix of numbers 0..25."""
    clean = _clean(key)
    if len(clean) != 4:
        raise ValueError(
            "Hill key must be exactly 4 letters (a 2x2 matrix), "
            f"got {len(clean)} letter(s): '{key}'."
        )
    return [
        [_to_num(clean[0]), _to_num(clean[1])],
        [_to_num(clean[2]), _to_num(clean[3])],
    ]


def hill_encrypt(plaintext, key):
    """Encrypt `plaintext` with Hill 2x2 key `key` (4 letters)."""
    matrix = _hill_parse_key(key)
    clean = _clean(plaintext)
    if not clean:
        return ""

    # Pad with 'X' so length is even.
    if len(clean) % 2 == 1:
        clean += 'X'

    out = []
    for i in range(0, len(clean), 2):
        p1 = _to_num(clean[i])
        p2 = _to_num(clean[i + 1])
        # C1 = a*p1 + b*p2  (mod 26)
        c1 = (matrix[0][0] * p1 + matrix[0][1] * p2) % 26
        # C2 = c*p1 + d*p2  (mod 26)
        c2 = (matrix[1][0] * p1 + matrix[1][1] * p2) % 26
        out.append(_to_ch(c1))
        out.append(_to_ch(c2))
    return ''.join(out)


def hill_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Hill 2x2 key `key` (4 letters)."""
    matrix = _hill_parse_key(key)
    inv = _hill_matrix_inv(matrix)
    clean = _clean(ciphertext)
    if not clean:
        return ""
    if len(clean) % 2 == 1:
        raise ValueError("Hill ciphertext length must be even.")

    out = []
    for i in range(0, len(clean), 2):
        c1 = _to_num(clean[i])
        c2 = _to_num(clean[i + 1])
        # P1 = inv00*c1 + inv01*c2  (mod 26)
        p1 = (inv[0][0] * c1 + inv[0][1] * c2) % 26
        # P2 = inv10*c1 + inv11*c2  (mod 26)
        p2 = (inv[1][0] * c1 + inv[1][1] * c2) % 26
        out.append(_to_ch(p1))
        out.append(_to_ch(p2))
    return ''.join(out)


# ==================== PLAYFAIR CIPHER ====================
# Builds a 5x5 table from the key (J merged with I).
# Rules:
#   - Same row:  replace each letter with the one to its right (wrap).
#   - Same col:  replace each letter with the one below (wrap).
#   - Rectangle: replace each letter with the one on its own row but
#                in the other letter's column.


def _playfair_build_table(key):
    """Build the 5x5 Playfair table from `key` (J merged into I)."""
    clean = _clean(key).replace('J', 'I')
    seen = []
    for ch in clean:
        if ch not in seen:
            seen.append(ch)
    for ch in _ALPHABET:
        if ch == 'J':
            continue
        if ch not in seen:
            seen.append(ch)
    # 5x5 grid
    return [seen[i:i + 5] for i in range(0, 25, 5)]


def _playfair_find(table, ch):
    """Return (row, col) of `ch` in the Playfair table."""
    for r, row in enumerate(table):
        if ch in row:
            return r, row.index(ch)
    raise ValueError(f"Character '{ch}' not found in Playfair table.")


def _playfair_prepare(plaintext):
    """Split into digraphs, insert X between doubles, pad odd length with X."""
    clean = _clean(plaintext).replace('J', 'I')
    digraphs = []
    i = 0
    while i < len(clean):
        a = clean[i]
        b = clean[i + 1] if i + 1 < len(clean) else None
        if b is None:
            digraphs.append(a + 'X')
            i += 1
        elif a == b:
            digraphs.append(a + 'X')
            i += 1          # keep b for next pair
        else:
            digraphs.append(a + b)
            i += 2
    return digraphs


def playfair_encrypt(plaintext, key):
    """Encrypt `plaintext` with Playfair key `key`."""
    table = _playfair_build_table(key)
    out = []
    for a, b in _playfair_prepare(plaintext):
        ra, ca = _playfair_find(table, a)
        rb, cb = _playfair_find(table, b)
        if ra == rb:                       # same row -> shift right
            out.append(table[ra][(ca + 1) % 5])
            out.append(table[rb][(cb + 1) % 5])
        elif ca == cb:                     # same col -> shift down
            out.append(table[(ra + 1) % 5][ca])
            out.append(table[(rb + 1) % 5][cb])
        else:                              # rectangle -> column swap
            out.append(table[ra][cb])
            out.append(table[rb][ca])
    return ''.join(out)


def playfair_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Playfair key `key`."""
    table = _playfair_build_table(key)
    clean = _clean(ciphertext).replace('J', 'I')
    if len(clean) % 2 == 1:
        raise ValueError("Playfair ciphertext length must be even.")
    out = []
    for i in range(0, len(clean), 2):
        a, b = clean[i], clean[i + 1]
        ra, ca = _playfair_find(table, a)
        rb, cb = _playfair_find(table, b)
        if ra == rb:                       # same row -> shift left
            out.append(table[ra][(ca - 1) % 5])
            out.append(table[rb][(cb - 1) % 5])
        elif ca == cb:                     # same col -> shift up
            out.append(table[(ra - 1) % 5][ca])
            out.append(table[(rb - 1) % 5][cb])
        else:                              # rectangle -> column swap
            out.append(table[ra][cb])
            out.append(table[rb][ca])
    return ''.join(out)
