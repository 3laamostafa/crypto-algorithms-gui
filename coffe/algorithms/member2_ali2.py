# ============================================================================
# algorithms/member2_ali2.py  -  Ali 2 (Member 2)
# ============================================================================
# Algorithms:
#   1. Hill Cipher (2x2 Matrix Polygraphic Cipher)
#   2. Playfair Cipher (5x5 Key Matrix Digraph Cipher)
# ============================================================================

import re
from math import gcd
from numpy import array, dot
from sympy import Matrix


# ==================== 1. HILL CIPHER ====================

def char_to_num(c):
    return ord(c.upper()) - ord('A')


def num_to_char(n):
    return chr((int(n) % 26) + ord('A'))


def _parse_hill_key(key):
    """
    Parses key into a 2x2 numpy array.
    Accepts:
      - numpy array or list of lists
      - 4 comma/space separated numbers: "3, 3, 2, 5" or "3 3 2 5"
      - 4-letter string: "DDCF" (A=0..Z=25)
    """
    if isinstance(key, (list, tuple)):
        if len(key) == 2 and len(key[0]) == 2:
            mat = [[int(key[0][0]), int(key[0][1])], [int(key[1][0]), int(key[1][1])]]
            return array(mat)
        elif len(key) == 4:
            return array([[int(key[0]), int(key[1])], [int(key[2]), int(key[3])]])

    if hasattr(key, 'shape') and key.shape == (2, 2):
        return key

    key_str = str(key).strip()

    # Check if numbers separated by commas/spaces
    nums = re.findall(r'-?\d+', key_str)
    if len(nums) == 4:
        return array([[int(nums[0]), int(nums[1])], [int(nums[2]), int(nums[3])]])

    # Check if 4 letters
    letters = [c.upper() for c in key_str if c.isalpha()]
    if len(letters) == 4:
        return array([
            [char_to_num(letters[0]), char_to_num(letters[1])],
            [char_to_num(letters[2]), char_to_num(letters[3])]
        ])

    raise ValueError(
        "Hill Key must be a 2x2 matrix! Enter 4 numbers (e.g. '3, 3, 2, 5') "
        "or 4 letters (e.g. 'DDCF')."
    )


def hill_encrypt(plaintext, key):
    """Encrypt plaintext using Hill Cipher with 2x2 matrix."""
    key_matrix = _parse_hill_key(key)

    # Check determinant invertibility mod 26
    det = int(Matrix(key_matrix).det()) % 26
    if gcd(det, 26) != 1:
        raise ValueError(
            f"Hill Key matrix is not invertible mod 26! Determinant = {det}, "
            f"gcd({det}, 26) = {gcd(det, 26)} != 1. Choose a matrix with det coprime to 26."
        )

    clean_text = "".join(c.upper() for c in plaintext if c.isalpha())
    if not clean_text:
        return ""

    if len(clean_text) % 2 != 0:
        clean_text += "X"

    ciphertext = ""
    for i in range(0, len(clean_text), 2):
        block = [char_to_num(c) for c in clean_text[i:i + 2]]
        block = array(block)
        encrypted = dot(key_matrix, block) % 26
        ciphertext += "".join(num_to_char(n) for n in encrypted)
    return ciphertext


def hill_decrypt(ciphertext, key):
    """Decrypt ciphertext using Hill Cipher with 2x2 matrix."""
    key_matrix = _parse_hill_key(key)

    det = int(Matrix(key_matrix).det()) % 26
    if gcd(det, 26) != 1:
        raise ValueError(
            f"Hill Key matrix is not invertible mod 26! Determinant = {det}, "
            f"gcd({det}, 26) = {gcd(det, 26)} != 1."
        )

    try:
        inv_key = array(Matrix(key_matrix).inv_mod(26))
    except Exception as exc:
        raise ValueError(f"Could not invert Hill Key matrix mod 26: {exc}")

    clean_text = "".join(c.upper() for c in ciphertext if c.isalpha())
    if not clean_text:
        return ""
    if len(clean_text) % 2 != 0:
        raise ValueError("Hill Ciphertext length must be even (blocks of 2)!")

    plaintext = ""
    for i in range(0, len(clean_text), 2):
        block = [char_to_num(c) for c in clean_text[i:i + 2]]
        block = array(block)
        decrypted = dot(inv_key, block) % 26
        plaintext += "".join(num_to_char(n) for n in decrypted)
    return plaintext


# ==================== 2. PLAYFAIR CIPHER ====================

def generate_key_matrix(key):
    """Generate 5x5 key matrix for Playfair Cipher (J merged with I)."""
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()
    for char in key:
        if char.isalpha() and char not in used:
            matrix.append(char)
            used.add(char)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used:
            matrix.append(char)
            used.add(char)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    """Prepare plaintext into digraphs with 'X' padding."""
    text = "".join(c.upper() for c in text if c.isalpha()).replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                pairs.append(a + "X")
                i += 1
            else:
                pairs.append(a + b)
                i += 2
        else:
            pairs.append(a + "X")
            i += 1
    return pairs


def find_position(matrix, char):
    """Find row and column of character in 5x5 matrix."""
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None


def encrypt_pairs(a, b, matrix):
    row1, col1 = find_position(matrix, a)
    row2, col2 = find_position(matrix, b)
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]


def decrypt_pairs(a, b, matrix):
    row1, col1 = find_position(matrix, a)
    row2, col2 = find_position(matrix, b)
    if row1 == row2:
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    elif col1 == col2:
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(plaintext, key):
    """Encrypt plaintext using Playfair Cipher."""
    if not key:
        raise ValueError("Playfair key cannot be empty!")
    matrix = generate_key_matrix(key)
    pairs = prepare_text(plaintext)
    if not pairs:
        return ""
    ciphertext = "".join(encrypt_pairs(a, b, matrix) for a, b in pairs)
    return ciphertext


def playfair_decrypt(ciphertext, key):
    """Decrypt ciphertext using Playfair Cipher."""
    if not key:
        raise ValueError("Playfair key cannot be empty!")
    matrix = generate_key_matrix(key)
    clean_text = "".join(c.upper() for c in ciphertext if c.isalpha()).replace("J", "I")
    if len(clean_text) % 2 != 0:
        raise ValueError("Playfair ciphertext length must be even!")
    pairs = [clean_text[i:i + 2] for i in range(0, len(clean_text), 2)]
    plaintext = "".join(decrypt_pairs(a, b, matrix) for a, b in pairs)
    return plaintext