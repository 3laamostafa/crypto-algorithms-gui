# ============================================================================
# algorithms/member3_ali_ayman.py  -  Ali Ayman (Member 3)
# ============================================================================
# Algorithms:
#   1. Affine Cipher (E(x) = (a*x + b) mod 26, D(x) = a^-1*(x - b) mod 26)
#   2. DNA Encryption (Text -> Bits -> XOR with Key Bits -> DNA Nucleotides A,T,C,G)
# ============================================================================

from math import gcd


# ==================== 1. AFFINE CIPHER ====================

def _mod_inverse(k, m=26):
    """Modular multiplicative inverse using brute force / Euclid."""
    if gcd(k, m) != 1:
        return None
    for x in range(1, m):
        if (k * x) % m == 1:
            return x
    return None


def affine_encrypt(text, a, b):
    """Encrypt text using Affine Cipher with multiplier a and shift b."""
    a = int(a)
    b = int(b)
    if gcd(a, 26) != 1:
        raise ValueError(
            f"Key 'a' ({a}) is invalid! gcd({a}, 26) = {gcd(a, 26)} != 1.\n"
            "'a' must be coprime to 26 (valid 'a': 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)."
        )
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (a * position + b) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


def affine_decrypt(text, a, b):
    """Decrypt text using Affine Cipher with multiplier a and shift b."""
    a = int(a)
    b = int(b)
    x = _mod_inverse(a, 26)
    if x is None:
        raise ValueError(
            f"Key 'a' ({a}) has no modular inverse mod 26! gcd({a}, 26) != 1.\n"
            "'a' must be coprime to 26."
        )
    cipher_list = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            position = ord(char) - base
            c = (x * (position - b)) % 26
            new_char = chr(c + base)
            cipher_list.append(new_char)
        else:
            cipher_list.append(char)
    return "".join(cipher_list)


# ==================== 2. DNA ENCRYPTION ====================
# Mapping from doctor's lecture / notebook:
# A = '00', T = '01', C = '10', G = '11'

DNA_MAP = {
    'A': '00',
    'T': '01',
    'C': '10',
    'G': '11'
}

REVERSE_DNA_MAP = {v: k for k, v in DNA_MAP.items()}


def text_to_bits(text):
    """Convert text to 8-bit binary string."""
    if any(ord(ch) > 255 for ch in text):
        raise ValueError("DNA Encryption supports only ASCII / Latin-1 characters (8 bits per character).")
    return ''.join(format(ord(ch), '08b') for ch in text)


def bits_to_text(bits):
    """Convert 8-bit binary chunks back to ASCII text."""
    chars = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)


def xor_bits(bits1, bits2):
    """Bitwise XOR between two equal-length bit strings."""
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(bits1, bits2))


def bits_to_dna(bits):
    """Convert 2-bit pairs to DNA nucleotides (A, T, C, G)."""
    # Pad with '0' if odd number of bits
    if len(bits) % 2 != 0:
        bits += '0'
    return ''.join(REVERSE_DNA_MAP[bits[i:i + 2]] for i in range(0, len(bits), 2))


def dna_to_bits(dna):
    """Convert DNA nucleotides (A, T, C, G) back to bit string."""
    clean_dna = dna.upper().replace(" ", "").replace("\n", "")
    for ch in clean_dna:
        if ch not in DNA_MAP:
            raise ValueError(f"Invalid DNA base '{ch}'! DNA ciphertext can only contain A, T, C, G.")
    return ''.join(DNA_MAP[ch] for ch in clean_dna)


def dna_encrypt(message, key):
    """
    Encrypt plaintext into DNA ciphertext:
      1. Convert message and key to 8-bit binary strings.
      2. Repeat/trim key bits to match message length.
      3. XOR message bits with key bits.
      4. Map 2-bit pairs into DNA bases (A, T, C, G).
    """
    if not message:
        return ""
    if not key:
        raise ValueError("DNA Encryption requires a non-empty key!")

    msg_bits = text_to_bits(message)
    key_bits = text_to_bits(key)

    # Repeat or trim key bits to match message bit length
    key_bits = (key_bits * ((len(msg_bits) // len(key_bits)) + 1))[:len(msg_bits)]

    # XOR
    cipher_bits = xor_bits(msg_bits, key_bits)

    # Convert to DNA sequence
    encrypted_dna = bits_to_dna(cipher_bits)
    return encrypted_dna


def dna_decrypt(dna_ciphertext, key):
    """
    Decrypt DNA ciphertext back to plaintext:
      1. Convert DNA sequence (A, T, C, G) back to bit string.
      2. Repeat/trim key bits to match DNA bits length.
      3. XOR cipher bits with key bits.
      4. Convert recovered bits back to ASCII text.
    """
    if not dna_ciphertext:
        return ""
    if not key:
        raise ValueError("DNA Decryption requires a non-empty key!")

    cipher_bits_back = dna_to_bits(dna_ciphertext)
    key_bits = text_to_bits(key)
    key_bits = (key_bits * ((len(cipher_bits_back) // len(key_bits)) + 1))[:len(cipher_bits_back)]

    decrypted_bits = xor_bits(cipher_bits_back, key_bits)
    decrypted_text = bits_to_text(decrypted_bits)
    return decrypted_text