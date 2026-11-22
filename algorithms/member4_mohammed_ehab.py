# ============================================================================
# algorithms/member4_mohammed_ehab.py  -  Mohammed Ehab (Member 4)
# ============================================================================
#   1. Vigenere Cipher   (polyalphabetic: E(x) = (x + k_i) mod 26)
#   2. Autokey Cipher    (keystream = key letters then plaintext letters)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _clean(text):
    return ''.join(ch.upper() for ch in text if ch.isalpha())


def _to_num(ch):
    return _ALPHABET.index(ch)


def _to_ch(n):
    return _ALPHABET[n % 26]


# ==================== VIGENERE CIPHER ====================
# E(x_i) = (x_i + k_i) mod 26     D(y_i) = (y_i - k_i) mod 26
# The key repeats to cover the whole message. Non-letters are preserved.


def vigenere_encrypt(plaintext, key):
    """Encrypt `plaintext` with Vigenere key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one letter.")
    result = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            k = _to_num(key[ki % len(key)])
            ki += 1
            result.append(chr(base + (i + k) % 26))  # E = (x + k) mod 26
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Vigenere key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("Vigenere key must contain at least one letter.")
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            i = ord(ch) - base
            k = _to_num(key[ki % len(key)])
            ki += 1
            result.append(chr(base + (i - k) % 26))  # D = (y - k) mod 26
        else:
            result.append(ch)
    return ''.join(result)


# ==================== AUTOKEY CIPHER ====================
# The keystream = key letters followed by the plaintext letters (encryption)
# or key then recovered plaintext (decryption).
# E(x_i) = (x_i + k_i) mod 26     D(y_i) = (y_i - k_i) mod 26


def _autokey_keystream(key, n, plain_indices):
    """Build an Autokey keystream of length n: key nums then plaintext nums."""
    key = _clean(key)
    if not key:
        raise ValueError("Autokey key must contain at least one letter.")
    key_nums = [_to_num(c) for c in key]
    stream = []
    for i in range(n):
        if i < len(key_nums):
            stream.append(key_nums[i])
        else:
            stream.append(plain_indices[i - len(key_nums)])
    return stream


def autokey_encrypt(plaintext, key):
    """Encrypt `plaintext` with Autokey key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("Autokey key must contain at least one letter.")
    letters = [ch for ch in plaintext if ch.isalpha()]
    letter_indices = [ord(ch.upper()) - ord('A') for ch in letters]
    stream = _autokey_keystream(key, len(letter_indices), letter_indices)
    out_letters = [
        _to_ch((p + s) % 26) for p, s in zip(letter_indices, stream)
    ]
    # Rebuild the full string, preserving non-letters and original case.
    result = []
    li = 0
    for ch in plaintext:
        if ch.isalpha():
            enc = out_letters[li]
            result.append(enc if ch.isupper() else enc.lower())
            li += 1
        else:
            result.append(ch)
    return ''.join(result)


def autokey_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Autokey key `key`."""
    key = _clean(key)
    if not key:
        raise ValueError("Autokey key must contain at least one letter.")
    key_nums = [_to_num(c) for c in key]
    letters = [ch for ch in ciphertext if ch.isalpha()]
    letter_indices = [ord(ch.upper()) - ord('A') for ch in letters]
    # Recover plaintext letter by letter; keystream uses recovered plaintext.
    plain_indices = []
    for i, c in enumerate(letter_indices):
        if i < len(key_nums):
            k = key_nums[i]
        else:
            k = plain_indices[i - len(key_nums)]
        plain_indices.append((c - k) % 26)
    out_letters = [_to_ch(p) for p in plain_indices]
    result = []
    li = 0
    for ch in ciphertext:
        if ch.isalpha():
            dec = out_letters[li]
            result.append(dec if ch.isupper() else dec.lower())
            li += 1
        else:
            result.append(ch)
    return ''.join(result)
