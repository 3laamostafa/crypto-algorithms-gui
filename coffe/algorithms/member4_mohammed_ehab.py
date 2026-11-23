# ============================================================================
# algorithms/member4_mohammed_ehab.py  -  Mohammed Ehab (Member 4)
# ============================================================================
# Algorithms:
#   1. Vigenère Cipher (Polyalphabetic Cipher with repeating key)
#   2. Autokey Cipher (Polyalphabetic Cipher with primer key + plaintext stream)
# ============================================================================


# ==================== 1. VIGENERE CIPHER ====================

def vigenere_encrypt(plaintext, key):
    """Encrypt plaintext using Vigenere Cipher with repeating key."""
    clean_key = ''.join(c.upper() for c in key if c.isalpha())
    if not clean_key:
        raise ValueError("Vigenere key must contain at least one alphabetic letter!")

    cipher = []
    key_index = 0
    for p in plaintext:
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            p_val = ord(p) - base
            k_val = ord(clean_key[key_index % len(clean_key)]) - ord('A')
            c_val = (p_val + k_val) % 26
            cipher.append(chr(c_val + base))
            key_index += 1
        else:
            cipher.append(p)
    return "".join(cipher)


def vigenere_decrypt(ciphertext, key):
    """Decrypt ciphertext using Vigenere Cipher with repeating key."""
    clean_key = ''.join(c.upper() for c in key if c.isalpha())
    if not clean_key:
        raise ValueError("Vigenere key must contain at least one alphabetic letter!")

    plain = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            c_val = ord(c) - base
            k_val = ord(clean_key[key_index % len(clean_key)]) - ord('A')
            p_val = (c_val - k_val) % 26
            plain.append(chr(p_val + base))
            key_index += 1
        else:
            plain.append(c)
    return "".join(plain)


# ==================== 2. AUTOKEY CIPHER ====================

def autokey_encrypt(plaintext, key):
    """
    Encrypt plaintext using Autokey Cipher.
    Keystream starts with primer key, then continues with the plaintext letters.
    """
    clean_key = ''.join(c.upper() for c in key if c.isalpha())
    if not clean_key:
        raise ValueError("Autokey key must contain at least one alphabetic letter!")

    # Extract only alpha letters for the stream
    letters = [c.upper() for c in plaintext if c.isalpha()]
    full_keystream = clean_key + "".join(letters)

    cipher_letters = []
    for i in range(len(letters)):
        p = ord(letters[i]) - ord('A')
        k = ord(full_keystream[i]) - ord('A')
        c = (p + k) % 26
        cipher_letters.append(chr(c + ord('A')))

    # Reconstruct with original formatting
    result = []
    letter_idx = 0
    for char in plaintext:
        if char.isalpha():
            c = cipher_letters[letter_idx]
            result.append(c if char.isupper() else c.lower())
            letter_idx += 1
        else:
            result.append(char)
    return "".join(result)


def autokey_decrypt(ciphertext, key):
    """
    Decrypt ciphertext using Autokey Cipher.
    Keystream is dynamically recovered: as each plaintext letter is decrypted,
    it is appended to the keystream for subsequent letters.
    """
    clean_key = ''.join(c.upper() for c in key if c.isalpha())
    if not clean_key:
        raise ValueError("Autokey key must contain at least one alphabetic letter!")

    letters = [c.upper() for c in ciphertext if c.isalpha()]
    plain_letters = []
    keystream_chars = list(clean_key)

    for i in range(len(letters)):
        c = ord(letters[i]) - ord('A')
        k = ord(keystream_chars[i]) - ord('A')
        p = (c - k) % 26
        recovered_char = chr(p + ord('A'))
        plain_letters.append(recovered_char)
        keystream_chars.append(recovered_char)

    # Reconstruct with original formatting
    result = []
    letter_idx = 0
    for char in ciphertext:
        if char.isalpha():
            p = plain_letters[letter_idx]
            result.append(p if char.isupper() else p.lower())
            letter_idx += 1
        else:
            result.append(char)
    return "".join(result)