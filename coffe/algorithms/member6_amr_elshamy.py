# ============================================================================
# algorithms/member6_amr_elshamy.py  -  Amr Elshamy (Member 6)
# ============================================================================
#   1. Rail Fence Transposition Cipher   (zig-zag writing on rails)
#   2. Single Columnar Transposition     (write in rows, read columns by key order)
#   3. Double Columnar Transposition     (apply columnar transposition twice)
#
# Each function receives the text and the needed key(s) and returns a string.
# Raises ValueError with a friendly message when the input or key is invalid.
# ----------------------------------------------------------------------------

# ==================== RAIL FENCE CIPHER ====================
# Write the message in a zig-zag pattern down and up `rails` rows, then read
# off row by row. Decryption rebuilds the same rail pattern.


def rail_fence_encrypt(plaintext, rails):
    """Encrypt `plaintext` with Rail Fence `rails`."""
    rails = int(rails)
    if rails < 2:
        raise ValueError("Rail Fence needs at least 2 rails.")
    if rails == 1 or not plaintext:
        return plaintext
    fence = [[] for _ in range(rails)]
    rail = 0
    step = 1
    for ch in plaintext:
        fence[rail].append(ch)
        rail += step
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
    return ''.join(''.join(row) for row in fence)


def rail_fence_decrypt(ciphertext, rails):
    """Decrypt `ciphertext` with Rail Fence `rails`."""
    rails = int(rails)
    if rails < 2:
        raise ValueError("Rail Fence needs at least 2 rails.")
    if rails == 1 or not ciphertext:
        return ciphertext
    n = len(ciphertext)
    # Determine how many chars belong to each rail by simulating the path.
    rail_counts = [0] * rails
    rail = 0
    step = 1
    for _ in range(n):
        rail_counts[rail] += 1
        rail += step
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
    # Slice the ciphertext into rails in order.
    rails_text = []
    idx = 0
    for count in rail_counts:
        rails_text.append(list(ciphertext[idx:idx + count]))
        idx += count
    # Reconstruct by walking the zig-zag and popping from each rail.
    out = []
    rail = 0
    step = 1
    for _ in range(n):
        out.append(rails_text[rail].pop(0))
        rail += step
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
    return ''.join(out)


# ==================== SINGLE COLUMNAR TRANSPOSITION ====================
# Write plaintext into rows under the key columns, then read columns in
# alphabetical order of the key letters. Pad short cells with 'X'.


def _columnar_order(key):
    """Return column indices sorted by the key letters (stable for ties)."""
    key = key.upper()
    if not key:
        raise ValueError("Columnar key must not be empty.")
    if len(set(key)) != len(key):
        raise ValueError("Columnar key must not have repeated letters.")
    # stable sort by letter -> column index order
    indexed = list(enumerate(key))  # (col_index, letter)
    indexed.sort(key=lambda item: item[1])
    return [col for col, _ in indexed]


def single_columnar_encrypt(plaintext, key):
    """Encrypt `plaintext` with Single Columnar key `key`."""
    order = _columnar_order(key)
    ncols = len(key)
    # Fill row by row, left to right.
    rows = []
    for i in range(0, len(plaintext), ncols):
        row = list(plaintext[i:i + ncols])
        # pad the last row with X
        while len(row) < ncols:
            row.append('X')
        rows.append(row)
    # Read columns in key order.
    out = []
    for col in order:
        for row in rows:
            out.append(row[col])
    return ''.join(out)


def single_columnar_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Single Columnar key `key`."""
    order = _columnar_order(key)
    ncols = len(key)
    n = len(ciphertext)
    nrows = (n + ncols - 1) // ncols
    # Figure out how many chars each column got during encryption.
    # Full columns = those whose position < (n % ncols); all columns have
    # nrows chars except the last partial row.
    remainder = n % ncols
    col_lengths = {}
    for ci in range(ncols):
        if remainder == 0:
            col_lengths[ci] = nrows
        else:
            # columns in original order: first `remainder` columns are full.
            col_lengths[ci] = nrows if ci < remainder else nrows - 1
    # Slice ciphertext into columns according to key-read order.
    cols = {}
    idx = 0
    for col in order:
        length = col_lengths[col]
        cols[col] = list(ciphertext[idx:idx + length])
        idx += length
    # Rebuild row by row: row r takes the r-th char of each column in order.
    out = []
    for r in range(nrows):
        for col in range(ncols):
            if r < len(cols[col]):
                out.append(cols[col][r])
    return ''.join(out).rstrip('X')


# ==================== DOUBLE COLUMNAR TRANSPOSITION ====================
# Apply single columnar transposition twice (with the same or two keys).
# Here we use one key applied twice for simplicity and round-trip clarity.


def double_columnar_encrypt(plaintext, key):
    """Encrypt `plaintext` with Double Columnar key `key` (apply twice)."""
    first = single_columnar_encrypt(plaintext, key)
    return single_columnar_encrypt(first, key)


def double_columnar_decrypt(ciphertext, key):
    """Decrypt `ciphertext` with Double Columnar key `key` (apply twice)."""
    first = single_columnar_decrypt(ciphertext, key)
    return single_columnar_decrypt(first, key)
