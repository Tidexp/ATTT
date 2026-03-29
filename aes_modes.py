import secrets


BLOCK_SIZE = 16
NONCE_SIZE_12 = 12
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Dữ liệu không hợp lệ (không chia hết block size)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Đệm không hợp lệ")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Đệm không hợp lệ")
    return data[:-pad_len]


def encrypt_ecb(aes, padded: bytes, expanded_key) -> bytes:
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out += aes.encrypt_block(padded[i:i+BLOCK_SIZE], expanded_key)
    return bytes(out)


def decrypt_ecb(aes, encrypted_data: bytes, expanded_key) -> bytes:
    out = bytearray()
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        out += aes.decrypt_block(encrypted_data[i:i+BLOCK_SIZE], expanded_key)
    return bytes(out)


def encrypt_cbc(aes, padded: bytes, expanded_key, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = aes.encrypt_block(x, expanded_key)
        out += c
        prev = c
    return bytes(out)


def decrypt_cbc(aes, encrypted_data: bytes, expanded_key, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        c = encrypted_data[i:i+BLOCK_SIZE]
        p = aes.decrypt_block(c, expanded_key)
        out += xor_bytes(p, prev)
        prev = c
    return bytes(out)


def _pad16(data: bytes) -> bytes:
    if len(data) % BLOCK_SIZE == 0:
        return data
    return data + b"\x00" * (BLOCK_SIZE - (len(data) % BLOCK_SIZE))


def _u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _inc32(counter_block: bytes) -> bytes:
    if len(counter_block) != BLOCK_SIZE:
        raise ValueError("Counter block phải dài 16 bytes.")
    prefix = counter_block[:12]
    ctr = int.from_bytes(counter_block[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


def ctr_crypt(aes, data: bytes, expanded_key, nonce12: bytes, initial_counter: int = 1) -> bytes:
    """
    AES-CTR (RFC-style):
      counter_block = nonce12 || counter32 (big-endian)
    """
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("CTR cần nonce 12 bytes (24 ký tự hex).")
    if initial_counter < 0 or initial_counter > 0xFFFFFFFF:
        raise ValueError("initial_counter không hợp lệ.")

    counter_block = nonce12 + initial_counter.to_bytes(4, "big")
    out = bytearray()
    offset = 0
    while offset < len(data):
        keystream = aes.encrypt_block(counter_block, expanded_key)
        chunk = data[offset:offset + BLOCK_SIZE]
        out += xor_bytes(chunk, keystream[:len(chunk)])
        offset += len(chunk)
        counter_block = _inc32(counter_block)
    return bytes(out)


def _gf_mul_128(x: int, y: int) -> int:
    """
    GF(2^128) multiply with reduction polynomial:
      R = 0xe1 << 120
    """
    r = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    if len(h) != BLOCK_SIZE:
        raise ValueError("H phải dài 16 bytes.")
    h_int = int.from_bytes(h, "big")
    y = 0

    def _update(block16: bytes):
        nonlocal y
        y ^= int.from_bytes(block16, "big")
        y = _gf_mul_128(y, h_int)

    for i in range(0, len(_pad16(aad)), BLOCK_SIZE):
        _update(_pad16(aad)[i:i + BLOCK_SIZE])

    for i in range(0, len(_pad16(ciphertext)), BLOCK_SIZE):
        _update(_pad16(ciphertext)[i:i + BLOCK_SIZE])

    lengths = _u64_be(len(aad) * 8) + _u64_be(len(ciphertext) * 8)
    _update(lengths)
    return y.to_bytes(16, "big")


def gcm_encrypt(aes, plaintext: bytes, expanded_key, nonce12: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    AES-GCM with 12-byte nonce, empty AAD by default.
    Returns: (ciphertext, tag16)
    """
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("GCM cần nonce 12 bytes (24 ký tự hex).")

    h = aes.encrypt_block(b"\x00" * 16, expanded_key)
    j0 = nonce12 + b"\x00\x00\x00\x01"
    ciphertext = ctr_crypt(aes, plaintext, expanded_key, nonce12, initial_counter=2)
    s = _ghash(h, aad, ciphertext)
    e_j0 = aes.encrypt_block(j0, expanded_key)
    tag = xor_bytes(e_j0, s)
    return ciphertext, tag


def gcm_decrypt(aes, ciphertext: bytes, expanded_key, nonce12: bytes, tag16: bytes, aad: bytes = b"") -> bytes:
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("GCM cần nonce 12 bytes (24 ký tự hex).")
    if len(tag16) != TAG_SIZE:
        raise ValueError("Tag GCM phải dài 16 bytes.")

    h = aes.encrypt_block(b"\x00" * 16, expanded_key)
    j0 = nonce12 + b"\x00\x00\x00\x01"
    s = _ghash(h, aad, ciphertext)
    e_j0 = aes.encrypt_block(j0, expanded_key)
    expected = xor_bytes(e_j0, s)
    if not secrets.compare_digest(expected, tag16):
        raise ValueError("Sai tag GCM (dữ liệu bị sửa hoặc key/nonce không đúng).")
    return ctr_crypt(aes, ciphertext, expanded_key, nonce12, initial_counter=2)


def parse_header_from_file(f) -> tuple[str, bytes, bytes]:
    """
    Reads header from current file position.
    Returns: (mode, iv_or_nonce, tag)
    After return, file cursor points to start of payload.
    """
    magic = f.read(4)
    if len(magic) < 4:
        raise ValueError("File mã hóa không hợp lệ (thiếu header).")

    if magic == b"CBC1":
        iv = f.read(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("File CBC không hợp lệ (thiếu IV).")
        return "CBC", iv, b""

    if magic == b"CTR1":
        nonce = f.read(NONCE_SIZE_12)
        if len(nonce) != NONCE_SIZE_12:
            raise ValueError("File CTR không hợp lệ (thiếu nonce).")
        return "CTR", nonce, b""

    if magic == b"GCM1":
        nonce = f.read(NONCE_SIZE_12)
        tag = f.read(TAG_SIZE)
        if len(nonce) != NONCE_SIZE_12 or len(tag) != TAG_SIZE:
            raise ValueError("File GCM không hợp lệ (thiếu nonce/tag).")
        return "GCM", nonce, tag

    if magic == b"ECB1":
        return "ECB", b"", b""

    # legacy: không có header => rewind để payload bắt đầu từ đầu
    f.seek(-4, 1)
    return "ECB (legacy)", b"", b""


def encrypt_stream_ecb(aes, infile, outfile, expanded_key, chunk_size: int = DEFAULT_CHUNK_SIZE):
    """
    ECB + PKCS7 padding (streaming).
    Expects header already written if needed.
    """
    buffer = b""
    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break
        buffer += chunk
        # giữ lại tối thiểu 1 block để padding cuối
        while len(buffer) >= 2 * BLOCK_SIZE:
            block = buffer[:BLOCK_SIZE]
            buffer = buffer[BLOCK_SIZE:]
            outfile.write(aes.encrypt_block(block, expanded_key))

    padded = pad_pkcs7(buffer, BLOCK_SIZE)
    for i in range(0, len(padded), BLOCK_SIZE):
        outfile.write(aes.encrypt_block(padded[i:i + BLOCK_SIZE], expanded_key))


def decrypt_stream_ecb(aes, infile, outfile, expanded_key, chunk_size: int = DEFAULT_CHUNK_SIZE):
    """
    ECB + PKCS7 unpadding (streaming).
    Requires ciphertext length multiple of 16.
    """
    buffer = b""
    last_plain_block = None

    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break
        buffer += chunk
        # xử lý block trừ block cuối (giữ 1 block để unpad)
        while len(buffer) >= 2 * BLOCK_SIZE:
            c = buffer[:BLOCK_SIZE]
            buffer = buffer[BLOCK_SIZE:]
            p = aes.decrypt_block(c, expanded_key)
            if last_plain_block is not None:
                outfile.write(last_plain_block)
            last_plain_block = p

    if len(buffer) % BLOCK_SIZE != 0:
        raise ValueError("File ECB không hợp lệ (payload không chia hết 16 byte).")
    while len(buffer) >= BLOCK_SIZE:
        c = buffer[:BLOCK_SIZE]
        buffer = buffer[BLOCK_SIZE:]
        p = aes.decrypt_block(c, expanded_key)
        if last_plain_block is not None:
            outfile.write(last_plain_block)
        last_plain_block = p

    if last_plain_block is None:
        raise ValueError("File ECB không hợp lệ (payload rỗng).")
    outfile.write(unpad_pkcs7(last_plain_block, BLOCK_SIZE))


def encrypt_stream_cbc(aes, infile, outfile, expanded_key, iv: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
    buffer = b""
    prev = iv
    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break
        buffer += chunk
        while len(buffer) >= 2 * BLOCK_SIZE:
            block = buffer[:BLOCK_SIZE]
            buffer = buffer[BLOCK_SIZE:]
            x = xor_bytes(block, prev)
            c = aes.encrypt_block(x, expanded_key)
            outfile.write(c)
            prev = c

    padded = pad_pkcs7(buffer, BLOCK_SIZE)
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = aes.encrypt_block(x, expanded_key)
        outfile.write(c)
        prev = c


def decrypt_stream_cbc(aes, infile, outfile, expanded_key, iv: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
    buffer = b""
    prev = iv
    last_plain_block = None

    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break
        buffer += chunk
        while len(buffer) >= 2 * BLOCK_SIZE:
            c = buffer[:BLOCK_SIZE]
            buffer = buffer[BLOCK_SIZE:]
            p = xor_bytes(aes.decrypt_block(c, expanded_key), prev)
            prev = c
            if last_plain_block is not None:
                outfile.write(last_plain_block)
            last_plain_block = p

    if len(buffer) % BLOCK_SIZE != 0:
        raise ValueError("File CBC không hợp lệ (payload không chia hết 16 byte).")
    while len(buffer) >= BLOCK_SIZE:
        c = buffer[:BLOCK_SIZE]
        buffer = buffer[BLOCK_SIZE:]
        p = xor_bytes(aes.decrypt_block(c, expanded_key), prev)
        prev = c
        if last_plain_block is not None:
            outfile.write(last_plain_block)
        last_plain_block = p

    if last_plain_block is None:
        raise ValueError("File CBC không hợp lệ (payload rỗng).")
    outfile.write(unpad_pkcs7(last_plain_block, BLOCK_SIZE))


def ctr_crypt_stream(aes, infile, outfile, expanded_key, nonce12: bytes, initial_counter: int = 1, chunk_size: int = DEFAULT_CHUNK_SIZE):
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("CTR cần nonce 12 bytes (24 ký tự hex).")
    counter_block = nonce12 + initial_counter.to_bytes(4, "big")
    keystream = b""
    ks_off = 0

    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break
        out = bytearray()
        i = 0
        while i < len(chunk):
            if ks_off >= len(keystream):
                keystream = aes.encrypt_block(counter_block, expanded_key)
                ks_off = 0
                counter_block = _inc32(counter_block)
            take = min(len(chunk) - i, len(keystream) - ks_off)
            out += xor_bytes(chunk[i:i + take], keystream[ks_off:ks_off + take])
            i += take
            ks_off += take
        outfile.write(out)


def _ghash_update(y: int, h_int: int, block16: bytes) -> int:
    y ^= int.from_bytes(block16, "big")
    return _gf_mul_128(y, h_int)


def gcm_encrypt_stream(aes, infile, outfile, expanded_key, nonce12: bytes, aad: bytes = b"", chunk_size: int = DEFAULT_CHUNK_SIZE):
    """
    Streaming AES-GCM (nonce 12 bytes). Writes placeholder tag in header; caller must write magic+nonce+tag first.
    This function assumes outfile is seekable to patch tag later.
    Returns tag16.
    """
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("GCM cần nonce 12 bytes (24 ký tự hex).")
    if aad:
        raise ValueError("Hiện tại streaming GCM chỉ hỗ trợ AAD rỗng.")

    h = aes.encrypt_block(b"\x00" * 16, expanded_key)
    h_int = int.from_bytes(h, "big")
    j0 = nonce12 + b"\x00\x00\x00\x01"

    # CTR starts at counter=2
    counter_block = nonce12 + (2).to_bytes(4, "big")
    keystream = b""
    ks_off = 0

    y = 0
    ct_len = 0
    gbuf = b""

    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break

        out_ct = bytearray()
        i = 0
        while i < len(chunk):
            if ks_off >= len(keystream):
                keystream = aes.encrypt_block(counter_block, expanded_key)
                ks_off = 0
                counter_block = _inc32(counter_block)
            take = min(len(chunk) - i, len(keystream) - ks_off)
            part = xor_bytes(chunk[i:i + take], keystream[ks_off:ks_off + take])
            out_ct += part
            i += take
            ks_off += take

        ct_bytes = bytes(out_ct)
        outfile.write(ct_bytes)
        ct_len += len(ct_bytes)

        gbuf += ct_bytes
        while len(gbuf) >= BLOCK_SIZE:
            y = _ghash_update(y, h_int, gbuf[:BLOCK_SIZE])
            gbuf = gbuf[BLOCK_SIZE:]

    if gbuf:
        y = _ghash_update(y, h_int, _pad16(gbuf))

    lengths = _u64_be(len(aad) * 8) + _u64_be(ct_len * 8)
    y = _ghash_update(y, h_int, lengths)
    s = y.to_bytes(16, "big")
    tag = xor_bytes(aes.encrypt_block(j0, expanded_key), s)
    return tag


def gcm_decrypt_stream_to_temp(aes, infile, tmp_outfile, expanded_key, nonce12: bytes, tag16: bytes, aad: bytes = b"", chunk_size: int = DEFAULT_CHUNK_SIZE) -> bool:
    """
    Decrypts ciphertext stream to tmp_outfile while computing GHASH.
    Returns True if tag verified, else False.
    """
    if len(nonce12) != NONCE_SIZE_12:
        raise ValueError("GCM cần nonce 12 bytes (24 ký tự hex).")
    if len(tag16) != TAG_SIZE:
        raise ValueError("Tag GCM phải dài 16 bytes.")
    if aad:
        raise ValueError("Hiện tại streaming GCM chỉ hỗ trợ AAD rỗng.")

    h = aes.encrypt_block(b"\x00" * 16, expanded_key)
    h_int = int.from_bytes(h, "big")
    j0 = nonce12 + b"\x00\x00\x00\x01"

    # CTR starts at counter=2
    counter_block = nonce12 + (2).to_bytes(4, "big")
    keystream = b""
    ks_off = 0

    y = 0
    ct_len = 0
    gbuf = b""

    while True:
        chunk = infile.read(chunk_size)
        if not chunk:
            break

        # GHASH over ciphertext
        ct_len += len(chunk)
        gbuf += chunk
        while len(gbuf) >= BLOCK_SIZE:
            y = _ghash_update(y, h_int, gbuf[:BLOCK_SIZE])
            gbuf = gbuf[BLOCK_SIZE:]

        # decrypt via CTR
        out_pt = bytearray()
        i = 0
        while i < len(chunk):
            if ks_off >= len(keystream):
                keystream = aes.encrypt_block(counter_block, expanded_key)
                ks_off = 0
                counter_block = _inc32(counter_block)
            take = min(len(chunk) - i, len(keystream) - ks_off)
            out_pt += xor_bytes(chunk[i:i + take], keystream[ks_off:ks_off + take])
            i += take
            ks_off += take
        tmp_outfile.write(out_pt)

    if gbuf:
        y = _ghash_update(y, h_int, _pad16(gbuf))

    lengths = _u64_be(len(aad) * 8) + _u64_be(ct_len * 8)
    y = _ghash_update(y, h_int, lengths)
    s = y.to_bytes(16, "big")
    expected = xor_bytes(aes.encrypt_block(j0, expanded_key), s)
    return secrets.compare_digest(expected, tag16)


def parse_iv_hex(iv_hex: str) -> bytes:
    raw = (iv_hex or "").strip()
    if not raw:
        return b""
    raw_hex = raw.replace(" ", "")
    iv = bytes.fromhex(raw_hex)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV phải đúng 16 bytes (32 ký tự hex).")
    return iv


def random_iv() -> bytes:
    return secrets.token_bytes(BLOCK_SIZE)


def parse_nonce12_hex(nonce_hex: str) -> bytes:
    raw = (nonce_hex or "").strip()
    if not raw:
        return b""
    raw_hex = raw.replace(" ", "")
    nonce = bytes.fromhex(raw_hex)
    if len(nonce) != NONCE_SIZE_12:
        raise ValueError("Nonce phải đúng 12 bytes (24 ký tự hex).")
    return nonce


def random_nonce12() -> bytes:
    return secrets.token_bytes(NONCE_SIZE_12)


def build_header(mode: str, iv_or_nonce: bytes | None = None, tag16: bytes | None = None) -> bytes:
    m = (mode or "").upper()
    if m == "CBC":
        if iv_or_nonce is None or len(iv_or_nonce) != BLOCK_SIZE:
            raise ValueError("CBC cần IV 16 bytes.")
        return b"CBC1" + iv_or_nonce
    if m == "CTR":
        if iv_or_nonce is None or len(iv_or_nonce) != NONCE_SIZE_12:
            raise ValueError("CTR cần nonce 12 bytes.")
        return b"CTR1" + iv_or_nonce
    if m == "GCM":
        if iv_or_nonce is None or len(iv_or_nonce) != NONCE_SIZE_12:
            raise ValueError("GCM cần nonce 12 bytes.")
        if tag16 is None or len(tag16) != TAG_SIZE:
            raise ValueError("GCM cần tag 16 bytes.")
        return b"GCM1" + iv_or_nonce + tag16
    return b"ECB1"


def parse_header(blob: bytes) -> tuple[str, bytes, bytes, bytes]:
    """
    Returns: (mode, iv_or_nonce, tag, payload)
      - mode: "CBC" | "CTR" | "GCM" | "ECB" | "ECB (legacy)"
      - iv_or_nonce: CBC=16 bytes, CTR/GCM=12 bytes, else b""
      - tag: GCM=16 bytes, else b""
      - payload: ciphertext bytes
    """
    if len(blob) < 4:
        raise ValueError("File mã hóa không hợp lệ (thiếu header).")

    magic = blob[:4]
    if magic == b"CBC1":
        if len(blob) < 4 + BLOCK_SIZE:
            raise ValueError("File CBC không hợp lệ (thiếu IV).")
        iv = blob[4:20]
        payload = blob[20:]
        return "CBC", iv, b"", payload

    if magic == b"CTR1":
        if len(blob) < 4 + NONCE_SIZE_12:
            raise ValueError("File CTR không hợp lệ (thiếu nonce).")
        nonce = blob[4:16]
        payload = blob[16:]
        return "CTR", nonce, b"", payload

    if magic == b"GCM1":
        if len(blob) < 4 + NONCE_SIZE_12 + TAG_SIZE:
            raise ValueError("File GCM không hợp lệ (thiếu nonce/tag).")
        nonce = blob[4:16]
        tag = blob[16:32]
        payload = blob[32:]
        return "GCM", nonce, tag, payload

    if magic == b"ECB1":
        return "ECB", b"", b"", blob[4:]

    # fallback: file cũ (không có header) => coi như ECB
    return "ECB (legacy)", b"", b"", blob

