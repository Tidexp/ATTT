class AES_Scratch:
    def __init__(self):
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        self.inv_sbox = [0] * 256
        for i, v in enumerate(self.sbox):
            self.inv_sbox[v] = i

        # đủ cho AES-128/192/256 key expansion (thực tế cần <= 8 giá trị cho AES-192/256)
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def sub_bytes(self, state):
        for i in range(16):
            state[i] = self.sbox[state[i]]

    def inv_sub_bytes(self, state):
        for i in range(16):
            state[i] = self.inv_sbox[state[i]]

    def shift_rows(self, state):
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    def inv_shift_rows(self, state):
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    def xtime(self, a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

    def gmul(self, a, b):
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return result

    def mix_columns(self, state):
        for i in range(0, 16, 4):
            s0, s1, s2, s3 = state[i:i+4]
            state[i]   = self.xtime(s0) ^ (self.xtime(s1) ^ s1) ^ s2 ^ s3
            state[i+1] = s0 ^ self.xtime(s1) ^ (self.xtime(s2) ^ s2) ^ s3
            state[i+2] = s0 ^ s1 ^ self.xtime(s2) ^ (self.xtime(s3) ^ s3)
            state[i+3] = (self.xtime(s0) ^ s0) ^ s1 ^ s2 ^ self.xtime(s3)

    def inv_mix_columns(self, state):
        for i in range(0, 16, 4):
            s0, s1, s2, s3 = state[i:i+4]
            state[i]   = self.gmul(s0, 0x0e) ^ self.gmul(s1, 0x0b) ^ self.gmul(s2, 0x0d) ^ self.gmul(s3, 0x09)
            state[i+1] = self.gmul(s0, 0x09) ^ self.gmul(s1, 0x0e) ^ self.gmul(s2, 0x0b) ^ self.gmul(s3, 0x0d)
            state[i+2] = self.gmul(s0, 0x0d) ^ self.gmul(s1, 0x09) ^ self.gmul(s2, 0x0e) ^ self.gmul(s3, 0x0b)
            state[i+3] = self.gmul(s0, 0x0b) ^ self.gmul(s1, 0x0d) ^ self.gmul(s2, 0x09) ^ self.gmul(s3, 0x0e)

    def add_round_key(self, state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]

    def expand_key(self, master_key):
        """
        Key expansion for AES-128/192/256.
        Returns expanded key bytes as list[int] with length 16 * (Nr + 1).
        """
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key phải là bytes/bytearray.")
        key_len = len(master_key)
        if key_len not in (16, 24, 32):
            raise ValueError("Key phải dài 16/24/32 bytes (AES-128/192/256).")

        nb = 4  # AES block words
        nk = key_len // 4  # key words: 4/6/8
        nr = {4: 10, 6: 12, 8: 14}[nk]
        total_words = nb * (nr + 1)

        # w: list of 4-byte words
        w: list[list[int]] = []
        key_bytes = list(master_key)
        for i in range(nk):
            w.append(key_bytes[4 * i : 4 * (i + 1)])

        def _rot_word(word: list[int]) -> list[int]:
            return word[1:] + word[:1]

        def _sub_word(word: list[int]) -> list[int]:
            return [self.sbox[b] for b in word]

        i = nk
        while i < total_words:
            temp = w[i - 1].copy()
            if i % nk == 0:
                temp = _sub_word(_rot_word(temp))
                rc_index = (i // nk) - 1
                if rc_index >= len(self.rcon):
                    raise ValueError("Thiếu Rcon cho key expansion.")
                temp[0] ^= self.rcon[rc_index]
            elif nk == 8 and (i % nk) == 4:
                # AES-256 extra SubWord step
                temp = _sub_word(temp)
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
            i += 1

        expanded = [b for word in w for b in word]
        return expanded

    def encrypt_block(self, block, expanded_key):
        state = list(block)
        nr = (len(expanded_key) // 16) - 1
        if nr not in (10, 12, 14):
            raise ValueError("Expanded key không hợp lệ.")

        self.add_round_key(state, expanded_key[0:16])
        for i in range(1, nr):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, expanded_key[i*16:(i+1)*16])
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, expanded_key[nr * 16 : (nr + 1) * 16])
        return bytes(state)

    def decrypt_block(self, block, expanded_key):
        state = list(block)
        nr = (len(expanded_key) // 16) - 1
        if nr not in (10, 12, 14):
            raise ValueError("Expanded key không hợp lệ.")

        self.add_round_key(state, expanded_key[nr * 16 : (nr + 1) * 16])
        for round_num in range(nr - 1, 0, -1):
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self.add_round_key(state, expanded_key[round_num*16:(round_num+1)*16])
            self.inv_mix_columns(state)
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        self.add_round_key(state, expanded_key[0:16])
        return bytes(state)

