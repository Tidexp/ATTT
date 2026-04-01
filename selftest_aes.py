from aes_core import AES_Scratch


def main() -> None:
    aes = AES_Scratch()
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    vectors = [
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ]

    for key, expected_ct in vectors:
        ek = aes.expand_key(key)
        ct = aes.encrypt_block(pt, ek)
        ok = ct == expected_ct
        print(f"AES-{len(key) * 8}: {'OK' if ok else 'FAIL'}")
        if not ok:
            print(" expected:", expected_ct.hex())
            print(" got     :", ct.hex())
            raise SystemExit(1)

    # quick decrypt check
    for key, expected_ct in vectors:
        ek = aes.expand_key(key)
        pt2 = aes.decrypt_block(expected_ct, ek)
        if pt2 != pt:
            print(f"AES-{len(key) * 8}: FAIL (decrypt)")
            raise SystemExit(1)

    print("All AES KATs passed.")


if __name__ == "__main__":
    main()

