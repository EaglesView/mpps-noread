#!/usr/bin/env python3
"""
make_testvec.py - Generate a synthetic MPPS-NOREAD test vector (matched pair).

Produces:
  test_plain.bin  - a 1 MB firmware-like plaintext (the "reference tune")
  test_noread.Bin - its NOREAD-encrypted form (32-byte marker + two-stage payload)

The synthetic format mirrors what we reverse-engineered from 1K0907115S.Bin:
  Stage 1 (packing): runs of the 0xFF blank byte are stripped out.
  Stage 2 (cipher) : the packed stream is XORed with a byte-state PRNG keystream
                     (an 8-bit LFSR), so constant-plaintext regions leak a
                     periodic keystream orbit -- exactly the behaviour we see.

This is a *model* of the format for pipeline testing, not the real MPPS algorithm
(which we finalize from the real reference tune). `noread.py derive` should crack
this pair end-to-end.
"""

import random

HEADER = b"No read file has been encrypted-"
BLANK = 0xFF


def make_plaintext(size=1024 * 1024, seed=1234):
    """Build a 1 MB image: high-entropy 'code', calibration tables, blank fill,
    and one constant-value region (to create a periodic leak in the cipher)."""
    rnd = random.Random(seed)
    buf = bytearray()
    while len(buf) < size:
        kind = rnd.random()
        if kind < 0.45:                              # code-like high entropy
            buf += bytes(rnd.getrandbits(8) for _ in range(rnd.randint(2000, 8000)))
        elif kind < 0.70:                            # blank flash (0xFF)
            buf += bytes([BLANK]) * rnd.randint(1000, 6000)
        elif kind < 0.85:                            # calibration table (low entropy)
            base = rnd.randint(0, 255)
            buf += bytes((base + (i % 7)) & 0xFF for i in range(rnd.randint(800, 3000)))
        else:                                        # constant region -> periodic leak
            buf += bytes([rnd.randint(0, 255)]) * rnd.randint(400, 1200)
    return bytes(buf[:size])


def stage1_pack(buf, fill=BLANK):
    """Remove maximal runs of the fill byte."""
    out = bytearray()
    i, n = 0, len(buf)
    while i < n:
        if buf[i] == fill:
            while i < n and buf[i] == fill:
                i += 1
            continue
        out.append(buf[i])
        i += 1
    return bytes(out)


def lfsr_keystream(n, seed=0xACE1):
    """8-bit output from a 16-bit Galois LFSR -> consistent byte-state PRNG."""
    s = seed & 0xFFFF
    out = bytearray()
    for _ in range(n):
        # 16-bit LFSR, taps 0xB400
        for _ in range(8):
            lsb = s & 1
            s >>= 1
            if lsb:
                s ^= 0xB400
        out.append(s & 0xFF)
    return bytes(out)


def stage2_cipher(packed):
    ks = lfsr_keystream(len(packed))
    return bytes(a ^ b for a, b in zip(packed, ks))


def main():
    plain = make_plaintext()
    packed = stage1_pack(plain)
    cipher = stage2_cipher(packed)
    noread = HEADER + cipher

    with open("test_plain.bin", "wb") as f:
        f.write(plain)
    with open("test_noread.Bin", "wb") as f:
        f.write(noread)

    print(f"test_plain.bin   : {len(plain)} bytes (plaintext / reference tune)")
    print(f"  blank 0xFF bytes: {plain.count(BLANK)}")
    print(f"test_noread.Bin  : {len(noread)} bytes "
          f"(32 header + {len(cipher)} cipher body)")
    print(f"  packed length   : {len(packed)}  (= cipher body)")
    print("\nValidate with:")
    print("  python3 noread.py analyze test_noread.Bin")
    print("  python3 noread.py derive  test_noread.Bin test_plain.bin -o ks.bin")
    print("  python3 noread.py decrypt test_noread.Bin --keystream ks.bin -o out.bin")


if __name__ == "__main__":
    main()
