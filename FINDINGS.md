# MPPS NOREAD format — reverse-engineering notes

Target sample: `1K0907115S.Bin` (VW/Audi part number; `1K0` = PQ35 platform).

## Container layout

| Offset | Size | Contents |
|--------|------|----------|
| `0x00` | 32 | ASCII marker `No read file has been encrypted-` (exactly 32 bytes) |
| `0x20` | 811961 | scrambled payload ("body") |

Total file: 811993 bytes. **Body length 811961 is odd**, which is unusual for a
byte-aligned cipher over an (even-sized) firmware image — suggests either trailing
padding or that the payload is not a straight length-preserving cipher of the raw
firmware.

## Two-stage model (source: GTI Golf, ~1 MB stage1 tune)

The plaintext firmware is ~1 MB (1048576), but the cipher body is only 811961 →
the transform is **NOT length-preserving** (~231 KB smaller). Yet the payload
contains exact periodic runs (571 B period-18, 386 B period-2), which compressed
data never has. Reconciled by a **two-stage** format:

1. **Stage 1 — packing**: blank regions (likely `0xFF`) of the 1 MB image are
   omitted / run-length packed → a packed stream `P'` of ~811961 bytes.
   (1048576 − 811961 = 236615 ≈ plausible blank content of an ME7/MED9 image.)
2. **Stage 2 — cipher**: a position-aligned scramble on `P'` (the periodic leak
   runs come from near-constant regions of `P'`).

Reference will be the **plaintext of THIS file** (1K0907115S), pairing with the
ciphertext we already have. Because lengths differ, `derive` first reverses the
packing (`analyze_packing` / `try_reconstruct_packed`) to rebuild `P'`, then
extracts the cipher keystream from `C ⊕ P'`. If Stage 1 turns out to be RLE/LZ
rather than plain blank-strip, we need the region/packing map.

## Statistical profile of the body

- Entropy ≈ **7.995 bits/byte**, all 256 byte values present → strong scrambling.
- Self-coincidence peaks at **period 18** and its multiples (36, 54, 72, 108) →
  18 bytes is a genuine structural period of the transform.

## Constant-plaintext "leak" regions

Where the underlying firmware is constant/blank, the ciphertext becomes periodic
and leaks keystream structure:

| Body offset | Length | Period | Repeating unit |
|-------------|--------|--------|----------------|
| `0x94`   | 571 | 18 | `2851a3478e1d3a75ebd7ae5cb871e2c58a14` |
| `0xb9112` | 386 | 2 | `ae51` |
| `0xc6325` | 89  | 2 | `55aa` |

Notes:
- The 18-byte unit has a self-similar shift structure: `u[i+1] ≈ (u[i] << 1) | bit`,
  and it cycles back after 18 bytes → an **LFSR / rotate-with-feedback** signature.
- `ae51 = 55aa ⊕ fbfb` — the two period-2 regions are related, consistent with the
  same blank constant seen at different keystream phases/positions.
- The tail `55aa…` fill may be literal post-encryption padding (would explain the
  odd length).

## Hypotheses ruled OUT (ciphertext-only)

- **Simple repeating-XOR key** (any period, incl. 18): decrypting the whole body
  with the 18-byte unit yields only ~0.9% `00`/`FF` bytes — a real firmware decrypt
  would expose large blank regions. Rejected.
- **Per-byte substitution (single S-box)**: constant plaintext would map to a
  *constant* byte, but we observe *periodic* output. Rejected.
- **ECB block cipher** (block 4/6/8/9/16/18/32): a firmware with blank regions would
  produce thousands of duplicate ciphertext blocks; we see almost none. Rejected.

## Leading hypotheses (need known-plaintext to confirm)

1. **Stream cipher** — body = firmware ⊕ keystream, where keystream is a
   position-dependent PRNG (LFSR / counter). The 18-byte period and byte-shift
   signature fit a custom PRNG. If the keystream depends only on position, one
   reference tune yields a **universal** decryptor.
2. **Chaining block cipher** (CBC/CFB) — would also give high entropy and destroy
   block repetition. Distinguishable from (1) because its "keystream" (C ⊕ P)
   would depend on plaintext, not just position.

## What the reference tune resolves

Given the real firmware `P` for this ECU, aligned with the cipher body `C`:

- Compute `K = C ⊕ P`.
- If `K` is position-only (same across regions / another NOREAD file) → **XOR stream
  cipher**, and `K` (or its generator) is the whole decryptor.
- If `K` varies with `P` → chaining/block cipher; analyze the round function next.

Run: `python3 noread.py derive 1K0907115S.Bin <reference.bin> -o keystream.bin`

## Requirement

Decryption must **preserve the NOREAD marker** (the 32-byte header) in the output —
we recover the payload but keep the container tag. `noread.py decrypt` keeps the
header by default.
