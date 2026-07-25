# tuneman — MPPS NOREAD decryptor

Toolkit to recover plaintext ECU firmware from the MPPS "NOREAD" encrypted `.Bin`
format (files beginning with `No read file has been encrypted-`), **without**
removing the NOREAD marker.

## Commands

```bash
# 1. Inspect a file (container layout, entropy, periodic leak regions)
python3 noread.py analyze 1K0907115S.Bin

# 2. Once you have a reference tune (the real firmware for the same ECU),
#    derive the transform from the known-plaintext pair:
python3 noread.py derive 1K0907115S.Bin reference.bin -o keystream.bin

# 3. Decrypt (keeps the 32-byte NOREAD header by default):
python3 noread.py decrypt 1K0907115S.Bin --keystream keystream.bin -o out.bin
```

## Status

Container format and payload structure are characterized (see `FINDINGS.md`).
The exact payload transform is pinned once a single aligned reference tune is
supplied — `derive` tests the XOR-stream hypothesis and reports whether the
keystream is position-only (→ universal decryptor) or plaintext-dependent
(→ chaining/block cipher, needs further work).

## Reference tune requirements

For `derive` to work, the reference should be the **raw firmware for the same
ECU** (`1K0907115S`), same length as the cipher payload (811961 bytes) and byte
-aligned to it. If it differs (e.g. an `.frf`/flash-container or a different
region size), tell me and we'll handle alignment/offset first.
