# noread — MPPS NOREAD tune decryptor

> Have you ever had the idea you would start car tuning, or want to fix a broken tune, to find out the tune from the previous owner had a NOREAD flag, and your MPPS software encrypted it, making it unuseable, even after an hour long search of a decryptor tool online from 15 years ago that is now paywalled? look no further!

noread is a tool that allows you to remove the encryption that MPPS used on NOREAD tunes. this does not remove the NOREAD flag from the firmware, so the checksum remains valid.This tool should work on any
`.Bin` that begins with `No read file has been encrypted…` and whose payload is
scrambled. My dataset of testing is still very limited, and the reverse engineering was done on MPPS v18, newer versions might have different algorithms.

Command-line, pure Python standard library, **no dependencies**. GUI is coming soon in next release.

Most if not all of the reverse engineering has been done with Claude Opus 5 using (GhidraMCP by LaurieWired)[https://github.com/lauriewired/ghidramcp]. I just gave enough context & examples to get started.

```
$ python3 noread.py decrypt 1K0907115S.Bin
[+] 1K0907115S.Bin -> 1K0907115S.decrypted.bin  (2097152 bytes, payload @31)
```

## Install / run

No install needed — just run it:

```bash
python3 noread.py --help
```

Or install as a `noread` command (optional):

```bash
pip install .
noread decrypt file.Bin
```

Requires Python 3.8+.

## Usage

```bash
# Decrypt one or more NOREAD files -> raw firmware
python3 noread.py decrypt file.Bin [more.Bin ...] [-o out.bin]

# Inspect / validate a NOREAD file (size, marker, zlib check, inflated size)
python3 noread.py analyze file.Bin

# Inverse transform (firmware -> NOREAD container), for round-trip testing
python3 noread.py encrypt firmware.bin [-o out.Bin]
```

Exit codes: `0` success · `1` not a valid NOREAD file (analyze) · `2` bad
arguments · `3` I/O or decrypt error.

## How it works

```
NOREAD file = marker || XOR55AA( zlib_deflate( firmware ) )

  marker  : "No read file has been encrypted"   (payload begins right after the
            "encrypted"/"encryted" word within the first 128 bytes)
  XOR55AA : byte[i] ^= 0x55 if i is even else 0xAA   (alternating, self-inverse)
  then a standard zlib (78 9c) stream.

decrypt = strip marker -> XOR 0x55/0xAA -> zlib-inflate
```

The algorithm was recovered by reverse-engineering MPPS's Obsidium-protected
`Mpps.exe`. Full write-up in [`FINDINGS.md`](FINDINGS.md).

## Notes

- **The firmware is never modified**, so the ECU-internal NOREAD flag is preserved
  (clearing it would corrupt checksums and is intentionally out of scope).
- Verified on a Bosch **MED9.1** read (`1K0907115`, decrypts to a 2 MB image with
  the correct part number and calibration block).
- `encrypt` uses stock zlib, so it won't reproduce a byte-identical original
  (the compressor differs), but decrypt / round-trip is exact.
- For **legitimate** use — recovering your own ECU data. You are responsible for
  how you use the output; always validate checksums before writing to an ECU.

## Tests

```bash
python3 test_noread.py      # or: pytest test_noread.py
```

## Roadmap

- **1.0** — command-line tool (this release).
- **1.x** — standalone GUI executable (PyInstaller); no Python needed to run, cross-platform.
- **ideas** — pattern finder for early table detection without an `.a2l` or `.xml` file, port to web/javascript or rust WASM library.

## License

MIT — see [`LICENSE`](LICENSE).
