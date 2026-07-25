#!/usr/bin/env python3
"""
noread.py - Decryptor for the MPPS "NOREAD" encrypted ECU tune format.

An MPPS "no-read" protected read produces a .Bin that begins with the ASCII
marker "No read file has been encrypted" and whose payload is scrambled. This
tool recovers the original firmware.

Format (recovered by reverse-engineering MPPS; see FINDINGS.md):

    NOREAD file = marker || XOR55AA( zlib_deflate( firmware ) )

      marker  : "No read file has been encrypted"  (payload begins right after
                the "encrypted"/"encryted" word within the first 128 bytes)
      XOR55AA : byte[i] ^= 0x55 if i is even else 0xAA   (alternating, self-inverse)
      then a standard zlib (78 9c) stream, inflated to the raw firmware.

    decrypt = strip marker -> XOR 0x55/0xAA -> zlib-inflate

The firmware bytes are never modified, so the ECU-internal NOREAD flag is
preserved (clearing it would corrupt checksums and is out of scope).

Pure standard library. No dependencies.
"""

import argparse
import os
import sys
import zlib

__version__ = "1.1.0"

MARKER = b"No read file has been encrypted"          # 31 bytes
SIGNATURES = (b"encrypted", b"encryted")             # MPPS payload-locator words
ZLIB_MAGIC = b"\x78\x9c"


# --------------------------------------------------------------------------- #
# core transform
# --------------------------------------------------------------------------- #
def xor55aa(buf):
    """byte[i] ^= 0x55 (even i) / 0xAA (odd i). Self-inverse."""
    return bytes(b ^ (0x55 if (i & 1) == 0 else 0xAA) for i, b in enumerate(buf))


def find_payload_start(data):
    """Locate the encrypted payload the way MPPS does: search the first 128 bytes
    for 'encrypted'/'encryted'; the payload begins immediately after that word.
    Returns the byte offset, or None if this is not a NOREAD file."""
    head = data[:128]
    for sig in SIGNATURES:
        p = head.find(sig)
        if p >= 0:
            return p + len(sig)
    if data[:len(MARKER)] == MARKER:
        return len(MARKER)
    return None


def decrypt_bytes(data):
    """Decrypt NOREAD container bytes -> raw firmware bytes.
    Raises ValueError if not a NOREAD file, zlib.error if inflate fails."""
    start = find_payload_start(data)
    if start is None:
        raise ValueError("not a NOREAD file (no marker / 'encrypted' signature)")
    payload = xor55aa(data[start:])
    return zlib.decompress(payload), start, payload[:2]


def encrypt_bytes(firmware, level=9):
    """Raw firmware -> NOREAD container bytes (inverse; for testing)."""
    return MARKER + xor55aa(zlib.compress(firmware, level))


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_decrypt(args):
    if len(args.input) > 1 and args.output:
        print("[!] -o/--output cannot be used with multiple input files",
              file=sys.stderr)
        return 2
    rc = 0
    for path in args.input:
        try:
            data = _read(path)
            firmware, start, magic = decrypt_bytes(data)
        except (OSError, ValueError, zlib.error) as e:
            print(f"[!] {path}: {e}", file=sys.stderr)
            rc = 3
            continue
        if magic != ZLIB_MAGIC:
            print(f"[!] {path}: unexpected payload header {magic.hex()} "
                  "(decrypted anyway)", file=sys.stderr)
        out = args.output or _derive(path, ".decrypted.bin")
        _write(out, firmware)
        print(f"[+] {path} -> {out}  ({len(firmware)} bytes, payload @{start})")
    return rc


def cmd_encrypt(args):
    try:
        fw = _read(args.input)
    except OSError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 3
    out = args.output or _derive(args.input, ".NOREAD.Bin")
    _write(out, encrypt_bytes(fw, args.level))
    print(f"[+] {args.input} -> {out}")
    return 0


def cmd_analyze(args):
    try:
        data = _read(args.file)
    except OSError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 3
    start = find_payload_start(data)
    is_noread = data[:len(MARKER)] == MARKER
    print(f"file          : {args.file} ({len(data)} bytes)")
    print(f"marker        : {data[:len(MARKER)]!r} {'(NOREAD)' if is_noread else ''}")
    print(f"payload start : {start}")
    if start is None:
        print("verdict       : not a NOREAD file")
        return 1
    payload = xor55aa(data[start:])
    zlib_ok = payload[:2] == ZLIB_MAGIC
    print(f"xor55aa[:4]   : {payload[:4].hex()} "
          f"{'(zlib 78 9c OK)' if zlib_ok else '(NOT a zlib header!)'}")
    try:
        fw = zlib.decompress(payload)
        print(f"inflates to   : {len(fw)} bytes (0xFF blanks: {fw.count(0xff)})")
        print("verdict       : valid NOREAD file")
        return 0
    except zlib.error as e:
        print(f"inflate       : FAILED ({e})")
        print("verdict       : marker present but payload did not inflate")
        return 1


# --------------------------------------------------------------------------- #
# io helpers
# --------------------------------------------------------------------------- #
def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _derive(path, suffix):
    base = path[:-4] if path.lower().endswith(".bin") else path
    return base + suffix


# --------------------------------------------------------------------------- #
def build_parser():
    ap = argparse.ArgumentParser(
        prog="noread",
        description="MPPS NOREAD tune decryptor (%(prog)s " + __version__ + ")",
        epilog="The ECU-internal NOREAD flag is preserved; the firmware is not modified.",
    )
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="NOREAD .Bin -> raw firmware")
    d.add_argument("input", nargs="+", help="one or more NOREAD .Bin files")
    d.add_argument("-o", "--output", help="output path (single input only)")
    d.set_defaults(func=cmd_decrypt)

    e = sub.add_parser("encrypt", help="raw firmware -> NOREAD .Bin (inverse; testing)")
    e.add_argument("input")
    e.add_argument("-o", "--output")
    e.add_argument("--level", type=int, default=9, help="zlib level (default 9)")
    e.set_defaults(func=cmd_encrypt)

    a = sub.add_parser("analyze", help="inspect a NOREAD file")
    a.add_argument("file")
    a.set_defaults(func=cmd_analyze)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
