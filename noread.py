#!/usr/bin/env python3
"""
noread.py - Decryptor for the MPPS "NOREAD" encrypted tune format.

SOLVED. The algorithm was recovered by unpacking MPPS's Obsidium-protected
Mpps.exe (classic 32-bit Wine defeats the packer's anti-VM check) and reversing
the NOREAD read routine (FUN_0041a068) and its transform (FUN_00410374):

  NOREAD file  =  marker  ||  XOR55AA( zlib_deflate( firmware ) )

    * marker : 31 ASCII bytes  "No read file has been encrypted"
               (MPPS locates the payload by searching the first 128 bytes for the
                signature "encrypted"/"encryted"; payload = end of that word)
    * XOR55AA: a[i] ^= (0x55 if i even else 0xAA)   # alternating keystream
    * then a standard zlib (78 9c) stream, inflated to the raw firmware.

Decryption therefore = strip marker -> XOR 0x55/0xAA -> zlib-inflate.

We do NOT touch the firmware bytes, so the ECU-internal NOREAD flag is preserved
(removing it would corrupt checksums -- out of scope here).

Usage:
    python3 noread.py decrypt  INPUT.Bin [-o OUT.bin]
    python3 noread.py encrypt  FIRMWARE.bin [-o OUT.Bin]   # inverse, for testing
    python3 noread.py analyze  FILE
"""

import argparse
import sys
import zlib

MARKER = b"No read file has been encrypted"          # 31 bytes
SIGNATURES = (b"encrypted", b"encryted")             # MPPS payload-locator words


def xor55aa(buf):
    """a[i] ^= 0x55 (even i) / 0xAA (odd i) -- self-inverse."""
    return bytes(b ^ (0x55 if (i & 1) == 0 else 0xAA) for i, b in enumerate(buf))


def find_payload_start(data):
    """Mirror MPPS: find 'encrypted'/'encryted' in the first 128 bytes; the payload
    begins immediately after that word."""
    head = data[:128]
    for sig in SIGNATURES:
        p = head.find(sig)
        if p >= 0:
            return p + len(sig)
    if data[:len(MARKER)] == MARKER:
        return len(MARKER)
    return None


# --------------------------------------------------------------------------- #
def cmd_decrypt(args):
    data = open(args.input, "rb").read()
    start = find_payload_start(data)
    if start is None:
        print("[!] not a NOREAD file (no marker / 'encrypted' signature found)",
              file=sys.stderr)
        sys.exit(2)
    payload = xor55aa(data[start:])
    if payload[:2] != b"\x78\x9c":
        print(f"[!] warning: expected zlib header 78 9c, got {payload[:2].hex()} "
              "-- decrypting anyway", file=sys.stderr)
    try:
        firmware = zlib.decompress(payload)
    except zlib.error as e:
        print(f"[!] zlib inflate failed: {e}", file=sys.stderr)
        sys.exit(3)
    out = args.output or (args.input.rsplit(".", 1)[0] + ".decrypted.bin")
    open(out, "wb").write(firmware)
    print(f"[+] decrypted -> {out}")
    print(f"    payload offset {start}, firmware {len(firmware)} bytes")
    print("    (ECU-internal NOREAD flag left intact)")


def cmd_encrypt(args):
    """Inverse transform (compress -> XOR -> prepend marker). Note: zlib output is
    not guaranteed byte-identical to MPPS's, so this is for round-trip testing, not
    for reproducing an exact original file."""
    fw = open(args.input, "rb").read()
    payload = xor55aa(zlib.compress(fw, args.level))
    out = args.output or (args.input.rsplit(".", 1)[0] + ".NOREAD.Bin")
    with open(out, "wb") as f:
        f.write(MARKER)
        f.write(payload)
    print(f"[+] encrypted -> {out} ({len(MARKER) + len(payload)} bytes)")


def cmd_analyze(args):
    data = open(args.file, "rb").read()
    start = find_payload_start(data)
    print(f"file          : {args.file} ({len(data)} bytes)")
    print(f"marker        : {data[:len(MARKER)]!r}"
          f" {'(NOREAD)' if data[:len(MARKER)] == MARKER else ''}")
    print(f"payload start : {start}")
    if start is not None:
        payload = xor55aa(data[start:])
        print(f"XOR55AA[:4]   : {payload[:4].hex()} "
              f"{'(zlib 78 9c OK)' if payload[:2] == b'\x78\x9c' else '(NOT zlib!)'}")
        try:
            fw = zlib.decompress(payload)
            print(f"inflates to   : {len(fw)} bytes  "
                  f"(0xFF blanks: {fw.count(0xff)})")
        except zlib.error as e:
            print(f"inflate       : FAILED ({e})")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="NOREAD .Bin -> raw firmware")
    d.add_argument("input")
    d.add_argument("-o", "--output")
    d.set_defaults(func=cmd_decrypt)

    e = sub.add_parser("encrypt", help="raw firmware -> NOREAD .Bin (testing)")
    e.add_argument("input")
    e.add_argument("-o", "--output")
    e.add_argument("--level", type=int, default=9)
    e.set_defaults(func=cmd_encrypt)

    a = sub.add_parser("analyze", help="inspect a NOREAD file")
    a.add_argument("file")
    a.set_defaults(func=cmd_analyze)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
