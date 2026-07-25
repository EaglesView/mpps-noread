#!/usr/bin/env python3
"""
noread.py - Decryptor / analysis toolkit for the MPPS "NOREAD" encrypted tune format.

Background
----------
Older MPPS (and compatible) ECU flashing software, when performing a protected
("no read") read, produces a .Bin whose payload is scrambled and whose first
32 bytes are the ASCII marker:

    "No read file has been encrypted-"

The goal of this tool is to recover the plaintext firmware from such a file
WITHOUT stripping the NOREAD marker (the marker/container is preserved so the
file stays valid for the tool chain).

Status
------
Ciphertext-only analysis (see FINDINGS.md) established the container layout and
that the payload uses a position-dependent transform with an 18-byte structural
period (not a trivial repeating XOR / ECB / per-byte substitution). To pin the
*exact* transform we need one aligned known-plaintext pair (a "reference tune":
the same ECU's real firmware). Given that, `derive` reconstructs the transform;
`decrypt` then applies it.

Usage
-----
    python3 noread.py analyze  FILE
    python3 noread.py derive   ENCRYPTED_FILE  REFERENCE_PLAINTEXT  [-o keystream.bin]
    python3 noread.py decrypt  ENCRYPTED_FILE  [--keystream keystream.bin] [-o out.bin]
                               [--strip-header]
"""

import argparse
import collections
import math
import sys

HEADER = b"No read file has been encrypted-"   # exactly 32 bytes
HEADER_LEN = len(HEADER)


# --------------------------------------------------------------------------- #
# container helpers
# --------------------------------------------------------------------------- #
def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def split_container(data):
    """Return (header, body). Header is the 32-byte NOREAD marker if present."""
    if data[:HEADER_LEN] == HEADER:
        return data[:HEADER_LEN], data[HEADER_LEN:]
    # Not a NOREAD container (e.g. a plain reference tune): no header.
    return b"", data


def entropy(buf):
    if not buf:
        return 0.0
    c = collections.Counter(buf)
    n = len(buf)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def cmd_analyze(args):
    data = read_file(args.file)
    header, body = split_container(data)
    print(f"file            : {args.file}")
    print(f"total size      : {len(data)} bytes ({len(data):#x})")
    print(f"NOREAD header   : {'yes' if header else 'no'}"
          + (f"  ({header!r})" if header else ""))
    print(f"body size       : {len(body)} bytes ({len(body):#x})"
          f"  {'ODD' if len(body) & 1 else 'even'}")
    print(f"body entropy    : {entropy(body):.4f} bits/byte")
    print(f"distinct bytes  : {len(set(body))}")

    # dominant self-coincidence period (Kasiski-style)
    n = len(body)
    scores = []
    for p in range(1, min(600, n // 2)):
        m = sum(1 for i in range(0, n - p, 7) if body[i] == body[i + p])
        scores.append((m, p))
    scores.sort(reverse=True)
    print("top periods (self-coincidence, sampled):")
    for m, p in scores[:8]:
        print(f"    period {p:4d}  score {m}")

    # find exactly-periodic runs (constant-plaintext windows leak the keystream)
    print("periodic runs (>= 64 bytes, period <= 32):")
    runs = find_periodic_runs(body, min_len=64, max_period=32)
    for start, length, period, unit in runs[:12]:
        off = start + len(header)
        print(f"    {off:#08x} len={length:6d} period={period:2d} "
              f"unit={unit[:period].hex()}")
    if not runs:
        print("    (none)")


def find_periodic_runs(buf, min_len=64, max_period=32):
    """Locate maximal runs where buf[i] == buf[i+period]."""
    runs = []
    n = len(buf)
    i = 0
    while i < n:
        best = None
        for p in range(1, max_period + 1):
            j = i
            while j + p < n and buf[j] == buf[j + p]:
                j += 1
            run_len = (j - i) + p if j > i else 0
            if run_len >= min_len and (best is None or run_len > best[0]):
                best = (run_len, p)
        if best:
            run_len, p = best
            runs.append((i, run_len, p, bytes(buf[i:i + p])))
            i += run_len
        else:
            i += 1
    runs.sort(key=lambda r: -r[1])
    return runs


# --------------------------------------------------------------------------- #
# stage 1: packing analysis (why cipher is shorter than plaintext)
# --------------------------------------------------------------------------- #
def strip_fill_runs(buf, fill, min_run=1):
    """Remove maximal runs (>= min_run) of `fill` byte. Returns (packed, kept_mask)."""
    out = bytearray()
    n = len(buf)
    i = 0
    while i < n:
        if buf[i] == fill:
            j = i
            while j < n and buf[j] == fill:
                j += 1
            if j - i >= min_run:
                i = j
                continue
        out.append(buf[i])
        i += 1
    return bytes(out)


def analyze_packing(pbody, cbody):
    """Report how the plaintext size could shrink to the cipher size."""
    gap = len(pbody) - len(cbody)
    print(f"    size gap plaintext-cipher : {gap} bytes")
    c = collections.Counter(pbody)
    # which single fill byte, if run-stripped, best explains the gap?
    print("    blank-byte census in plaintext (candidate Stage-1 fill):")
    for b, _ in c.most_common(4):
        cnt = c[b]
        for mr in (1, 2, 8):
            packed_len = len(strip_fill_runs(pbody, b, min_run=mr))
            if abs((len(pbody) - packed_len) - gap) < 64 or mr == 1:
                print(f"      fill={b:#04x} count={cnt:7d}  strip(min_run={mr}) "
                      f"-> packed_len={packed_len}  (target {len(cbody)}, "
                      f"delta {packed_len - len(cbody):+d})")


def try_reconstruct_packed(pbody, cbody, args):
    """Attempt to rebuild the packed plaintext stream matching the cipher length.

    Tries stripping runs of each common blank byte; if one yields a length that
    matches the cipher (within a small header tolerance), returns it. Otherwise
    returns None so the caller can stop before the cipher stage.
    """
    if args.fill is not None:
        packed = strip_fill_runs(pbody, args.fill, min_run=args.min_run)
        print(f"    [manual] fill={args.fill:#04x} min_run={args.min_run} "
              f"-> {len(packed)} bytes")
        return packed if len(packed) == len(cbody) else packed
    c = collections.Counter(pbody)
    for b, _ in c.most_common(6):
        for mr in (1, 2, 3, 4, 8, 16):
            packed = strip_fill_runs(pbody, b, min_run=mr)
            if len(packed) == len(cbody):
                print(f"    [auto] exact packed match: fill={b:#04x} "
                      f"min_run={mr} -> {len(packed)} bytes")
                return packed
    print("    [auto] no exact blank-strip length matched the cipher.")
    print("          Stage-1 may use RLE/tokens or LZ compression, or the")
    print("          plaintext isn't the raw 1MB image. Options: pass --fill/--min-run,")
    print("          or provide the packing/region map.")
    return None


# --------------------------------------------------------------------------- #
# derive  (needs a known-plaintext reference)
# --------------------------------------------------------------------------- #
def cmd_derive(args):
    enc = read_file(args.encrypted)
    ref = read_file(args.reference)
    _, cbody = split_container(enc)
    _, pbody = split_container(ref)  # a plain reference has no header

    print(f"cipher body         : {len(cbody)} bytes")
    print(f"reference plaintext : {len(pbody)} bytes")

    if len(cbody) != len(pbody):
        print()
        print("[!] length mismatch -> NOREAD is NOT length-preserving.")
        print("    Investigating Stage-1 packing (blank-region removal) before")
        print("    deriving the Stage-2 cipher.\n")
        analyze_packing(pbody, cbody)
        pbody = try_reconstruct_packed(pbody, cbody, args)
        if pbody is None:
            print("[!] Could not auto-reconstruct the packed stream. Stopping before")
            print("    the cipher stage. See notes above; we may need the packing map.")
            return
    n = min(len(cbody), len(pbody))

    # Hypothesis 1: XOR stream cipher.  keystream = cipher ^ plain.
    ks = bytes(cbody[i] ^ pbody[i] for i in range(n))
    print("=== XOR-stream hypothesis ===")
    print(f"aligned length      : {n}")
    print(f"keystream entropy   : {entropy(ks):.4f} bits/byte")

    # Is the keystream position-only (universal) or plaintext-dependent?
    # Test: within the derived keystream, do equal *plaintext* bytes at different
    # positions with equal position-structure yield a consistent keystream?
    # Simple universality probe: keystream should be independent of plaintext, so
    # a repeating-key check reveals the true period if one exists.
    period = detect_keystream_period(ks)
    period_desc = str(period) if period else "none < 4096 (likely a long PRNG / counter stream)"
    print(f"keystream period    : {period_desc}")

    # Report byte-transition regularity (LFSR/PRNG signature).
    report_transition_regularity(ks)

    out = args.output or "keystream.bin"
    with open(out, "wb") as f:
        f.write(ks)
    print(f"[+] wrote derived keystream -> {out} ({len(ks)} bytes)")
    print("    Next: `decrypt --keystream keystream.bin` on the same or another "
          "NOREAD file to validate universality.")


def detect_keystream_period(ks, max_period=4096):
    n = len(ks)
    for p in range(1, min(max_period, n // 2)):
        if all(ks[i] == ks[i + p] for i in range(0, n - p, max(1, (n - p) // 512))):
            # verify fully
            if all(ks[i] == ks[i % p] for i in range(n)):
                return p
    return None


def report_transition_regularity(ks):
    """Check whether ks[i+1] is a fixed function of ks[i] (byte PRNG signature)."""
    fmap = {}
    consistent = 0
    total = 0
    for i in range(len(ks) - 1):
        a, b = ks[i], ks[i + 1]
        total += 1
        if a in fmap:
            if fmap[a] == b:
                consistent += 1
        else:
            fmap[a] = b
            consistent += 1
    print(f"byte-transition map : {consistent}/{total} consistent "
          f"({consistent/max(1,total):.3f}) "
          f"-> {'looks like a byte-state PRNG' if consistent/max(1,total) > 0.95 else 'not a simple byte-state PRNG'}")


# --------------------------------------------------------------------------- #
# decrypt
# --------------------------------------------------------------------------- #
def cmd_decrypt(args):
    enc = read_file(args.encrypted)
    header, body = split_container(enc)

    if not args.keystream:
        print("[!] No keystream supplied. The exact transform is only known once "
              "derived from a reference tune:", file=sys.stderr)
        print("    python3 noread.py derive <encrypted> <reference> -o keystream.bin",
              file=sys.stderr)
        sys.exit(2)

    ks = read_file(args.keystream)
    if len(ks) < len(body):
        print(f"[!] keystream ({len(ks)}) shorter than body ({len(body)}); "
              "it will be tiled (only valid if the keystream is truly periodic).",
              file=sys.stderr)
    plain = bytes(body[i] ^ ks[i % len(ks)] for i in range(len(body)))

    out = args.output or (args.encrypted + ".dec")
    with open(out, "wb") as f:
        if not args.strip_header:
            f.write(header)          # preserve the NOREAD marker by default
        f.write(plain)
    kept = "stripped" if args.strip_header else "kept"
    print(f"[+] decrypted -> {out}  (NOREAD header {kept}, body {len(plain)} bytes)")
    print(f"    decrypted body entropy: {entropy(plain):.4f} bits/byte "
          f"(expect << 8 for real firmware)")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="inspect a NOREAD (or plain) file")
    a.add_argument("file")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("derive", help="derive the transform from a known-plaintext reference")
    d.add_argument("encrypted")
    d.add_argument("reference")
    d.add_argument("-o", "--output")
    d.add_argument("--fill", type=lambda x: int(x, 0), default=None,
                   help="Stage-1 blank fill byte to strip (e.g. 0xff)")
    d.add_argument("--min-run", type=int, default=1,
                   help="min run length of the fill byte to strip (default 1)")
    d.set_defaults(func=cmd_derive)

    c = sub.add_parser("decrypt", help="decrypt a NOREAD file using a derived keystream")
    c.add_argument("encrypted")
    c.add_argument("--keystream")
    c.add_argument("-o", "--output")
    c.add_argument("--strip-header", action="store_true",
                   help="also remove the NOREAD marker (default: keep it)")
    c.set_defaults(func=cmd_decrypt)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
