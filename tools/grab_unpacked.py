#!/usr/bin/env python3
"""
grab_unpacked.py - Dump an Obsidium-unpacked Windows module from a live Wine process.

Finds the Wine process that has the given PE *mapped* (robust: does NOT match on
command line, so it won't grab this script by mistake), then dumps the module's
in-memory span (unpacked code) plus every other readable region, and reports where
the 'No read file has been encrypted' marker sits.

Run it WHILE the anti-VM dialog is on screen (process alive + already unpacked):

    python3 tools/grab_unpacked.py Mpps.exe

Then import the base module dump into Ghidra as Raw Binary at the printed base.
"""
import glob, os, re, struct, sys

MARKER = b"No read file has been encrypted"


def find_processes_with_mapped(name):
    out = []
    for mp in glob.glob('/proc/[0-9]*/maps'):
        pid = mp.split('/')[2]
        try:
            with open(mp) as f:
                data = f.read()
        except OSError:
            continue
        if name.lower() in data.lower():
            out.append((int(pid), data))
    return out


def read_mem(pid, start, size):
    try:
        with open(f'/proc/{pid}/mem', 'rb', 0) as mem:
            mem.seek(start)
            return mem.read(size)
    except (OSError, ValueError):
        return b''


def main():
    if len(sys.argv) < 2:
        print("usage: grab_unpacked.py <ExeName.exe> [out_prefix]")
        sys.exit(1)
    name = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 else name.rsplit('.', 1)[0] + "_unpacked"

    procs = find_processes_with_mapped(name)
    if not procs:
        print(f"[!] no live process has '{name}' mapped. Launch it under wine32 "
              f"and run this WHILE the VM dialog is open.")
        sys.exit(2)

    pid, maps = procs[0]
    print(f"[+] pid {pid} has {name} mapped")

    # module regions backed by the PE
    mod = []
    for line in maps.splitlines():
        if name.lower() in line.lower():
            m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)', line)
            if m:
                mod.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    if not mod:
        print("[!] PE named in maps but no address range parsed")
        sys.exit(3)
    base = min(s for s, _, _ in mod)
    top = max(e for _, e, _ in mod)
    for s, e, p in mod:
        print(f"    {s:#012x}-{e:#012x} {p}")
    blob = read_mem(pid, base, top - base)
    open(f"{prefix}_module.bin", "wb").write(blob)
    at = blob.find(MARKER)
    print(f"[+] wrote {prefix}_module.bin  base={base:#x}  size={len(blob)}")
    print(f"    marker in module: {hex(at) if at >= 0 else 'NOT (string may be runtime-decrypted)'}")

    # also scan ALL readable regions for the marker (may live on heap)
    hits = []
    for line in maps.splitlines():
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+(r\S+)', line)
        if not m:
            continue
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        if e - s > 64 * 1024 * 1024:   # skip giant reserve regions
            continue
        data = read_mem(pid, s, e - s)
        off = data.find(MARKER)
        if off >= 0:
            fn = f"{prefix}_region_{s:012x}.bin"
            open(fn, "wb").write(data)
            hits.append((fn, s, off))
    if hits:
        print("[+] marker also present in:")
        for fn, s, off in hits:
            print(f"    {fn} base={s:#x} +{off:#x}")
    print(f"\nGhidra: import {prefix}_module.bin as Raw Binary, x86:LE:32, base {base:#x}")


if __name__ == "__main__":
    main()
