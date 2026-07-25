#!/usr/bin/env python3
"""
dump_wine_module.py - Dump the in-memory (unpacked) image of a Wine process module.

Use this to unpack a self-unpacking Windows exe on Linux without a VM:
  1. Run it under Wine and wait until it has fully unpacked (main window shown):
         wine "Tricore Boot.exe" &
  2. Find the PID:
         pgrep -af -i tricore        # or:  ps aux | grep -i tricore
  3. Dump the module's memory image:
         python3 tools/dump_wine_module.py <PID> --name tricore -o tricore_dump.bin
  4. Note the printed BASE address, then in Ghidra:
         File -> Import -> tricore_dump.bin
         Format: Raw Binary   Language: x86:LE:32:default (or Visual Studio/gcc)
         Options -> Base Address: <BASE>   (e.g. 0x400000)
     Run auto-analysis. The 'No read file has been encrypted-' string and the
     real functions should now be present.

Notes
-----
* Reading /proc/<pid>/mem may require ptrace access. If you get PermissionError,
  either run the target from the same shell (so it's your descendant) or set:
      echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
* Self-unpacking-in-place packers restore code at the original section VAs, so
  dumping the whole module span captures the unpacked code. If the marker string
  still doesn't appear, the packer unpacked into a fresh region: re-run with
  --anon to also include large executable anonymous mappings.
"""

import argparse
import re
import sys

MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$"
)


def parse_maps(pid):
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            m = MAPS_RE.match(line.strip())
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            perms = m.group(3)
            path = m.group(4) or ""
            regions.append((start, end, perms, path))
    return regions


def read_mem(pid, start, end):
    """Read [start,end) from /proc/pid/mem; return bytes (zero-filled on error)."""
    size = end - start
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as mem:
            mem.seek(start)
            data = mem.read(size)
            if len(data) < size:
                data += b"\x00" * (size - len(data))
            return data
    except (OSError, ValueError):
        return b"\x00" * size


def dump_all(pid, regions, out_prefix):
    """Dump every readable region; scan each for the NOREAD marker + real strings.

    Intended to run WHILE the target is paused (e.g. an anti-VM dialog is on
    screen) so any unpacked code/data is still mapped.
    """
    marker = b"No read file has been encrypted"
    prefix = out_prefix.rsplit(".", 1)[0]
    hits = []
    total = 0
    for start, end, perms, path in regions:
        if "r" not in perms:
            continue
        data = read_mem(pid, start, end)
        total += len(data)
        nz = len(data) - data.count(0)
        if nz == 0:
            continue
        fn = f"{prefix}_{start:012x}.bin"
        with open(fn, "wb") as f:
            f.write(data)
        note = ""
        at = data.find(marker)
        if at >= 0:
            note = f"  *** MARKER at +{at:#x} ***"
            hits.append((fn, start))
        print(f"  {start:#012x}-{end:#012x} {perms} {len(data):8d}B "
              f"{path[:32]:32s}{note}")
    print(f"\ndumped ~{total} bytes across readable regions")
    if hits:
        print("[+] NOREAD marker found in:")
        for fn, s in hits:
            print(f"    {fn} (base {s:#x})  <-- unpacked! import this into Ghidra")
    else:
        print("[!] marker NOT in any region -> the VM check runs BEFORE Obsidium "
              "unpacks. We'll need to defeat the Wine detection instead.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pid", type=int)
    ap.add_argument("--name", default=None,
                    help="substring of the module path to select (e.g. 'tricore')")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=None,
                    help="explicit base address; dumps the region containing it")
    ap.add_argument("--anon", action="store_true",
                    help="also include large executable anonymous mappings")
    ap.add_argument("--all", action="store_true",
                    help="dump EVERY readable region to <output>_<addr>.bin and "
                         "scan each for the NOREAD marker (best while a dialog is open)")
    ap.add_argument("-o", "--output", default="module_dump.bin")
    args = ap.parse_args()

    regions = parse_maps(args.pid)
    if not regions:
        print("no regions parsed (bad PID?)", file=sys.stderr)
        sys.exit(1)

    if args.all:
        dump_all(args.pid, regions, args.output)
        return

    # select the target regions
    sel = []
    if args.base is not None:
        for r in regions:
            if r[0] <= args.base < r[1]:
                sel.append(r)
    if args.name:
        nl = args.name.lower()
        sel += [r for r in regions if nl in r[3].lower()]
    if args.anon:
        for r in regions:
            if "x" in r[2] and not r[3] and (r[1] - r[0]) >= 0x10000:
                sel.append(r)
    if not sel:
        print("No matching regions. Here are the executable/module maps:\n",
              file=sys.stderr)
        for s, e, p, path in regions:
            if "x" in p or path.lower().endswith((".exe", ".dll")):
                print(f"  {s:#012x}-{e:#012x} {p} {path}", file=sys.stderr)
        sys.exit(2)

    base = min(r[0] for r in sel)
    top = max(r[1] for r in sel)
    print(f"selected {len(set(sel))} region(s)")
    for s, e, p, path in sorted(set(sel)):
        print(f"  {s:#012x}-{e:#012x} {p} {path}")
    print(f"dumping span {base:#x}..{top:#x} ({top - base} bytes)")

    data = read_mem(args.pid, base, top)
    with open(args.output, "wb") as f:
        f.write(data)

    # quick self-check for the NOREAD marker
    marker = b"No read file has been encrypted"
    at = data.find(marker)
    print(f"[+] wrote {args.output} ({len(data)} bytes)")
    print(f"    Ghidra Raw Binary base address: {base:#x}")
    print(f"    marker '{marker.decode()}' {'FOUND at +%#x' % at if at >= 0 else 'NOT found (try --anon)'}")


if __name__ == "__main__":
    main()
