# tuneman — MPPS NOREAD decryptor (SOLVED)

Decrypts the MPPS "NOREAD" encrypted ECU read (`No read file has been encrypted…`)
back to the raw firmware, **without** modifying the ECU-internal NOREAD flag.

## Algorithm

```
NOREAD file = marker(31B) || XOR55AA( zlib_deflate( firmware ) )

  marker  : "No read file has been encrypted"  (payload located via the
            "encrypted"/"encryted" signature in the first 128 bytes)
  XOR55AA : byte[i] ^= 0x55 if i even else 0xAA   (alternating, self-inverse)
  then a standard zlib (78 9c) stream.

decrypt = drop marker  ->  XOR 0x55/0xAA  ->  zlib-inflate
```

Recovered by unpacking MPPS's Obsidium-protected `Mpps.exe` (classic 32-bit Wine
defeats the packer's anti-VM TLS check) and reversing the NOREAD read routine
`FUN_0041a068` + transform `FUN_00410374`. See `FINDINGS.md` for the full trail.

## Usage

```bash
python3 noread.py decrypt 1K0907115S.Bin -o firmware.bin   # NOREAD -> raw firmware
python3 noread.py analyze 1K0907115S.Bin                   # inspect
python3 noread.py encrypt firmware.bin -o out.Bin          # inverse (testing)
```

Verified on `1K0907115S.Bin`: decrypts to 2,097,152 bytes (2 MB MED9.1 image,
entropy 5.91, 423,877 `0xFF` blank bytes) containing the part number `1K0907115`
and `MED9` strings.

## Notes

- The firmware's internal NOREAD flag is left untouched (clearing it corrupts
  checksums; out of scope).
- `encrypt` uses stock zlib, so it won't reproduce a byte-identical original
  (compressor differs), but decrypt/round-trip is exact.
```
