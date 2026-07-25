# Changelog

## 1.0.0 — 2026-07-25
Initial release. Command-line decryptor for the MPPS "NOREAD" tune format.

- `decrypt` — NOREAD `.Bin` → raw firmware (strip 31-byte marker, XOR `0x55`/`0xAA`,
  zlib-inflate). Supports multiple input files.
- `encrypt` — inverse transform, for round-trip testing.
- `analyze` — inspect / validate a NOREAD file.
- Pure Python standard library, no dependencies. Meaningful exit codes.

Algorithm recovered by reverse-engineering MPPS (Obsidium-protected `Mpps.exe`);
see `FINDINGS.md`. The ECU-internal NOREAD flag is preserved.

### Next
- Standalone GUI executable (PyInstaller).
