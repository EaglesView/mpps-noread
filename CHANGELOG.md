# Changelog

## 1.1.0 — 2026-07-25
Added a simple desktop GUI and cross-platform standalone binaries.

- `noread_gui.py` — minimal PySide6 window: **Open file** or **Open folder**, a
  red/green indicator showing whether the selection is a valid NOREAD file, a
  recursive-subfolder option with a live count of valid files, a destination
  folder (defaults to the executable's directory), and a **Decrypt** button.
  Wraps the existing `noread.decrypt_bytes` path; core CLI unchanged and still
  dependency-free.
- PyInstaller spec (`noread.spec`) producing a single windowed executable
  (`.app` bundle on macOS).
- GitHub Actions workflow builds macOS, Windows, and Linux binaries on tag push
  and attaches them (with SHA256 checksums and the changelog notes) to the
  GitHub Release.

## 1.0.0 — 2026-07-25
Initial release. Command-line decryptor for the MPPS "NOREAD" tune format.

- `decrypt` — NOREAD `.Bin` → raw firmware (strip 31-byte marker, XOR `0x55`/`0xAA`,
  zlib-inflate). Supports multiple input files.
- `encrypt` — inverse transform, for round-trip testing.
- `analyze` — inspect / validate a NOREAD file.
- Pure Python standard library, no dependencies. Meaningful exit codes.

Algorithm recovered by reverse-engineering MPPS (Obsidium-protected `Mpps.exe`);
see `FINDINGS.md`. The ECU-internal NOREAD flag is preserved.
