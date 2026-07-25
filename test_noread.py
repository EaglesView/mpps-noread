#!/usr/bin/env python3
"""Self-contained tests for noread.py (no real ECU files needed).

Run:  python3 test_noread.py     (or: pytest test_noread.py)
"""
import zlib

import noread


def test_xor_is_self_inverse():
    data = bytes(range(256)) * 3
    assert noread.xor55aa(noread.xor55aa(data)) == data


def test_keystream_pattern():
    assert noread.xor55aa(b"\x00\x00\x00\x00") == b"\x55\xaa\x55\xaa"


def test_find_payload_start():
    blob = noread.MARKER + b"\x78\x9c" + b"rest"
    assert noread.find_payload_start(blob) == len(noread.MARKER)
    assert noread.find_payload_start(b"not a noread file at all") is None


def test_roundtrip():
    firmware = bytes((i * 7) & 0xFF for i in range(50000))
    container = noread.encrypt_bytes(firmware)
    assert container[:len(noread.MARKER)] == noread.MARKER
    recovered, start, magic = noread.decrypt_bytes(container)
    assert recovered == firmware
    assert start == len(noread.MARKER)
    assert magic == b"\x78\xda"          # zlib level-9 header (also accepted)


def test_decrypt_rejects_non_noread():
    try:
        noread.decrypt_bytes(b"random bytes, definitely not noread")
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-NOREAD input")


def test_real_zlib_magic_payload():
    # a payload produced with default zlib compression starts 78 9c
    payload = zlib.compress(b"hello world" * 100)  # default level -> 78 9c
    container = noread.MARKER + noread.xor55aa(payload)
    recovered, _, magic = noread.decrypt_bytes(container)
    assert magic == b"\x78\x9c"
    assert recovered == b"hello world" * 100


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    _run()
