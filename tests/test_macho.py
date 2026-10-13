from __future__ import annotations

from ios_re_agent.macho import inspect_macho
from tests.helpers import make_macho


def test_parses_thin_macho_load_commands() -> None:
    result = inspect_macho(make_macho())
    assert result["format"] == "thin_macho"
    assert len(result["slices"]) == 1
    image = result["slices"][0]
    assert image["architecture"] == "arm64"
    assert image["file_type"] == "executable"
    assert image["platform"] == "iOS"
    assert image["minimum_os"] == "14.0.0"
    assert "/usr/lib/libSystem.B.dylib" in image["linked_libraries"]
    assert image["encrypted_flag_set"] is None


def test_detects_encryption_flag_without_attempting_to_decrypt() -> None:
    image = inspect_macho(make_macho(encrypted=True))["slices"][0]
    assert image["encrypted_flag_set"] is True


def test_unknown_binary_is_reported_as_unknown() -> None:
    result = inspect_macho(b"not a Mach-O binary")
    assert result["format"] == "unknown"
    assert result["slices"] == []


def test_parses_universal_macho_architecture_table() -> None:
    import struct

    thin = make_macho()
    slice_offset = 28
    fat_header = struct.pack(">II", 0xCAFEBABE, 1)
    architecture = struct.pack(">iiIII", 0x0100000C, 0, slice_offset, len(thin), 2)
    result = inspect_macho(fat_header + architecture + thin)
    assert result["format"] == "fat_macho"
    assert result["slices"][0]["architecture"] == "arm64"


def test_handles_truncated_macho_header() -> None:
    result = inspect_macho(b"\xcf\xfa\xed\xfe" + b"\0" * 10)
    assert result["format"] == "unknown"
