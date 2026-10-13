"""Small, dependency-free Mach-O header and load-command reader.

This module parses metadata only. It does not execute, decrypt, modify, or patch binaries.
"""

from __future__ import annotations

import struct
from typing import Any

# Magic bytes -> byte order and 64-bit header flag.
_THIN_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xce\xfa\xed\xfe": ("<", False),  # MH_MAGIC
    b"\xcf\xfa\xed\xfe": ("<", True),   # MH_MAGIC_64
    b"\xfe\xed\xfa\xce": (">", False),  # MH_CIGAM
    b"\xfe\xed\xfa\xcf": (">", True),   # MH_CIGAM_64
}
_FAT_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xca\xfe\xba\xbe": (">", False),  # FAT_MAGIC
    b"\xbe\xba\xfe\xca": ("<", False),  # FAT_CIGAM
    b"\xca\xfe\xba\xbf": (">", True),   # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca": ("<", True),   # FAT_CIGAM_64
}

_CPU_TYPES = {
    7: "i386",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}
_FILE_TYPES = {
    1: "object",
    2: "executable",
    6: "dylib",
    8: "bundle",
}
_PLATFORM = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    6: "Mac Catalyst",
    7: "iOS Simulator",
    8: "tvOS Simulator",
    9: "watchOS Simulator",
    11: "visionOS",
    12: "visionOS Simulator",
}

_LC_LOAD_DYLIB = 0x0000000C
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_LOAD_UPWARD_DYLIB = 0x80000023
_LC_LAZY_LOAD_DYLIB = 0x00000020
_LC_RPATH = 0x8000001C
_LC_BUILD_VERSION = 0x00000032
_LC_VERSION_MIN_IOS = 0x00000025
_LC_VERSION_MIN_TVOS = 0x0000002F
_LC_VERSION_MIN_WATCHOS = 0x00000030
_LC_ENCRYPTION_INFO = 0x00000021
_LC_ENCRYPTION_INFO_64 = 0x0000002C


def _cstring(data: bytes, offset: int, command_end: int) -> str | None:
    if offset < 8 or offset >= command_end:
        return None
    raw = data[offset:command_end].split(b"\0", 1)[0]
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")[:512]


def _parse_thin(data: bytes, base_offset: int = 0) -> dict[str, Any] | None:
    if len(data) < 28:
        return None
    magic = data[:4]
    if magic not in _THIN_MAGICS:
        return None
    endian, is_64 = _THIN_MAGICS[magic]
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        return None
    try:
        # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
        _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "IiiIIII", data, 0
        )
    except struct.error:
        return None

    # Refuse unreasonable counts/sizes instead of walking malformed input.
    if ncmds > 100_000 or sizeofcmds > len(data) - header_size:
        return {
            "valid_header": True,
            "parse_limited": True,
            "architecture": _CPU_TYPES.get(cputype, f"cpu_type_{cputype}"),
            "is_64_bit": is_64,
            "file_type": _FILE_TYPES.get(filetype, f"file_type_{filetype}"),
            "load_command_count": ncmds,
            "load_commands": [],
            "linked_libraries": [],
            "rpaths": [],
            "platform": None,
            "minimum_os": None,
            "encrypted_flag_set": None,
            "note": "Load commands were not parsed because header sizes were inconsistent.",
        }

    libraries: list[str] = []
    rpaths: list[str] = []
    platform: str | None = None
    min_os: str | None = None
    encryption_flag: bool | None = None
    commands_seen = 0
    offset = header_size
    commands_end = header_size + sizeofcmds

    for _ in range(ncmds):
        if offset + 8 > commands_end:
            break
        try:
            cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        except struct.error:
            break
        if cmdsize < 8 or offset + cmdsize > commands_end:
            break
        commands_seen += 1
        command_end = offset + cmdsize

        if cmd in {
            _LC_LOAD_DYLIB,
            _LC_LOAD_WEAK_DYLIB,
            _LC_REEXPORT_DYLIB,
            _LC_LOAD_UPWARD_DYLIB,
            _LC_LAZY_LOAD_DYLIB,
        } and cmdsize >= 24:
            name_offset = struct.unpack_from(endian + "I", data, offset + 8)[0]
            name = _cstring(data, offset + name_offset, command_end)
            if name and name not in libraries:
                libraries.append(name)
        elif cmd == _LC_RPATH and cmdsize >= 12:
            path_offset = struct.unpack_from(endian + "I", data, offset + 8)[0]
            path = _cstring(data, offset + path_offset, command_end)
            if path and path not in rpaths:
                rpaths.append(path)
        elif cmd == _LC_BUILD_VERSION and cmdsize >= 24:
            platform_id, minos, _sdk, _ntools = struct.unpack_from(endian + "IIII", data, offset + 8)
            platform = _PLATFORM.get(platform_id, f"platform_{platform_id}")
            min_os = _packed_version(minos)
        elif cmd in {_LC_VERSION_MIN_IOS, _LC_VERSION_MIN_TVOS, _LC_VERSION_MIN_WATCHOS} and cmdsize >= 16:
            minos = struct.unpack_from(endian + "I", data, offset + 8)[0]
            platform = {
                _LC_VERSION_MIN_IOS: "iOS",
                _LC_VERSION_MIN_TVOS: "tvOS",
                _LC_VERSION_MIN_WATCHOS: "watchOS",
            }[cmd]
            min_os = _packed_version(minos)
        elif cmd in {_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64} and cmdsize >= 20:
            cryptid = struct.unpack_from(endian + "I", data, offset + 16)[0]
            encryption_flag = cryptid != 0

        offset += cmdsize

    return {
        "valid_header": True,
        "parse_limited": commands_seen != ncmds,
        "architecture": _CPU_TYPES.get(cputype, f"cpu_type_{cputype}"),
        "cpu_subtype": cpusubtype,
        "is_64_bit": is_64,
        "file_type": _FILE_TYPES.get(filetype, f"file_type_{filetype}"),
        "flags": flags,
        "load_command_count": ncmds,
        "load_commands_parsed": commands_seen,
        "linked_libraries": sorted(libraries),
        "rpaths": sorted(rpaths),
        "platform": platform,
        "minimum_os": min_os,
        "encrypted_flag_set": encryption_flag,
        "slice_offset": base_offset,
    }


def _packed_version(value: int) -> str:
    major = (value >> 16) & 0xFFFF
    minor = (value >> 8) & 0xFF
    patch = value & 0xFF
    return f"{major}.{minor}.{patch}"


def inspect_macho(data: bytes) -> dict[str, Any]:
    """Inspect a thin or universal Mach-O header from in-memory bytes."""
    thin = _parse_thin(data)
    if thin is not None:
        return {"format": "thin_macho", "slices": [thin]}

    magic = data[:4]
    if magic not in _FAT_MAGICS:
        return {"format": "unknown", "slices": [], "note": "No recognized Mach-O header found."}

    endian, is_64 = _FAT_MAGICS[magic]
    if len(data) < 8:
        return {"format": "fat_macho", "slices": [], "note": "Truncated universal header."}
    nfat_arch = struct.unpack_from(endian + "I", data, 4)[0]
    if nfat_arch > 64:
        return {"format": "fat_macho", "slices": [], "note": "Architecture count exceeded safety limit."}

    entry_size = 32 if is_64 else 20
    expected = 8 + nfat_arch * entry_size
    if expected > len(data):
        return {"format": "fat_macho", "slices": [], "note": "Truncated universal architecture table."}

    slices: list[dict[str, Any]] = []
    for index in range(nfat_arch):
        entry = 8 + index * entry_size
        try:
            if is_64:
                cputype, _cpusubtype, slice_offset, slice_size, _align, _reserved = struct.unpack_from(
                    endian + "iiQQII", data, entry
                )
            else:
                cputype, _cpusubtype, slice_offset, slice_size, _align = struct.unpack_from(
                    endian + "iiIII", data, entry
                )
        except struct.error:
            continue
        if slice_offset + slice_size > len(data) or slice_size < 28:
            slices.append({
                "valid_header": False,
                "architecture": _CPU_TYPES.get(cputype, f"cpu_type_{cputype}"),
                "note": "Slice is outside the inspected byte range.",
                "slice_offset": slice_offset,
                "slice_size": slice_size,
            })
            continue
        parsed = _parse_thin(data[slice_offset:slice_offset + slice_size], base_offset=slice_offset)
        if parsed is None:
            slices.append({
                "valid_header": False,
                "architecture": _CPU_TYPES.get(cputype, f"cpu_type_{cputype}"),
                "note": "Slice does not contain a recognized thin Mach-O header.",
                "slice_offset": slice_offset,
            })
        else:
            slices.append(parsed)
    return {"format": "fat_macho", "slices": slices}
