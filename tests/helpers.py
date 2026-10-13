from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path


def make_macho(*, encrypted: bool = False) -> bytes:
    commands = []

    dylib_path = b"/usr/lib/libSystem.B.dylib\0"
    dylib_size = (24 + len(dylib_path) + 3) & ~3
    commands.append(
        struct.pack("<IIIIII", 0x0000000C, dylib_size, 24, 0, 0, 0)
        + dylib_path
        + b"\0" * (dylib_size - 24 - len(dylib_path))
    )
    commands.append(struct.pack("<IIIIII", 0x00000032, 24, 2, 0x000E0000, 0x00180000, 0))
    if encrypted:
        commands.append(struct.pack("<IIIIII", 0x0000002C, 24, 0, 0, 1, 0))

    command_blob = b"".join(commands)
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        len(commands),
        len(command_blob),
        0,
        0,
    )
    return header + command_blob + b"\0" * 8


def app_info() -> dict:
    return {
        "CFBundleIdentifier": "org.example.Demo",
        "CFBundleName": "Demo App",
        "CFBundleDisplayName": "Demo",
        "CFBundleExecutable": "Demo",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "45",
        "MinimumOSVersion": "16.0",
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp"]}],
        "NSCameraUsageDescription": "Take a photo for a demo.",
        "UIBackgroundModes": ["fetch"],
    }


def write_app_bundle(path: Path, *, encrypted: bool = False) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "Info.plist").write_bytes(plistlib.dumps(app_info()))
    (path / "Demo").write_bytes(make_macho(encrypted=encrypted) + b"https://user:pass@api.example.test/v1/items/token=pathsecret?token=do-not-print#private\0")
    (path / "en.lproj").mkdir()
    (path / "en.lproj" / "Localizable.strings").write_text('"hello" = "world";', encoding="utf-8")
    (path / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": ["tracking.example.test"],
        "NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "test-category"}],
        "NSPrivacyCollectedDataTypes": [{"NSPrivacyCollectedDataType": "test-data-type"}],
    }))
    framework_dir = path / "Frameworks" / "DemoKit.framework"
    framework_dir.mkdir(parents=True)
    (framework_dir / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "org.example.DemoKit"}))
    appex_dir = path / "PlugIns" / "DemoShare.appex"
    appex_dir.mkdir(parents=True)
    (appex_dir / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "org.example.Demo.share",
        "CFBundleName": "DemoShare",
        "CFBundleExecutable": "DemoShare",
        "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services"},
    }))
    return path


def write_ipa(path: Path) -> Path:
    info = plistlib.dumps(app_info())
    binary = make_macho() + b"https://user:pass@api.example.test/v1/items/token=pathsecret?token=do-not-print#private\0"
    privacy = plistlib.dumps({"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": ["tracking.example.test"]})
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/Demo.app/Info.plist", info)
        zf.writestr("Payload/Demo.app/Demo", binary)
        zf.writestr("Payload/Demo.app/PrivacyInfo.xcprivacy", privacy)
        zf.writestr("Payload/Demo.app/en.lproj/Localizable.strings", '"hello" = "world";')
    return path
