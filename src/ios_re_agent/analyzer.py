"""Read-only iOS package inspection with bounded resource use and evidence notes."""

from __future__ import annotations

import os
import plistlib
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .macho import inspect_macho

MAX_ARCHIVE_ENTRIES = 25_000
MAX_SINGLE_READ = 64 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 256 * 1024 * 1024
MAX_SCAN_FILES = 180
MAX_PLIST_READ = 2 * 1024 * 1024

URL_RE = re.compile(rb"https?://[^\x00-\x20\"'<>\\]{4,512}", re.IGNORECASE)
KEYWORD_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "analytics": re.compile(rb"analytics|telemetry|amplitude|mixpanel|segment\.com", re.I),
    "crash_reporting": re.compile(rb"sentry|crashlytics|bugsnag|rollbar|\bcrashreport", re.I),
    "authentication": re.compile(rb"oauth|openid|auth0|firebaseauth|sign[_-]?in|log[_-]?in", re.I),
    "payments": re.compile(rb"stripe|adyen|braintree|paymentintent|storekit|in[_-]?app[_-]?purchase", re.I),
    "push_notifications": re.compile(rb"apns|push[_-]?notification|notificationservice", re.I),
    "cloud_services": re.compile(rb"firebase|amazonaws|cloudflare|supabase|azure|googleapis", re.I),
    "web_sockets": re.compile(rb"wss?://|websocket|socket\.io", re.I),
}
SENSITIVE_PATH_SEGMENT = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|session)[=:_-].+"
)
LONG_OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{28,}$")


class AnalysisError(Exception):
    """Raised when input cannot be analyzed safely or meaningfully."""


class ArtifactReader:
    """Read files from an IPA, .app bundle directory, or single binary without extraction."""

    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.kind: str
        self._zip: zipfile.ZipFile | None = None
        self._zip_infos: dict[str, zipfile.ZipInfo] = {}
        self.root_prefix = ""
        self.truncated_paths: set[str] = set()

        if not self.path.exists():
            raise AnalysisError(f"Input does not exist: {self.path}")
        if self.path.is_dir():
            if self.path.suffix.lower() != ".app":
                raise AnalysisError("Directory input must be an .app bundle directory.")
            self.kind = "app_bundle"
            if not (self.path / "Info.plist").is_file():
                raise AnalysisError("The .app directory does not contain Info.plist.")
        elif not self.path.is_file():
            raise AnalysisError("Input must be an IPA file, an .app directory, or a Mach-O binary.")
        elif self.path.suffix.lower() == ".ipa" or zipfile.is_zipfile(self.path):
            try:
                self._zip = zipfile.ZipFile(self.path, "r")
            except (OSError, zipfile.BadZipFile) as exc:
                raise AnalysisError(f"Could not open archive: {exc}") from exc
            infos = self._zip.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                self.close()
                raise AnalysisError(f"Archive contains too many entries (limit {MAX_ARCHIVE_ENTRIES}).")
            for info in infos:
                # ZIP paths are never extracted. Normalize separators only for analysis.
                name = info.filename.replace("\\", "/")
                if info.is_dir():
                    continue
                self._zip_infos[name] = info
            app_plists = [
                name for name in self._zip_infos
                if name.startswith("Payload/") and ".app/Info.plist" in name
                and ".appex/" not in name
            ]
            if not app_plists:
                self.close()
                raise AnalysisError("No Payload/*.app/Info.plist found. Is this a standard iOS IPA?")
            app_plists.sort(key=lambda n: (n.count(".app/"), len(n), n))
            self.root_prefix = app_plists[0].rsplit("Info.plist", 1)[0]
            self.kind = "ipa"
        else:
            self.kind = "binary"

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def __enter__(self) -> "ArtifactReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def list_paths(self) -> list[str]:
        if self.kind == "binary":
            return [self.path.name]
        if self.kind == "app_bundle":
            result: list[str] = []
            for current, dirs, files in os.walk(self.path, followlinks=False):
                dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
                for filename in files:
                    file_path = Path(current) / filename
                    if file_path.is_symlink() or not file_path.is_file():
                        continue
                    result.append(file_path.relative_to(self.path).as_posix())
            return sorted(result)
        prefix = self.root_prefix
        return sorted(name[len(prefix):] for name in self._zip_infos if name.startswith(prefix))

    def read(self, relative_path: str, max_bytes: int = MAX_SINGLE_READ) -> bytes | None:
        if relative_path.startswith("/") or ".." in PurePosixPath(relative_path).parts:
            return None
        if self.kind == "binary":
            if relative_path != self.path.name:
                return None
            try:
                if self.path.stat().st_size > max_bytes:
                    self.truncated_paths.add(relative_path)
                    with self.path.open("rb") as stream:
                        return stream.read(max_bytes)
                return self.path.read_bytes()
            except OSError:
                return None
        if self.kind == "app_bundle":
            candidate = (self.path / Path(*PurePosixPath(relative_path).parts)).resolve()
            try:
                candidate.relative_to(self.path)
            except ValueError:
                return None
            if candidate.is_symlink() or not candidate.is_file():
                return None
            try:
                if candidate.stat().st_size > max_bytes:
                    self.truncated_paths.add(relative_path)
                with candidate.open("rb") as stream:
                    return stream.read(max_bytes + 1)[:max_bytes]
            except OSError:
                return None

        archive_name = self.root_prefix + relative_path
        info = self._zip_infos.get(archive_name)
        if info is None or self._zip is None:
            return None
        if info.file_size > max_bytes:
            self.truncated_paths.add(relative_path)
        try:
            with self._zip.open(info, "r") as stream:
                data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                self.truncated_paths.add(relative_path)
                return data[:max_bytes]
            return data
        except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
            return None


def _safe_url(raw: bytes | str) -> str | None:
    text = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else raw
    text = text.rstrip(".,);]}>")
    try:
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        # Credentials and query values are omitted from reports to reduce accidental secret leaks.
        host = parsed.hostname.lower()
        # XML property lists commonly contain Apple's external DTD identifier;
        # it is format metadata, not evidence of an app endpoint.
        if host == "www.apple.com" and parsed.path.startswith("/DTDs/PropertyList-"):
            return None
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        netloc = host + port
        segments = []
        for segment in parsed.path.split("/"):
            if SENSITIVE_PATH_SEGMENT.search(segment) or LONG_OPAQUE_SEGMENT.fullmatch(segment):
                segments.append("<redacted>")
            else:
                segments.append(segment[:120])
        path = "/".join(segments)[:400]
        suffix = "?<redacted>" if parsed.query else ""
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", "")) + suffix
    except (ValueError, UnicodeError):
        return None


def _load_plist(data: bytes | None) -> dict[str, Any] | None:
    if not data:
        return None
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
        return None
    return value if isinstance(value, dict) else None


def _extension_counts(paths: list[str]) -> dict[str, int]:
    counts = Counter(Path(path).suffix.lower() or "[no extension]" for path in paths)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:80])


def _privacy_manifest(path: str, data: bytes) -> dict[str, Any] | None:
    manifest = _load_plist(data)
    if not manifest:
        return None
    accessed = manifest.get("NSPrivacyAccessedAPITypes", [])
    collected = manifest.get("NSPrivacyCollectedDataTypes", [])
    return {
        "path": path,
        "tracking": manifest.get("NSPrivacyTracking") if isinstance(manifest.get("NSPrivacyTracking"), bool) else None,
        "tracking_domains": sorted({str(x)[:255] for x in manifest.get("NSPrivacyTrackingDomains", []) if isinstance(x, str)})[:100],
        "accessed_api_categories": sorted({
            str(item.get("NSPrivacyAccessedAPIType"))
            for item in accessed if isinstance(item, dict) and item.get("NSPrivacyAccessedAPIType")
        })[:100] if isinstance(accessed, list) else [],
        "collected_data_categories": sorted({
            str(item.get("NSPrivacyCollectedDataType"))
            for item in collected if isinstance(item, dict) and item.get("NSPrivacyCollectedDataType")
        })[:100] if isinstance(collected, list) else [],
        "note": "Manifest declarations are reported as declared; they are not proof of runtime behavior.",
    }


def _bundle_metadata(info: dict[str, Any] | None) -> dict[str, Any]:
    if not info:
        return {}
    url_schemes: set[str] = set()
    for item in info.get("CFBundleURLTypes", []) if isinstance(info.get("CFBundleURLTypes", []), list) else []:
        if not isinstance(item, dict):
            continue
        schemes = item.get("CFBundleURLSchemes", [])
        if isinstance(schemes, list):
            url_schemes.update(str(s)[:120] for s in schemes if isinstance(s, str))
    queries = info.get("LSApplicationQueriesSchemes", [])
    background = info.get("UIBackgroundModes", [])
    permission_strings = []
    for key, value in info.items():
        if isinstance(key, str) and key.endswith("UsageDescription") and isinstance(value, str):
            permission_strings.append({"key": key, "description": value[:500]})
    return {
        "bundle_identifier": _short_string(info.get("CFBundleIdentifier")),
        "bundle_name": _short_string(info.get("CFBundleDisplayName") or info.get("CFBundleName")),
        "executable": _short_string(info.get("CFBundleExecutable")),
        "version": _short_string(info.get("CFBundleShortVersionString")),
        "build": _short_string(info.get("CFBundleVersion")),
        "minimum_os": _short_string(info.get("MinimumOSVersion")),
        "supported_platforms": sorted({str(x)[:100] for x in info.get("CFBundleSupportedPlatforms", []) if isinstance(x, str)})[:20]
            if isinstance(info.get("CFBundleSupportedPlatforms", []), list) else [],
        "url_schemes": sorted(url_schemes)[:100],
        "queried_url_schemes": sorted({str(x)[:120] for x in queries if isinstance(x, str)})[:200]
            if isinstance(queries, list) else [],
        "background_modes": sorted({str(x)[:100] for x in background if isinstance(x, str)})[:100]
            if isinstance(background, list) else [],
        "privacy_usage_descriptions": sorted(permission_strings, key=lambda item: item["key"]),
        "app_transport_security_declared": isinstance(info.get("NSAppTransportSecurity"), dict),
        "info_plist_keys": sorted(str(key) for key in info.keys() if isinstance(key, str))[:300],
    }


def _short_string(value: Any) -> str | None:
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _inspect_extensions(paths: list[str], reader: ArtifactReader) -> list[dict[str, Any]]:
    extensions = [path for path in paths if path.endswith(".appex/Info.plist")][:50]
    result = []
    for path in extensions:
        info = _load_plist(reader.read(path, MAX_PLIST_READ))
        if not info:
            continue
        nested = info.get("NSExtension", {})
        result.append({
            "path": path,
            "bundle_identifier": _short_string(info.get("CFBundleIdentifier")),
            "name": _short_string(info.get("CFBundleDisplayName") or info.get("CFBundleName")),
            "executable": _short_string(info.get("CFBundleExecutable")),
            "extension_point": _short_string(nested.get("NSExtensionPointIdentifier")) if isinstance(nested, dict) else None,
        })
    return result


def _framework_names(paths: list[str]) -> list[str]:
    names: set[str] = set()
    for path in paths:
        pure = PurePosixPath(path)
        for part in pure.parts:
            if part.endswith(".framework") or part.endswith(".dylib"):
                names.add(part)
    return sorted(names)[:500]


def _select_scan_paths(paths: list[str], executable: str | None) -> list[str]:
    selected: list[str] = []
    if executable and executable in paths:
        selected.append(executable)
    for path in paths:
        suffix = Path(path).suffix.lower()
        p = PurePosixPath(path)
        should_scan = (
            suffix in {".strings", ".stringsdict", ".plist", ".xcprivacy", ".json", ".js", ".mjs", ".html", ".xml", ".txt", ".conf", ".cfg"}
            or ("Frameworks" in p.parts and (suffix == ".dylib" or ".framework" in "/".join(p.parts)))
        )
        if should_scan and path not in selected:
            selected.append(path)
        if len(selected) >= MAX_SCAN_FILES:
            break
    return selected[:MAX_SCAN_FILES]


def analyze(path: str | Path) -> dict[str, Any]:
    """Analyze an iOS app artifact. Results are evidence/indicators, not runtime proof."""
    input_path = Path(path)
    with ArtifactReader(input_path) as reader:
        if reader.kind == "binary":
            data = reader.read(reader.path.name, MAX_SINGLE_READ)
            macho = inspect_macho(data or b"")
            result = {
                "schema_version": "1.0",
                "tool": {"name": "ios-re-agent", "version": __version__},
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "input": {"name": reader.path.name, "type": "macho_binary"},
                "macho": macho,
                "scan": {"truncated_files": sorted(reader.truncated_paths)},
                "limitations": [
                    "A binary-only input has no bundle metadata or resources to inventory.",
                    "This tool parses headers and selected indicators; it is not a complete decompiler.",
                    *(["The binary exceeded the configured read limit and only its prefix was inspected."] if reader.truncated_paths else []),
                ],
            }
            return result

        paths = reader.list_paths()
        app_info = _load_plist(reader.read("Info.plist", MAX_PLIST_READ))
        if app_info is None:
            raise AnalysisError("Could not parse the app's Info.plist (missing, unsupported, or malformed).")

        metadata = _bundle_metadata(app_info)
        executable = metadata.get("executable")
        executable_data = reader.read(executable, MAX_SINGLE_READ) if executable else None
        macho = inspect_macho(executable_data or b"") if executable_data else {
            "format": "not_inspected",
            "slices": [],
            "note": "The executable was not found or exceeded the per-file read limit.",
        }

        privacy_manifests = []
        for manifest_path in [p for p in paths if PurePosixPath(p).name == "PrivacyInfo.xcprivacy"][:50]:
            details = _privacy_manifest(manifest_path, reader.read(manifest_path, MAX_PLIST_READ) or b"")
            if details:
                privacy_manifests.append(details)

        framework_names = _framework_names(paths)
        extensions = _inspect_extensions(paths, reader)
        extension_counts = _extension_counts(paths)

        candidate_urls: set[str] = set()
        scan_bytes = 0
        scanned_files: list[str] = []
        skipped_files: list[str] = []
        indicator_counts: Counter[str] = Counter()
        scan_paths = _select_scan_paths(paths, executable)
        for rel_path in scan_paths:
            if scan_bytes >= MAX_TOTAL_SCAN_BYTES:
                skipped_files.append(rel_path)
                continue
            data = reader.read(rel_path, min(MAX_SINGLE_READ, MAX_TOTAL_SCAN_BYTES - scan_bytes))
            if data is None:
                skipped_files.append(rel_path)
                continue
            scan_bytes += len(data)
            scanned_files.append(rel_path)
            if len(candidate_urls) < 500:
                for match in URL_RE.finditer(data):
                    clean = _safe_url(match.group(0))
                    if clean:
                        candidate_urls.add(clean)
                    if len(candidate_urls) >= 500:
                        break
            for name, pattern in KEYWORD_PATTERNS.items():
                # Count without retaining raw matches; cap work/output per category.
                hits = 0
                for _match in pattern.finditer(data):
                    hits += 1
                    if hits >= 10_000:
                        break
                if hits:
                    indicator_counts[name] = min(10_000, indicator_counts[name] + hits)

        endpoint_hosts: set[str] = set()
        for endpoint in candidate_urls:
            try:
                hostname = urlsplit(endpoint.split("?<redacted>", 1)[0]).hostname
                if hostname:
                    endpoint_hosts.add(hostname.lower())
            except ValueError:
                continue

        categories: dict[str, Any] = {
            "file_count": len(paths),
            "extension_counts": extension_counts,
            "frameworks_and_dynamic_libraries": framework_names,
            "app_extensions": extensions,
            "localization_count": len({
                part for p in paths for part in PurePosixPath(p).parts if part.endswith(".lproj")
            }),
            "privacy_manifests": privacy_manifests,
        }

        slices = macho.get("slices", []) if isinstance(macho, dict) else []
        encrypted_slices = [s for s in slices if isinstance(s, dict) and s.get("encrypted_flag_set") is True]
        limitations = [
            "Static inspection only: no app code is executed and no device or simulator is controlled.",
            "Mach-O metadata and string matches are partial evidence, not a reconstruction of all application logic.",
            "A reported URL may be unused, stale, environment-specific, or embedded in a third-party library.",
            "App Store encryption, missing symbols, obfuscation, stripped metadata, and dynamic behavior can limit analysis.",
            "The PrivacyInfo.xcprivacy section reports declarations found in packaged manifests; it does not verify actual collection.",
            f"String scanning covered {len(scanned_files)} selected files and {scan_bytes} bytes; this is intentionally bounded.",
        ]
        if skipped_files:
            limitations.append(f"{len(skipped_files)} selected files were skipped due to read errors or scan limits.")
        if reader.truncated_paths:
            limitations.append(f"{len(reader.truncated_paths)} file(s) exceeded a configured read limit; only a prefix may have been inspected.")
        if encrypted_slices:
            limitations.append("At least one Mach-O slice has a nonzero encryption flag; deeper code inspection may be limited.")

        return {
            "schema_version": "1.0",
            "tool": {"name": "ios-re-agent", "version": __version__},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input": {"name": reader.path.name, "type": reader.kind},
            "app": metadata,
            "inventory": categories,
            "macho": macho,
            "network_indicators": {
                "candidate_endpoints": sorted(candidate_urls)[:500],
                "candidate_hosts": sorted(endpoint_hosts)[:300],
                "interpretation": "Candidate strings only; confirm reachability and use through authorized dynamic testing or source evidence.",
            },
            "keyword_indicators": dict(sorted(indicator_counts.items())),
            "scan": {
                "files_scanned": scanned_files,
                "files_skipped": skipped_files[:100],
                "truncated_files": sorted(reader.truncated_paths)[:100],
                "bytes_scanned": scan_bytes,
                "scan_limits": {
                    "max_bytes_per_file": MAX_SINGLE_READ,
                    "max_total_bytes": MAX_TOTAL_SCAN_BYTES,
                    "max_files": MAX_SCAN_FILES,
                },
            },
            "limitations": limitations,
        }
