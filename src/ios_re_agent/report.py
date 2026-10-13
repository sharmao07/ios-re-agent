"""Report serialization helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], destination: Path) -> None:
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _md(value: Any) -> str:
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def write_markdown(report: dict[str, Any], destination: Path) -> None:
    app = report.get("app", {})
    inventory = report.get("inventory", {})
    macho = report.get("macho", {})
    lines = [
        "# iOS-RE Agent Analysis Report",
        "",
        f"- **Generated:** {_md(report.get('generated_at', 'unknown'))}",
        f"- **Input:** `{_md(report.get('input', {}).get('name', 'unknown'))}`",
        f"- **Input type:** {_md(report.get('input', {}).get('type', 'unknown'))}",
        f"- **Tool version:** {_md(report.get('tool', {}).get('version', 'unknown'))}",
        "",
        "> This is a static analysis summary, not proof of runtime behavior or a complete decompilation.",
        "",
        "## App metadata",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    metadata_fields = [
        ("Display name", app.get("bundle_name")),
        ("Bundle identifier", app.get("bundle_identifier")),
        ("Executable", app.get("executable")),
        ("Version", app.get("version")),
        ("Build", app.get("build")),
        ("Minimum OS", app.get("minimum_os")),
        ("Supported platforms", ", ".join(app.get("supported_platforms", []))),
        ("URL schemes", ", ".join(app.get("url_schemes", []))),
        ("Queried URL schemes", ", ".join(app.get("queried_url_schemes", []))),
        ("Background modes", ", ".join(app.get("background_modes", []))),
    ]
    for key, value in metadata_fields:
        lines.append(f"| {_md(key)} | {_md(value if value not in (None, '') else 'Not found')} |")

    lines += ["", "## Package inventory", "", f"- **Files in bundle:** {inventory.get('file_count', 'unknown')}",
              f"- **Localization directories:** {inventory.get('localization_count', 'unknown')}", "", "### File types", "",
              "| Extension | Count |", "|---|---:|"]
    for extension, count in inventory.get("extension_counts", {}).items():
        lines.append(f"| `{_md(extension)}` | {count} |")

    lines += ["", "### Frameworks and dynamic libraries", ""]
    frameworks = inventory.get("frameworks_and_dynamic_libraries", [])
    lines.extend([f"- `{_md(name)}`" for name in frameworks] or ["- None found in bundle paths."])

    lines += ["", "### App extensions", ""]
    extensions = inventory.get("app_extensions", [])
    if extensions:
        lines += ["| Bundle identifier | Name | Extension point | Path |", "|---|---|---|---|"]
        for ext in extensions:
            lines.append("| " + " | ".join(_md(ext.get(k) or "Not found") for k in (
                "bundle_identifier", "name", "extension_point", "path"
            )) + " |")
    else:
        lines.append("No `.appex` extension bundles were identified.")

    lines += ["", "### Privacy manifests", ""]
    privacy = inventory.get("privacy_manifests", [])
    if privacy:
        for manifest in privacy:
            lines += [
                f"#### `{_md(manifest.get('path'))}`",
                f"- Tracking declared: `{manifest.get('tracking') if manifest.get('tracking') is not None else 'not specified'}`",
                f"- Tracking domains: {_md(', '.join(manifest.get('tracking_domains', [])) or 'None listed')}",
                f"- Accessed API categories: {_md(', '.join(manifest.get('accessed_api_categories', [])) or 'None listed')}",
                f"- Collected data categories: {_md(', '.join(manifest.get('collected_data_categories', [])) or 'None listed')}",
                "",
            ]
    else:
        lines.append("No parseable `PrivacyInfo.xcprivacy` manifest was found in scanned bundle paths.")

    lines += ["", "## Declared privacy usage descriptions", ""]
    usage = app.get("privacy_usage_descriptions", [])
    if usage:
        lines += ["| Info.plist key | Description |", "|---|---|"]
        for item in usage:
            description = re.sub(r"\s+", " ", str(item.get("description", "")))[:500]
            lines.append(f"| `{_md(item.get('key'))}` | {_md(description)} |")
    else:
        lines.append("No `*UsageDescription` keys were found in the root Info.plist.")

    lines += ["", "## Mach-O metadata", "", f"- **Format:** {_md(macho.get('format', 'unknown'))}", ""]
    slices = macho.get("slices", [])
    if slices:
        lines += ["| Architecture | File type | Platform | Minimum OS | Encrypted flag |", "|---|---|---|---|---|"]
        for item in slices:
            if not isinstance(item, dict):
                continue
            encrypted = item.get("encrypted_flag_set")
            enc_text = "true" if encrypted is True else "false" if encrypted is False else "not determined"
            lines.append("| " + " | ".join(_md(v or "Not found") for v in (
                item.get("architecture"), item.get("file_type"), item.get("platform"), item.get("minimum_os"), enc_text
            )) + " |")
        linked = sorted({lib for item in slices if isinstance(item, dict) for lib in item.get("linked_libraries", [])})
        lines += ["", "### Linked libraries", ""]
        lines.extend([f"- `{_md(lib)}`" for lib in linked] or ["- No linked libraries recovered from parsed load commands."])
    else:
        lines.append(_md(macho.get("note", "No Mach-O slices were parsed.")))

    network = report.get("network_indicators", {})
    lines += ["", "## Candidate network indicators", "", "> These strings are leads for investigation, not confirmation that the app contacts these hosts.", ""]
    hosts = network.get("candidate_hosts", [])
    if hosts:
        lines.extend([f"- `{_md(host)}`" for host in hosts])
    else:
        lines.append("No HTTP(S) host strings were recovered from the selected files.")
    endpoints = network.get("candidate_endpoints", [])
    if endpoints:
        lines += ["", "### Sanitized endpoint strings", ""]
        lines.extend([f"- `{_md(endpoint)}`" for endpoint in endpoints[:100]])
        if len(endpoints) > 100:
            lines.append(f"- … and {len(endpoints) - 100} more (see `report.json`).")

    indicators = report.get("keyword_indicators", {})
    lines += ["", "## Keyword indicators", ""]
    if indicators:
        lines += ["| Category | Match count (capped) |", "|---|---:|"]
        for name, count in indicators.items():
            lines.append(f"| {_md(name)} | {count} |")
    else:
        lines.append("No keyword categories matched in the selected files.")

    scan = report.get("scan", {})
    lines += ["", "## Scan coverage", "", f"- Files scanned: {len(scan.get('files_scanned', []))}",
              f"- Files skipped: {len(scan.get('files_skipped', []))}",
              f"- Bytes scanned: {scan.get('bytes_scanned', 0)}", ""]

    lines += ["## Limitations and interpretation", ""]
    lines.extend([f"- {_md(note)}" for note in report.get("limitations", [])])
    lines += ["", "## Reproducibility", "", "The JSON report contains the machine-readable findings and the exact list of selected paths scanned. "
              "Re-run with the same input to compare results. Generated timestamps will differ.", ""]
    destination.write_text("\n".join(lines), encoding="utf-8")
