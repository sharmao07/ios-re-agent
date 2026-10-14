"""Thin, safety-bounded integration with upstream REA's native CLI.

This project keeps iOS package inventory in Python and delegates deep native
inspection to upstream ``rea-agents``. It deliberately does not reproduce or
fork REA's native provider implementation.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from .ghidra import MAX_EXECUTABLE_BYTES, _is_macho

REA_COMMANDS: dict[str, tuple[str, ...]] = {
    "analyze": ("analyze",),
    "search": ("search", "query"),
    "function": ("function", "symbol_or_address"),
    "decompile": ("decompile", "address"),
    "xrefs": ("xrefs", "address"),
    "trace": ("trace", "query"),
    "instructions": ("instructions", "address"),
}
MAX_REA_OUTPUT_BYTES = 32 * 1024 * 1024
REA_PROVIDERS = {"ghidra", "hopper", "ida"}


class ReaBackendError(RuntimeError):
    """Raised when upstream REA cannot complete a native operation."""


def find_rea_cli() -> str | None:
    """Return the installed REA CLI, without implicitly invoking npx/network."""
    return shutil.which("rea") or shutil.which("rea-agents")


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_process(command: list[str], *, timeout: int, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    if timeout < 1 or timeout > 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    process = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
        else:
            process.kill()
            stdout, stderr = process.communicate()
        detail = (_decode_output(stderr) or _decode_output(stdout) or "")[-5000:]
        raise ReaBackendError(f"REA command timed out after {timeout}s: {' '.join(command[:4])}\n{detail}") from exc
    stdout, stderr = _decode_output(stdout), _decode_output(stderr)
    if len(stdout.encode("utf-8", errors="replace")) > MAX_REA_OUTPUT_BYTES:
        raise ReaBackendError(
            f"REA response exceeded the {MAX_REA_OUTPUT_BYTES}-byte output limit; use a narrower query."
        )
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def run_rea_cli(arguments: Sequence[str], *, timeout: int = 300, cwd: str | Path | None = None) -> dict[str, Any]:
    """Invoke a known REA command without a shell and preserve the JSON evidence."""
    cli = find_rea_cli()
    if not cli:
        raise ReaBackendError(
            "Upstream REA CLI was not found. Install a supported Node.js release "
            "(REA requires Node.js >=22.19, >=24.11, or >=26) and run "
            "npm install --global rea-agents. Then verify `rea --help`."
        )
    if not arguments:
        raise ValueError("REA arguments are required; try `ios-re-agent rea -- --help`.")
    command = [cli, *[str(value) for value in arguments]]
    completed = _run_process(command, timeout=timeout, cwd=cwd)
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    try:
        payload: Any = json.loads(stdout) if stdout else {}
        json_valid = True
    except json.JSONDecodeError:
        payload = None
        json_valid = False
    result: dict[str, Any] = {
        "command": command[1:],
        "returncode": completed.returncode,
        "json_valid": json_valid,
        "stderr": stderr[-8000:],
    }
    if json_valid:
        result["evidence"] = payload
    else:
        result["stdout"] = stdout[:MAX_REA_OUTPUT_BYTES]
    if completed.returncode != 0:
        result["error"] = "REA command returned a non-zero exit code."
    return result


def run_native_operation(
    operation: str,
    target: str | Path,
    *,
    query: str | None = None,
    provider: str = "ghidra",
    timeout: int = 300,
) -> dict[str, Any]:
    """Call one of the documented REA native CLI workflows."""
    if operation not in REA_COMMANDS:
        raise ValueError(f"Unsupported REA native operation: {operation}")
    if provider not in REA_PROVIDERS:
        raise ValueError(f"Unsupported REA provider: {provider}; choose one of {sorted(REA_PROVIDERS)}")
    target_path = Path(target).expanduser().resolve()
    if not target_path.exists():
        raise ValueError(f"Target does not exist: {target_path}")
    if target_path.is_file() and target_path.suffix.lower() == ".ipa":
        raise ValueError("REA's native commands need a Mach-O binary or supported app directory; use `rea-ipa` for an IPA.")
    if target_path.is_file() and not _is_macho(target_path):
        raise ValueError(f"Target file is not a recognized Mach-O binary: {target_path}")
    if target_path.is_dir() and target_path.suffix.lower() != ".app":
        raise ValueError("Directory targets must be an .app bundle; use a Mach-O file or .app directory.")
    expected = REA_COMMANDS[operation]
    args = [operation, str(target_path)]
    if len(expected) > 1:
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"Operation `{operation}` requires a non-empty query/address argument.")
        args.append(query.strip())
    args.extend(["--provider", provider, "--json"])
    result = run_rea_cli(args, timeout=timeout)
    result["operation"] = operation
    result["target"] = str(target_path)
    result["provider"] = provider
    return result


def _safe_slug(index: int, name: str) -> str:
    safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in name)
    return f"{index:03d}_{safe[:70] or 'binary'}"


def _extract_summary(evidence: Any) -> dict[str, Any]:
    """Collect only known count fields; never invent function totals from unknown schemas."""
    summary: dict[str, Any] = {}
    if isinstance(evidence, dict):
        for key in ("function_count", "functions_count", "string_count", "procedure_count", "symbol_count", "reference_count"):
            value = evidence.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                summary[key] = value
        for key in ("functions", "strings", "procedures", "symbols", "references"):
            value = evidence.get(key)
            if isinstance(value, list):
                summary.setdefault(f"{key}_array_length", len(value))
        summary["top_level_keys"] = list(evidence.keys())[:80]
    else:
        summary["result_type"] = type(evidence).__name__
    return summary


def analyze_ipa_with_rea(
    input_path: str | Path,
    out_dir: str | Path,
    *,
    provider: str = "ghidra",
    timeout: int = 300,
    max_binaries: int = 20,
) -> dict[str, Any]:
    """Analyze each native component in an IPA/.app using upstream REA's native CLI.

    The IPA is never executed. Candidate Mach-O files are staged under a temporary
    directory by the existing bounded iOS inventory functions and removed afterward.
    Full REA JSON evidence is retained in the output directory.
    """
    source = Path(input_path).expanduser().resolve()
    if not source.exists() or (not source.is_file() and not source.is_dir()):
        raise ValueError(f"Input does not exist: {source}")
    if max_binaries < 1 or max_binaries > 250:
        raise ValueError("max_binaries must be between 1 and 250")
    if provider not in REA_PROVIDERS:
        raise ValueError(f"Unsupported REA provider: {provider}; choose one of {sorted(REA_PROVIDERS)}")
    if timeout < 30 or timeout > 3600:
        raise ValueError("timeout must be between 30 and 3600 seconds")
    output = Path(out_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    modules: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="ios-re-agent-rea-") as temporary:
        staging = Path(temporary) / "binaries"
        staging.mkdir()
        if source.is_file() and source.suffix.lower() == ".ipa":
            from .ghidra import _stage_ipa
            staged = _stage_ipa(source, staging, max_binaries)
        elif source.is_dir() and source.suffix.lower() == ".app":
            from .ghidra import _stage_app_bundle
            staged = _stage_app_bundle(source, staging, max_binaries)
        elif source.is_file() and _is_macho(source):
            size = source.stat().st_size
            if size > MAX_EXECUTABLE_BYTES:
                raise ValueError(f"Binary exceeds the {MAX_EXECUTABLE_BYTES} byte read limit.")
            staged = [{"source_path": source.name, "staged_path": source, "size_bytes": size}]
        else:
            raise ValueError("Input must be an IPA, a .app bundle directory, or a recognized Mach-O binary.")
        if not staged:
            raise ValueError("No readable Mach-O app executables or dynamic libraries were found.")

        for index, component in enumerate(staged, start=1):
            source_path = str(component["source_path"])
            module_dir = output / "modules" / _safe_slug(index, Path(source_path).name)
            module_dir.mkdir(parents=True, exist_ok=True)
            binary = Path(component["staged_path"])
            try:
                result = run_native_operation("analyze", binary, provider=provider, timeout=timeout)
                evidence = result.get("evidence") if result.get("json_valid") else None
                metadata = {key: value for key, value in result.items() if key != "evidence"}
                metadata_path = module_dir / "rea-command.json"
                metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                if result.get("json_valid"):
                    result_path = module_dir / "rea-evidence.json"
                    result_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    result_relative = str(result_path.relative_to(output))
                else:
                    result_path = module_dir / "rea-output.txt"
                    result_path.write_text(str(result.get("stdout", "")), encoding="utf-8")
                    result_relative = str(result_path.relative_to(output))
                status = "completed" if result.get("returncode") == 0 and result.get("json_valid") else "completed_with_unparsed_output" if result.get("returncode") == 0 else "failed"
                module = {
                    "source_path": source_path,
                    "binary_name": Path(source_path).name,
                    "size_bytes": int(component["size_bytes"]),
                    "status": status,
                    "result_file": result_relative,
                    "command_metadata": str(metadata_path.relative_to(output)),
                    "provider": provider,
                    "summary": _extract_summary(evidence) if result.get("json_valid") else {},
                }
                modules.append(module)
                if status == "failed":
                    failures.append({"source_path": source_path, "error": str(result.get("stderr") or result.get("stdout") or result.get("error"))[:2000]})
            except (ReaBackendError, ValueError, OSError) as exc:
                failures.append({"source_path": source_path, "error": str(exc)[:2000]})

    payload = {
        "schema_version": "1.0",
        "tool": {"name": "ios-re-agent-rea-adapter", "version": "0.3.0"},
        "input_name": source.name,
        "backend": "upstream REA native CLI",
        "provider": provider,
        "components_selected": len(staged),
        "components_analyzed": sum(module["status"] == "completed" for module in modules),
        "components_completed": sum(module["status"] in {"completed", "completed_with_unparsed_output"} for module in modules),
        "components_with_unparsed_output": sum(module["status"] == "completed_with_unparsed_output" for module in modules),
        "components_failed": len(failures),
        "modules": modules,
        "failures": failures,
        "limitations": [
            "REA evidence comes from the upstream REA CLI; result schema varies by REA version and provider.",
            "The target app was not executed and no original source code is recovered.",
            "Encrypted, stripped, obfuscated, or unsupported native code may limit evidence.",
            "Only native executables and dynamic libraries discovered by the iOS inventory layer are analyzed.",
        ],
    }
    json_path = output / "rea-native-analysis.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# iOS-RE Agent — REA Native Analysis", "",
        f"- **Input:** `{source.name}`",
        f"- **Backend:** upstream REA ({provider} provider)",
        f"- **Components selected:** {payload['components_selected']}",
        f"- **Components analyzed (JSON evidence parsed):** {payload['components_analyzed']}",
        f"- **Components completed:** {payload['components_completed']}",
        f"- **Components with unparsed output:** {payload['components_with_unparsed_output']}",
        f"- **Components failed:** {payload['components_failed']}", "",
        "Per-component raw upstream JSON evidence is preserved in `modules/*/rea-evidence.json`; command status and diagnostics are in `rea-command.json`.", "",
        "## Components", "",
        "| Source path | Status | Size (bytes) | Result file |", "|---|---|---:|---|",
    ]
    for module in modules:
        lines.append(f"| `{module['source_path']}` | {module['status']} | {module['size_bytes']} | `{module['result_file']}` |")
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- `{item['source_path']}` — {item['error'].splitlines()[0]}" for item in failures)
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in payload["limitations"])
    lines.append("")
    markdown_path = output / "REA_NATIVE_ANALYSIS.md"
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json_path": str(json_path), "markdown_path": str(markdown_path), **{key: payload[key] for key in ("components_selected", "components_analyzed", "components_failed", "provider")}}
