"""Optional read-only Ghidra headless adapter for authorized iOS executables."""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .analyzer import MAX_ARCHIVE_ENTRIES

MAX_EXECUTABLE_BYTES = 768 * 1024 * 1024
MAX_TOTAL_NATIVE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_BINARIES = 100
SCRIPT_PATH = Path(__file__).resolve().parent / "data" / "ExportAnalysis.py"
JYTHON_SCRIPT_PATH = Path(__file__).resolve().parent / "data" / "ExportAnalysisJython.py"
PRE_ANALYSIS_SCRIPT_PATH = Path(__file__).resolve().parent / "data" / "DisableObjcAnalyzers.java"
MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}


class GhidraError(RuntimeError):
    """Raised when optional Ghidra export cannot be completed."""


def find_analyze_headless(ghidra_home: str | Path | None = None) -> Path | None:
    """Find Ghidra's headless launcher across common archive and Homebrew layouts.

    ``GHIDRA_HOME`` is variously set to the extracted install root, its ``Ghidra``
    application subdirectory, or Homebrew's ``libexec`` directory. Support all
    three instead of assuming a single filesystem shape.
    """
    candidates: list[Path] = []
    roots: list[Path] = []
    if ghidra_home:
        roots.append(Path(ghidra_home).expanduser())
    if os.environ.get("GHIDRA_HOME"):
        roots.append(Path(os.environ["GHIDRA_HOME"]).expanduser())
    path_hit = shutil.which("analyzeHeadless")
    if path_hit:
        candidates.append(Path(path_hit))
    for root in roots:
        candidates.extend([
            root / "support" / "analyzeHeadless",
            root / "support" / "analyzeHeadless.bat",
            root.parent / "support" / "analyzeHeadless",
            root.parent / "support" / "analyzeHeadless.bat",
            root.parent.parent / "support" / "analyzeHeadless",
            root.parent.parent / "support" / "analyzeHeadless.bat",
            root / "Ghidra" / "support" / "analyzeHeadless",
        ])
    for pattern_root in (Path("/Applications"), Path.home() / "Applications", Path.home()):
        try:
            candidates.extend(pattern_root.glob("ghidra_*/support/analyzeHeadless"))
            candidates.extend(pattern_root.glob("ghidra_*/support/analyzeHeadless.bat"))
            candidates.extend(pattern_root.glob("ghidra_*/libexec/support/analyzeHeadless"))
        except OSError:
            pass
    # Homebrew's linked formula and Cellar versioned install.
    for pattern in (
        "/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless",
        "/opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless",
        "/usr/local/opt/ghidra/libexec/support/analyzeHeadless",
        "/usr/local/Cellar/ghidra/*/libexec/support/analyzeHeadless",
    ):
        import glob
        candidates.extend(Path(path) for path in glob.glob(pattern))
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    return None


def _is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) in MACHO_MAGICS
    except OSError:
        return False


def _safe_executable_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value or Path(value).name != value or value in {".", ".."}:
        return None
    return value


def _stage_file(source: Path, destination: Path, relative_label: str, total: list[int]) -> dict[str, Any] | None:
    if source.is_symlink() or not source.is_file():
        return None
    size = source.stat().st_size
    if size < 4 or size > MAX_EXECUTABLE_BYTES or total[0] + size > MAX_TOTAL_NATIVE_BYTES or not _is_macho(source):
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    total[0] += size
    return {"source_path": relative_label, "staged_path": destination, "size_bytes": size}


def _stage_app_bundle(source: Path, staging: Path, max_binaries: int) -> list[dict[str, Any]]:
    candidates: dict[str, tuple[Path, int]] = {}
    info_plists: list[Path] = []
    for current, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
        for filename in files:
            item = Path(current) / filename
            if item.is_symlink() or not item.is_file():
                continue
            if filename == "Info.plist":
                info_plists.append(item)
            elif item.suffix.lower() == ".dylib":
                candidates[item.relative_to(source).as_posix()] = (item, 3)
    for info_path in info_plists:
        try:
            info = plistlib.loads(info_path.read_bytes())
        except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
            continue
        name = _safe_executable_name(info.get("CFBundleExecutable") if isinstance(info, dict) else None)
        if not name:
            continue
        binary = info_path.parent / name
        try:
            binary.resolve().relative_to(source.resolve())
        except ValueError:
            continue
        if not binary.is_file() or binary.is_symlink():
            continue
        relative = binary.relative_to(source).as_posix()
        priority = 0 if info_path == source / "Info.plist" else 1 if ".appex/" in relative else 2
        candidates[relative] = (binary, priority)
    total = [0]
    staged: list[dict[str, Any]] = []
    ordered = sorted(candidates.items(), key=lambda item: (item[1][1], item[0]))
    for relative, (candidate, _priority) in ordered:
        if len(staged) >= max_binaries:
            break
        safe_name = f"{len(staged):03d}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', Path(relative).name)}"
        item = _stage_file(candidate, staging / safe_name, relative, total)
        if item:
            staged.append(item)
    return staged


def _stage_ipa(source: Path, staging: Path, max_binaries: int) -> list[dict[str, Any]]:
    try:
        archive = zipfile.ZipFile(source, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise GhidraError(f"Could not open IPA: {exc}") from exc
    staged: list[dict[str, Any]] = []
    total_bytes = 0
    with archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise GhidraError(f"IPA has too many entries ({len(infos)}; limit {MAX_ARCHIVE_ENTRIES}).")
        by_name = {item.filename.replace("\\", "/"): item for item in infos}
        candidates: dict[str, tuple[zipfile.ZipInfo, int]] = {}
        for info_item in infos:
            normalized = info_item.filename.replace("\\", "/")
            if not normalized.startswith("Payload/") or not normalized.endswith("/Info.plist"):
                continue
            # Only read the small plist, never extract arbitrary archive paths.
            if info_item.file_size > 2 * 1024 * 1024:
                continue
            try:
                metadata = plistlib.loads(archive.read(info_item))
            except (OSError, KeyError, RuntimeError, plistlib.InvalidFileException, ValueError, TypeError):
                continue
            name = _safe_executable_name(metadata.get("CFBundleExecutable") if isinstance(metadata, dict) else None)
            if not name:
                continue
            parent = normalized.rsplit("/Info.plist", 1)[0]
            binary_path = parent + "/" + name
            binary_info = by_name.get(binary_path)
            if binary_info is None:
                continue
            priority = 0 if normalized.count("/") == 2 and normalized.endswith(".app/Info.plist") else 1 if ".appex/" in normalized else 2
            candidates[binary_path] = (binary_info, priority)
        for path_name, item in by_name.items():
            if path_name.lower().endswith(".dylib"):
                candidates.setdefault(path_name, (item, 3))
        ordered = sorted(candidates.items(), key=lambda row: (row[1][1], row[0]))
        for path_name, (entry, _priority) in ordered:
            if len(staged) >= max_binaries:
                break
            if entry.file_size < 4 or entry.file_size > MAX_EXECUTABLE_BYTES or total_bytes + entry.file_size > MAX_TOTAL_NATIVE_BYTES:
                continue
            try:
                with archive.open(entry, "r") as stream:
                    header = stream.read(4)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            if header not in MACHO_MAGICS:
                continue
            safe_name = f"{len(staged):03d}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', Path(path_name).name)}"
            output = staging / safe_name
            output.parent.mkdir(parents=True, exist_ok=True)
            try:
                written = 0
                with archive.open(entry, "r") as source_stream, output.open("wb") as destination_stream:
                    first = source_stream.read(4)
                    if first not in MACHO_MAGICS:
                        continue
                    destination_stream.write(first)
                    written += len(first)
                    while True:
                        chunk = source_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_EXECUTABLE_BYTES or total_bytes + written > MAX_TOTAL_NATIVE_BYTES:
                            raise GhidraError("Native component exceeded configured staging limits while reading IPA.")
                        destination_stream.write(chunk)
                if written != entry.file_size:
                    output.unlink(missing_ok=True)
                    continue
            except (OSError, RuntimeError, zipfile.BadZipFile, GhidraError):
                output.unlink(missing_ok=True)
                continue
            total_bytes += written
            staged.append({"source_path": path_name, "staged_path": output, "size_bytes": written})
    return staged


def _module_slug(index: int, name: str) -> str:
    return f"{index:03d}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', name)[:70]}"


def _write_native_markdown(payload: dict[str, Any], path: Path) -> None:
    lines = [
        "# iOS-RE Agent Native Analysis", "",
        f"- **Input component:** `{payload.get('input_path', payload.get('input_name', 'unknown'))}`",
        "- **Backend:** Ghidra headless",
        f"- **Functions discovered:** {payload.get('function_count', 0)}",
        f"- **Functions decompiled:** {payload.get('decompiled_count', 0)}",
        f"- **Strings exported:** {payload.get('string_count', 0)}", "",
        "> Decompiled pseudocode is an approximation generated from machine code, not the original source. Names and types may be inferred.", "",
        "## Functions", "",
    ]
    for function in payload.get("functions", [])[:300]:
        lines += [f"### `{function.get('name', 'unknown')}` at `{function.get('entry_point', '?')}`", ""]
        if function.get("signature"):
            lines += ["```c", str(function["signature"])[:1000], "```", ""]
        body = function.get("pseudocode")
        if body:
            lines += ["```c", str(body)[:12000], "```", ""]
        if function.get("callers"):
            lines.append("- Callers: " + ", ".join(str(x) for x in function["callers"][:20]))
        if function.get("callees"):
            lines.append("- Callees: " + ", ".join(str(x) for x in function["callees"][:20]))
        lines.append("")
    lines += ["## Strings", ""]
    for item in payload.get("strings", [])[:500]:
        value = str(item.get("value", ""))[:300].replace("`", "'")
        lines.append(f"- `{item.get('address', '?')}` — `{value}`")
    lines += ["", "## Limitations", "", "- Static decompilation only; target code was not executed.", "- Stripped symbols, obfuscation, optimized code, encryption, and analysis quality can limit results.", "- Use cross-references, callers/callees and disassembly to validate hypotheses.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def _run_headless(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a Ghidra launch and reap its process group if it exceeds the timeout."""
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
        detail = (stderr or stdout or str(exc.stderr or exc.stdout or ""))[-4000:]
        raise GhidraError(f"Ghidra timed out after {timeout}s: {detail}") from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _run_one(headless: Path, binary: Path, source_path: str, output_dir: Path, timeout: int, index: int) -> dict[str, Any]:
    module_dir = output_dir / "modules" / _module_slug(index, binary.name)
    module_dir.mkdir(parents=True, exist_ok=True)
    raw_path = module_dir / "analysis.json"
    with tempfile.TemporaryDirectory(prefix="ios-re-agent-ghidra-project-") as temporary:
        project_dir = Path(temporary) / "project"
        project_dir.mkdir()
        project_name = "ios_re_agent_module"
        pyghidra = headless.parent / "pyghidraRun"
        use_pyghidra = pyghidra.is_file() and os.access(pyghidra, os.X_OK)
        launcher = pyghidra if use_pyghidra else headless
        export_script = SCRIPT_PATH if use_pyghidra else JYTHON_SCRIPT_PATH
        command = [str(launcher)]
        if use_pyghidra:
            # pyghidraRun's first positional argument is the Ghidra install
            # directory. It then forwards the remaining arguments to
            # AnalyzeHeadless when --headless is selected.
            install_dir = pyghidra.parent.parent
            command.extend([str(install_dir), "--headless"])
        command.extend([
            str(project_dir), project_name,
            "-import", str(binary),
            "-scriptPath", str(SCRIPT_PATH.parent),
            # This must run before auto-analysis. The post-script alone was too late
            # and allowed expensive Obj-C analyzers to consume the entire timeout.
            "-preScript", PRE_ANALYSIS_SCRIPT_PATH.name,
            "-postScript", export_script.name, str(raw_path),
            "-deleteProject",
        ])
        completed = _run_headless(command, timeout)
        log_path = module_dir / "ghidra.log"
        log_text = "[stdout]\n" + (completed.stdout or "") + "\n[stderr]\n" + (completed.stderr or "")
        encoded_log = log_text.encode("utf-8", errors="replace")
        if len(encoded_log) > 4 * 1024 * 1024:
            log_text = "[log truncated to final 4 MiB]\n" + encoded_log[-(4 * 1024 * 1024):].decode("utf-8", errors="replace")
        log_path.write_text(log_text, encoding="utf-8")
        if completed.returncode != 0 or not raw_path.is_file():
            detail = (completed.stderr or completed.stdout or "No diagnostic output")[-5000:]
            raise GhidraError(
                f"Ghidra failed on {source_path} (exit={completed.returncode}); see {log_path}:\n{detail}"
            )
    try:
        payload = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError(f"Ghidra output JSON is invalid for {source_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise GhidraError(f"Ghidra output for {source_path} was not a JSON object.")
    payload["input_path"] = source_path
    payload["binary_name"] = binary.name
    payload["tool"] = {"name": "ios-re-agent-ghidra-adapter", "version": "0.3.0"}
    payload["limitations"] = ["Static decompilation only; target code was not executed.", "Pseudocode is generated by Ghidra and is not original source code.", "Objective-C message and type-metadata analyzers are disabled to avoid known headless timeouts; their specialized findings may therefore be absent.", "Results depend on binary readability, symbols, optimization, architecture support and Ghidra quality."]
    raw_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_native_markdown(payload, module_dir / "NATIVE_ANALYSIS.md")
    return {
        "source_path": source_path,
        "binary_name": binary.name,
        "size_bytes": binary.stat().st_size,
        "report_json": str(raw_path.relative_to(output_dir)),
        "report_markdown": str((module_dir / "NATIVE_ANALYSIS.md").relative_to(output_dir)),
        "log_path": str(log_path.relative_to(output_dir)),
        "function_count": payload.get("function_count", 0),
        "decompiled_count": payload.get("decompiled_count", 0),
        "string_count": payload.get("string_count", 0),
        "language": payload.get("language"),
    }


def decompile_artifact(
    input_path: str | Path,
    out_dir: str | Path,
    *,
    ghidra_home: str | Path | None = None,
    timeout: int = 900,
    max_binaries: int = DEFAULT_MAX_BINARIES,
    show_progress: bool = True,
) -> dict[str, Any]:
    """Decompile multiple executable Mach-O components using Ghidra, without execution.

    For IPA/.app inputs the adapter inventories bundle executables and embedded dylibs,
    stages only recognized Mach-O payloads into a temporary directory, and runs each
    through Ghidra independently. No DRM removal or code-signing bypass is attempted.
    """
    source = Path(input_path).expanduser().resolve()
    if not source.exists() or (not source.is_file() and not source.is_dir()):
        raise GhidraError(f"Input does not exist: {source}")
    if max_binaries < 1 or max_binaries > 250:
        raise GhidraError("max_binaries must be between 1 and 250.")
    headless = find_analyze_headless(ghidra_home)
    if headless is None:
        raise GhidraError("Ghidra's analyzeHeadless was not found. Install Ghidra and set GHIDRA_HOME to its installation directory.")
    if not SCRIPT_PATH.is_file():
        raise GhidraError(f"Bundled Ghidra export script is missing: {SCRIPT_PATH}")
    if not JYTHON_SCRIPT_PATH.is_file():
        raise GhidraError(f"Bundled Jython fallback script is missing: {JYTHON_SCRIPT_PATH}")
    if not PRE_ANALYSIS_SCRIPT_PATH.is_file():
        raise GhidraError(f"Bundled Ghidra pre-analysis script is missing: {PRE_ANALYSIS_SCRIPT_PATH}")
    output_dir = Path(out_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ios-re-agent-ghidra-") as temporary:
        staging = Path(temporary) / "binaries"
        staging.mkdir()
        if source.is_dir() and source.suffix.lower() == ".app":
            candidates = _stage_app_bundle(source, staging, max_binaries)
        elif source.suffix.lower() == ".ipa" and source.is_file():
            candidates = _stage_ipa(source, staging, max_binaries)
        elif source.is_file():
            if source.stat().st_size > MAX_EXECUTABLE_BYTES:
                raise GhidraError(f"Binary exceeds the {MAX_EXECUTABLE_BYTES} byte read limit.")
            if not _is_macho(source):
                raise GhidraError("Input file does not start with a recognized Mach-O magic value.")
            candidate = _stage_file(source, staging / f"000_{source.name}", source.name, [0])
            candidates = [candidate] if candidate else []
        else:
            raise GhidraError("Input must be an IPA, .app bundle, or Mach-O file.")
        if not candidates:
            raise GhidraError("No recognized Mach-O executables or dynamic libraries were found within the configured limits.")
        summaries: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for index, candidate in enumerate(candidates, start=1):
            if show_progress:
                sys.stderr.write(f"[ios-re-agent] Ghidra component {index}/{len(candidates)}: {candidate['source_path']}\n")
                sys.stderr.flush()
            try:
                summaries.append(_run_one(headless, Path(candidate["staged_path"]), str(candidate["source_path"]), output_dir, timeout, index))
            except GhidraError as exc:
                failures.append({"source_path": str(candidate["source_path"]), "error": str(exc)[:2000]})

    aggregate = {
        "schema_version": "1.0",
        "tool": {"name": "ios-re-agent-ghidra-adapter", "version": "0.3.0"},
        "input_name": source.name,
        "backend": "Ghidra headless (Objective-C message/type analyzers disabled)",
        "components_selected": len(candidates),
        "components_analyzed": len(summaries),
        "components_failed": len(failures),
        "function_count": sum(int(item.get("function_count", 0)) for item in summaries),
        "decompiled_count": sum(int(item.get("decompiled_count", 0)) for item in summaries),
        "string_count": sum(int(item.get("string_count", 0)) for item in summaries),
        "modules": summaries,
        "failures": failures,
        "limits": {"max_binaries": max_binaries, "max_bytes_per_binary": MAX_EXECUTABLE_BYTES, "max_total_native_bytes": MAX_TOTAL_NATIVE_BYTES},
        "limitations": ["Static decompilation only; no target code was executed.", "This examines native Mach-O components discovered through bundle metadata and dylib paths, not every resource file.", "Pseudocode is approximate and is not the original source code.", "Analysis may be incomplete because of encryption, stripped symbols, obfuscation, size limits, selected-component limits or backend failures."],
    }
    json_path = output_dir / "native-analysis.json"
    json_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# iOS-RE Agent — Native Component Analysis", "", f"- **Input:** `{source.name}`", "- **Backend:** Ghidra headless", f"- **Components selected:** {aggregate['components_selected']}", f"- **Components analyzed:** {aggregate['components_analyzed']}", f"- **Components failed:** {aggregate['components_failed']}", f"- **Functions discovered:** {aggregate['function_count']}", f"- **Functions decompiled:** {aggregate['decompiled_count']}", f"- **Strings exported:** {aggregate['string_count']}", "", "> Static decompilation produces approximate pseudocode, not original source code.", "", "## Native components", "", "| Source path | Language | Functions | Decompiled | String clues | Detailed report |", "|---|---|---:|---:|---:|---|"]
    for item in summaries:
        lines.append("| " + " | ".join(str(item.get(key) or "—").replace("|", "\\|") for key in ("source_path", "language", "function_count", "decompiled_count", "string_count", "report_markdown")) + " |")
    if failures:
        lines += ["", "## Failed components", ""]
        lines.extend(f"- `{row['source_path']}` — {row['error'].splitlines()[0]}" for row in failures)
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {note}" for note in aggregate["limitations"])
    lines += ["", "See each component's `NATIVE_ANALYSIS.md` and `analysis.json` for pseudocode, function names, call edges and strings.", ""]
    markdown_path = output_dir / "NATIVE_ANALYSIS.md"
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json_path": str(json_path), "markdown_path": str(markdown_path), **{key: aggregate[key] for key in ("components_selected", "components_analyzed", "components_failed", "function_count", "decompiled_count", "string_count")}}
