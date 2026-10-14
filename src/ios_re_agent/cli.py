"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyzer import AnalysisError, analyze
from .ghidra import GhidraError, decompile_artifact, find_analyze_headless
from .ipa_sources import discover_github_ipa_releases, load_sources, search_sources
from .rea_backend import ReaBackendError, analyze_ipa_with_rea, find_rea_cli, run_native_operation
from .report import write_json, write_markdown


def _node_version_is_supported(version: str) -> bool:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version.strip())
    if not match:
        return False
    major, minor, _patch = (int(part) for part in match.groups())
    return major >= 26 or (major == 24 and minor >= 11) or (major == 22 and minor >= 19)


def _doctor() -> int:
    print(f"iOS-RE Agent {__version__}")
    print(f"Python: {platform.python_version()} ({platform.system()} {platform.machine()})")
    print(f"Host: {platform.platform()}")
    print("Runtime dependencies: Python standard library only")
    tools = {
        "otool": "Optional: inspect native load commands on macOS",
        "plutil": "Optional: inspect Apple property lists on macOS",
        "ghidraRun": "Optional: interactive native-analysis GUI",
        "analyzeHeadless": "Optional: native pseudocode/function extraction via Ghidra headless",
        "pyghidraRun": "Optional: Python-based Ghidra headless launcher",
        "node": "Runtime required by upstream REA CLI",
        "rea": "Upstream REA native-analysis CLI (install rea-agents with npm)",
    }
    for tool, purpose in tools.items():
        resolved = shutil.which(tool)
        if tool == "analyzeHeadless" and not resolved:
            headless = find_analyze_headless()
            resolved = str(headless) if headless else None
        if tool == "pyghidraRun" and not resolved:
            headless = find_analyze_headless()
            candidate = headless.parent / "pyghidraRun" if headless else None
            resolved = str(candidate) if candidate and candidate.is_file() else None
        status = f"found at {resolved}" if resolved else "not found (optional)"
        if tool == "node" and resolved:
            try:
                completed = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=5, check=False)
                version = (completed.stdout or completed.stderr).strip()
                if version:
                    status += f" ({version})"
                    if not _node_version_is_supported(version):
                        status += "; below REA's supported versions — use Node.js 22.19+, 24.11+, or 26+"
            except (OSError, subprocess.SubprocessError):
                status += " (version check failed)"
        print(f"{tool}: {status} — {purpose}")
    print("Safety: package inspection is read-only; target application code is not executed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ios-re-agent",
        description="Evidence-first static inspection for authorized iOS app artifacts.",
        epilog="Example: ios-re-agent analyze MyApp.ipa --out reports/MyApp",
    )
    parser.add_argument("--version", action="version", version=f"ios-re-agent {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an .ipa, .app bundle directory, or Mach-O file")
    analyze_parser.add_argument("input", type=Path, help="Path to an authorized IPA, .app directory, or binary")
    analyze_parser.add_argument("--out", type=Path, default=Path("reports/ios-re-agent"),
                                help="Output directory (default: reports/ios-re-agent)")
    analyze_parser.add_argument("--json-only", action="store_true", help="Write report.json only")
    analyze_parser.add_argument("--markdown-only", action="store_true", help="Write REPORT.md only")

    decompile_parser = subparsers.add_parser("decompile", help="Native analysis of an authorized IPA, .app or Mach-O using upstream REA or the Ghidra fallback")
    decompile_parser.add_argument("input", type=Path, help="IPA, .app bundle, or binary to inspect")
    decompile_parser.add_argument("--out", type=Path, default=Path("reports/native-analysis"), help="Output directory")
    decompile_parser.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory (or set GHIDRA_HOME)")
    decompile_parser.add_argument("--timeout", type=int, default=900, help="Maximum analysis time per native component in seconds (30-3600)")
    decompile_parser.add_argument("--max-binaries", type=int, default=100, help="Maximum embedded Mach-O components to analyze (1-250)")
    decompile_parser.add_argument("--backend", choices=("auto", "rea", "ghidra"), default="auto", help="Prefer upstream REA when installed; otherwise use bundled Ghidra adapter")
    decompile_parser.add_argument("--provider", choices=("ghidra", "hopper", "ida"), default="ghidra", help="Upstream REA native provider when backend is rea/auto")

    sources_parser = subparsers.add_parser("sources", help="Search the outbound IPA source catalog")
    source_subparsers = sources_parser.add_subparsers(dest="sources_command", required=True)
    source_subparsers.add_parser("list", help="List configured IPA discovery sources")
    source_search = source_subparsers.add_parser("search", help="Search configured sources by keyword")
    source_search.add_argument("query", help="Keyword(s) such as official, community, or GitHub")
    source_discover = source_subparsers.add_parser("discover", help="Search public GitHub metadata for release assets ending in .ipa")
    source_discover.add_argument("query", help="App or project name")
    source_discover.add_argument("--max-repositories", type=int, default=8, help="Repositories to inspect (1-20)")
    rea_ipa_parser = subparsers.add_parser(
        "rea-ipa", help="Analyze native components in an IPA/.app through upstream REA"
    )
    rea_ipa_parser.add_argument("input", type=Path, help="Authorized IPA, .app bundle, or Mach-O binary")
    rea_ipa_parser.add_argument("--out", type=Path, default=Path("reports/rea-native-analysis"), help="Output directory")
    rea_ipa_parser.add_argument("--provider", choices=("ghidra", "hopper", "ida"), default="ghidra", help="Upstream REA native provider")
    rea_ipa_parser.add_argument("--timeout", type=int, default=300, help="Maximum seconds per native component (30-3600)")
    rea_ipa_parser.add_argument("--max-binaries", type=int, default=20, help="Maximum native components to inspect (1-250)")

    native_parser = subparsers.add_parser(
        "rea-native", help="Run an upstream REA native-analysis operation on a binary/app"
    )
    native_parser.add_argument("operation", choices=("analyze", "search", "function", "decompile", "xrefs", "trace", "instructions"))
    native_parser.add_argument("target", type=Path, help="Native Mach-O binary or supported .app bundle")
    native_parser.add_argument("query", nargs="?", help="Search query, function name, or address as required by the operation")
    native_parser.add_argument("--provider", choices=("ghidra", "hopper", "ida"), default="ghidra")
    native_parser.add_argument("--timeout", type=int, default=300, help="Maximum seconds (1-3600)")

    rea_parser = subparsers.add_parser(
        "rea", help="Forward a CLI command to upstream REA (requires installed rea-agents)"
    )
    rea_parser.add_argument("rea_args", nargs=argparse.REMAINDER, help="Pass upstream REA arguments after `--`")

    subparsers.add_parser("mcp", help="Start the MCP stdio server for compatible AI agents")
    subparsers.add_parser("doctor", help="Check Python and optional local analysis tools")
    subparsers.add_parser("version", help="Print the installed version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "mcp":
        from .mcp_server import serve
        return serve()
    if args.command == "rea-native":
        if args.timeout < 1 or args.timeout > 3600:
            parser.error("--timeout must be between 1 and 3600 seconds.")
        try:
            result = run_native_operation(
                args.operation, args.target, query=args.query,
                provider=args.provider, timeout=args.timeout,
            )
        except (ReaBackendError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("returncode") == 0 else 1
    if args.command == "rea":
        cli = find_rea_cli()
        if not cli:
            print(
                "error: upstream REA was not found. Install a supported Node.js release "
                "and run `npm install --global rea-agents`.",
                file=sys.stderr,
            )
            return 2
        forwarded = list(args.rea_args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        if not forwarded:
            forwarded = ["--help"]
        try:
            completed = subprocess.run([cli, *forwarded], check=False)
            return int(completed.returncode)
        except OSError as exc:
            print(f"error: could not launch upstream REA: {exc}", file=sys.stderr)
            return 2
    if args.command == "rea-ipa":
        if args.timeout < 30 or args.timeout > 3600:
            parser.error("--timeout must be between 30 and 3600 seconds.")
        if args.max_binaries < 1 or args.max_binaries > 250:
            parser.error("--max-binaries must be between 1 and 250.")
        try:
            result = analyze_ipa_with_rea(
                args.input, args.out, provider=args.provider,
                timeout=args.timeout, max_binaries=args.max_binaries,
            )
        except (ReaBackendError, GhidraError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print("REA native analysis finished:")
        for key, value in result.items():
            print(f"  {key}: {value}")
        if result.get("components_failed", 0) or result.get("components_with_unparsed_output", 0):
            print(
                "Some components failed or returned output that could not be parsed as JSON; inspect per-component evidence and diagnostics.",
                file=sys.stderr,
            )
            return 1
        print("Reminder: this is static evidence, not recovered original source or verified runtime behavior.")
        return 0
    if args.command == "sources":
        try:
            if args.sources_command == "list":
                rows = load_sources()
            elif args.sources_command == "search":
                rows = search_sources(args.query)
            else:
                rows = discover_github_ipa_releases(args.query, max_repositories=args.max_repositories)
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        except (ValueError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.sources_command == "discover":
            print("\nNotice: GitHub received this search query. Results are links only; assets are not downloaded or verified.", file=sys.stderr)
        return 0
    if args.command == "decompile":
        if args.timeout < 30 or args.timeout > 3600:
            parser.error("--timeout must be between 30 and 3600 seconds.")
        if args.max_binaries < 1 or args.max_binaries > 250:
            parser.error("--max-binaries must be between 1 and 250.")
        try:
            use_rea = args.backend == "rea" or (args.backend == "auto" and find_rea_cli() is not None)
            if use_rea:
                if find_rea_cli() is None:
                    raise ReaBackendError(
                        "--backend rea requires upstream REA. Install a supported Node.js release and run `npm install --global rea-agents`."
                    )
                result = analyze_ipa_with_rea(
                    args.input, args.out, provider=args.provider,
                    timeout=args.timeout, max_binaries=args.max_binaries,
                )
            else:
                result = decompile_artifact(
                    args.input, args.out, ghidra_home=args.ghidra_home,
                    timeout=args.timeout, max_binaries=args.max_binaries,
                )
        except (ReaBackendError, GhidraError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print("Native analysis complete:")
        for key, value in result.items():
            print(f"  {key}: {value}")
        print("Reminder: decompiled pseudocode is approximate; validate conclusions with evidence.")
        if result.get("components_failed", 0) or result.get("components_with_unparsed_output", 0):
            print(
                "Some components failed or returned output that could not be parsed as JSON; inspect the report and diagnostics.",
                file=sys.stderr,
            )
            return 1
        return 0
    if args.json_only and args.markdown_only:
        parser.error("--json-only and --markdown-only cannot be used together.")

    try:
        report = analyze(args.input)
        args.out.mkdir(parents=True, exist_ok=True)
        if not args.markdown_only:
            write_json(report, args.out / "report.json")
        if not args.json_only:
            write_markdown(report, args.out / "REPORT.md")
    except (AnalysisError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Analysis complete: {args.out.resolve()}")
    if not args.markdown_only:
        print(f"  JSON: {args.out / 'report.json'}")
    if not args.json_only:
        print(f"  Markdown: {args.out / 'REPORT.md'}")
    print("Reminder: findings are static indicators; verify conclusions with authorized evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
