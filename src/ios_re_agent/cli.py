"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyzer import AnalysisError, analyze
from .ghidra import GhidraError, decompile_artifact, find_analyze_headless
from .ipa_sources import discover_github_ipa_releases, load_sources, search_sources
from .report import write_json, write_markdown


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
    }
    for tool, purpose in tools.items():
        resolved = shutil.which(tool)
        if tool == "analyzeHeadless" and not resolved:
            headless = find_analyze_headless()
            resolved = str(headless) if headless else None
        status = f"found at {resolved}" if resolved else "not found (optional)"
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

    decompile_parser = subparsers.add_parser("decompile", help="Optional Ghidra decompilation of an authorized IPA, .app or Mach-O executable")
    decompile_parser.add_argument("input", type=Path, help="IPA, .app bundle, or binary to inspect")
    decompile_parser.add_argument("--out", type=Path, default=Path("reports/native-analysis"), help="Output directory")
    decompile_parser.add_argument("--ghidra-home", type=Path, help="Ghidra installation directory (or set GHIDRA_HOME)")
    decompile_parser.add_argument("--timeout", type=int, default=900, help="Maximum analysis time per native component in seconds (30-3600)")
    decompile_parser.add_argument("--max-binaries", type=int, default=100, help="Maximum embedded Mach-O components to analyze (1-250)")

    sources_parser = subparsers.add_parser("sources", help="Search the outbound IPA source catalog")
    source_subparsers = sources_parser.add_subparsers(dest="sources_command", required=True)
    source_subparsers.add_parser("list", help="List configured IPA discovery sources")
    source_search = source_subparsers.add_parser("search", help="Search configured sources by keyword")
    source_search.add_argument("query", help="Keyword(s) such as official, community, or GitHub")
    source_discover = source_subparsers.add_parser("discover", help="Search public GitHub metadata for release assets ending in .ipa")
    source_discover.add_argument("query", help="App or project name")
    source_discover.add_argument("--max-repositories", type=int, default=8, help="Repositories to inspect (1-20)")
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
            result = decompile_artifact(args.input, args.out, ghidra_home=args.ghidra_home, timeout=args.timeout, max_binaries=args.max_binaries)
        except (GhidraError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print("Native analysis complete:")
        for key, value in result.items():
            print(f"  {key}: {value}")
        print("Reminder: decompiled pseudocode is approximate; validate conclusions with evidence.")
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
