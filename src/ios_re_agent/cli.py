"""Command-line interface."""

from __future__ import annotations

import argparse
import platform
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyzer import AnalysisError, analyze
from .report import write_json, write_markdown


def _doctor() -> int:
    print(f"iOS-RE Agent {__version__}")
    print(f"Python: {platform.python_version()} ({platform.system()} {platform.machine()})")
    print(f"Host: {platform.platform()}")
    print("Runtime dependencies: Python standard library only")
    tools = {
        "otool": "Optional: inspect native load commands on macOS",
        "plutil": "Optional: inspect Apple property lists on macOS",
        "ghidraRun": "Optional: deeper interactive native analysis (not invoked by this tool)",
    }
    for tool, purpose in tools.items():
        resolved = shutil.which(tool)
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
