"""Small MCP stdio server exposing iOS-RE Agent as agent-callable tools.

The server is intentionally dependency-free and emits only JSON-RPC messages to stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import analyze
from .ghidra import decompile_artifact
from .ipa_sources import discover_github_ipa_releases, load_sources, search_sources
from .report import write_json, write_markdown

SERVER_INFO = {"name": "ios-re-agent", "version": __version__}

TOOLS = [
    {
        "name": "analyze_ios_artifact",
        "description": "Run bounded, read-only static analysis on a locally accessible authorized .ipa, .app bundle or Mach-O file. Writes JSON/Markdown reports and returns a summary; never executes the target app.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Absolute path to the IPA, .app directory or Mach-O binary."}, "out_dir": {"type": "string", "description": "Directory for generated reports. Defaults to reports/mcp-analysis."}}, "required": ["path"], "additionalProperties": False},
    },
    {
        "name": "decompile_ios_native_code",
        "description": "Use an already-installed Ghidra headless analyzer to statically decompile an authorized IPA's main executable, .app executable or Mach-O file. Requires Ghidra; does not bypass encryption or execute target code.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "out_dir": {"type": "string"}, "ghidra_home": {"type": "string"}, "timeout_seconds": {"type": "integer", "minimum": 30, "maximum": 3600}, "max_binaries": {"type": "integer", "minimum": 1, "maximum": 250}}, "required": ["path", "out_dir"], "additionalProperties": False},
    },
    {
        "name": "search_analysis_report",
        "description": "Search an existing report.json for a term and return matching JSON paths and small snippets, including feature and endpoint provenance when available.",
        "inputSchema": {"type": "object", "properties": {"report_path": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, "required": ["report_path", "query"], "additionalProperties": False},
    },
    {
        "name": "get_feature_map",
        "description": "Return conservative feature hypotheses from a generated report.json. Each hypothesis links to supporting package paths and clearly labels confidence.",
        "inputSchema": {"type": "object", "properties": {"report_path": {"type": "string"}}, "required": ["report_path"], "additionalProperties": False},
    },
    {
        "name": "list_ipa_sources",
        "description": "List configured outbound IPA discovery source links with trust and verification labels. No IPA binary is downloaded or hosted by this tool.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "search_ipa_sources",
        "description": "Search the local outbound source catalog by keyword; community sources are marked unverified and may link to modified apps.",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"], "additionalProperties": False},
    },
    {
        "name": "discover_github_ipa_releases",
        "description": "Search public GitHub repository metadata and release assets for IPA files; returns external links only. This sends the search query to GitHub and does not download binaries.",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "max_repositories": {"type": "integer", "minimum": 1, "maximum": 20}}, "required": ["query"], "additionalProperties": False},
    },
]


def _text_result(payload: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}


def _load_report(path_text: str) -> dict[str, Any]:
    path = Path(path_text).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Report file does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Report JSON root must be an object.")
    return payload


def _search_report(payload: dict[str, Any], query: str, limit: int) -> list[dict[str, Any]]:
    needle = query.strip().lower()
    if not needle:
        raise ValueError("query must not be empty")
    results: list[dict[str, Any]] = []

    def visit(value: Any, path: str) -> None:
        if len(results) >= limit:
            return
        if isinstance(value, dict):
            # When an evidence object has source_path, carry it into the hit.
            source_path = value.get("source_path") if isinstance(value.get("source_path"), str) else None
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                if isinstance(child, (str, int, float, bool)) and needle in str(child).lower():
                    results.append({"json_path": child_path, "value": str(child)[:500], "source_path": source_path})
                    if len(results) >= limit:
                        return
                elif isinstance(child, (dict, list)):
                    visit(child, child_path)
                    if len(results) >= limit:
                        return
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
                if len(results) >= limit:
                    return

    visit(payload, "")
    return results


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "analyze_ios_artifact":
        input_path = Path(str(arguments["path"])).expanduser()
        out_dir = Path(str(arguments.get("out_dir", "reports/mcp-analysis"))).expanduser()
        report = analyze(input_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "report.json"
        markdown_path = out_dir / "REPORT.md"
        write_json(report, json_path)
        write_markdown(report, markdown_path)
        return {"input": report.get("input"), "app": report.get("app", {}), "report_json": str(json_path.resolve()), "report_markdown": str(markdown_path.resolve()), "framework_count": len(report.get("inventory", {}).get("frameworks_and_dynamic_libraries", [])), "features": report.get("feature_map", []), "limitations": report.get("limitations", [])}
    if name == "decompile_ios_native_code":
        return decompile_artifact(arguments["path"], arguments["out_dir"], ghidra_home=arguments.get("ghidra_home"), timeout=int(arguments.get("timeout_seconds", 900)), max_binaries=int(arguments.get("max_binaries", 100)), show_progress=False)
    if name == "search_analysis_report":
        report = _load_report(str(arguments["report_path"]))
        limit = max(1, min(int(arguments.get("limit", 20)), 50))
        return {"query": arguments["query"], "matches": _search_report(report, str(arguments["query"]), limit)}
    if name == "get_feature_map":
        report = _load_report(str(arguments["report_path"]))
        return {"input": report.get("input"), "features": report.get("feature_map", []), "interpretation": "Hypotheses based on static package evidence, not verified runtime behavior."}
    if name == "list_ipa_sources":
        return {"sources": load_sources(), "notice": "Outbound links only. Sources are not all independently audited; review provenance and legal rights."}
    if name == "search_ipa_sources":
        return {"sources": search_sources(str(arguments["query"])), "notice": "Outbound links only; do not assume a source or binary is safe, legal to redistribute, or current."}
    if name == "discover_github_ipa_releases":
        rows = discover_github_ipa_releases(str(arguments["query"]), max_repositories=int(arguments.get("max_repositories", 8)))
        return {"results": rows, "notice": "The search query was sent to GitHub's public API. Links only; assets were not downloaded or verified."}
    raise ValueError(f"Unknown tool: {name}")


def _dispatch(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    is_notification = "id" not in message
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": str(message.get("params", {}).get("protocolVersion", "2024-11-05")), "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO, "instructions": "Use only authorized artifacts. Treat findings as static evidence, never as proof of runtime behavior. Ask before invoking online IPA discovery; it sends a query to GitHub."}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            result = _call_tool(str(name), arguments)
            response = _text_result(result)
        except (KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
            response = {"isError": True, "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}]}
        return {"jsonrpc": "2.0", "id": request_id, "result": response}
    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def serve() -> int:
    """Serve one JSON-RPC message per line over stdin/stdout."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("JSON-RPC request must be an object")
            result = _dispatch(message)
            if result is not None:
                sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:  # Don't crash the stdio protocol on malformed input.
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": str(exc)}}
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0
