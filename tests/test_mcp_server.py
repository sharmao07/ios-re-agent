from __future__ import annotations

import json

from ios_re_agent.mcp_server import TOOLS, _dispatch


def test_mcp_initialize_and_tools_list() -> None:
    response = _dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    assert response["result"]["serverInfo"]["name"] == "ios-re-agent"
    tools = _dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert {item["name"] for item in tools["result"]["tools"]} == {item["name"] for item in TOOLS}
    assert "analyze_ios_artifact" in {item["name"] for item in TOOLS}
    assert "discover_github_ipa_releases" in {item["name"] for item in TOOLS}
    assert "rea_native_operation" in {item["name"] for item in TOOLS}
    assert "analyze_ios_with_rea" in {item["name"] for item in TOOLS}


def test_mcp_list_ipa_sources_tool_returns_notice() -> None:
    response = _dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_ipa_sources", "arguments": {}}})
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["sources"]
    assert "Outbound links only" in payload["notice"]
