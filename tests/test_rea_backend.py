from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ios_re_agent import rea_backend
from tests.helpers import write_ipa


def test_find_rea_cli_prefers_installed_cli(monkeypatch) -> None:
    monkeypatch.setattr(rea_backend.shutil, "which", lambda name: "/usr/local/bin/rea" if name == "rea" else None)
    assert rea_backend.find_rea_cli() == "/usr/local/bin/rea"


def test_run_native_operation_passes_supported_args_and_parses_json(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "demo"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    seen = {}

    def fake_run(command, *, timeout, cwd=None):
        seen["command"] = command
        seen["timeout"] = timeout
        return subprocess.CompletedProcess(command, 0, '{"function_count": 4}', "")

    monkeypatch.setattr(rea_backend, "find_rea_cli", lambda: "/usr/local/bin/rea")
    monkeypatch.setattr(rea_backend, "_run_process", fake_run)
    result = rea_backend.run_native_operation("analyze", binary, provider="ghidra", timeout=77)

    assert seen["command"] == ["/usr/local/bin/rea", "analyze", str(binary.resolve()), "--provider", "ghidra", "--json"]
    assert seen["timeout"] == 77
    assert result["evidence"]["function_count"] == 4
    assert result["json_valid"] is True


def test_run_native_operation_requires_query_for_decompile(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "demo"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    monkeypatch.setattr(rea_backend, "find_rea_cli", lambda: "/usr/local/bin/rea")
    with pytest.raises(ValueError, match="requires a non-empty"):
        rea_backend.run_native_operation("decompile", binary)


def test_analyze_ipa_with_rea_writes_manifest_and_per_component_evidence(monkeypatch, tmp_path: Path) -> None:
    ipa = write_ipa(tmp_path / "Demo.ipa")

    def fake_operation(operation, target, *, query=None, provider="ghidra", timeout=300):
        assert operation == "analyze"
        assert Path(target).is_file()
        return {
            "command": ["analyze", str(target), "--provider", provider, "--json"],
            "returncode": 0,
            "json_valid": True,
            "stderr": "",
            "evidence": {"function_count": 7, "functions": [{"name": "entry"}]},
        }

    monkeypatch.setattr(rea_backend, "run_native_operation", fake_operation)
    result = rea_backend.analyze_ipa_with_rea(ipa, tmp_path / "rea-out", max_binaries=5)
    manifest = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))

    assert manifest["components_selected"] == 1
    assert manifest["components_analyzed"] == 1
    assert manifest["components_failed"] == 0
    assert manifest["modules"][0]["source_path"] == "Payload/Demo.app/Demo"
    evidence_path = Path(result["json_path"]).parent / manifest["modules"][0]["result_file"]
    saved = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved["function_count"] == 7


def test_node_version_support_matches_upstream_engine_range() -> None:
    from ios_re_agent.cli import _node_version_is_supported

    assert _node_version_is_supported("v22.19.0")
    assert _node_version_is_supported("v24.11.1")
    assert _node_version_is_supported("v26.0.0")
    assert _node_version_is_supported("v27.0.0")
    assert not _node_version_is_supported("v22.16.0")
    assert not _node_version_is_supported("v24.10.9")
    assert not _node_version_is_supported("v25.0.0")
