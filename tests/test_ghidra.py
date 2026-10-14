from __future__ import annotations

from ios_re_agent.ghidra import _stage_app_bundle, _stage_ipa
from tests.helpers import write_app_bundle, write_ipa


def test_ghidra_stages_only_macho_components_from_app_bundle(tmp_path) -> None:
    app = write_app_bundle(tmp_path / "Demo.app")
    staged = _stage_app_bundle(app, tmp_path / "staging", max_binaries=20)
    assert staged
    assert any(item["source_path"] == "Demo" for item in staged)
    assert all(item["staged_path"].is_file() for item in staged)


def test_ghidra_stages_only_macho_components_from_ipa(tmp_path) -> None:
    ipa = write_ipa(tmp_path / "Demo.ipa")
    staged = _stage_ipa(ipa, tmp_path / "staging", max_binaries=20)
    assert any(item["source_path"] == "Payload/Demo.app/Demo" for item in staged)
    assert all(item["staged_path"].is_file() for item in staged)


def test_find_headless_supports_homebrew_layout(tmp_path, monkeypatch) -> None:
    from ios_re_agent.ghidra import find_analyze_headless

    root = tmp_path / "libexec" / "Ghidra"
    support = root.parent / "support"
    support.mkdir(parents=True)
    launcher = support / "analyzeHeadless"
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("ios_re_agent.ghidra.shutil.which", lambda name: None)

    assert find_analyze_headless(root) == launcher.resolve()


def test_run_one_uses_pygidra_and_objc_pre_script(tmp_path, monkeypatch) -> None:
    import json
    import subprocess
    from pathlib import Path

    from ios_re_agent import ghidra
    from tests.helpers import make_macho

    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    pyghidra = support / "pyghidraRun"
    for launcher in (headless, pyghidra):
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o755)
    binary = tmp_path / "Demo"
    binary.write_bytes(make_macho())
    captured = {}

    def fake_run(command, timeout):
        captured["command"] = command
        output_index = command.index("-postScript") + 2
        Path(command[output_index]).write_text(json.dumps({
            "function_count": 1,
            "decompiled_count": 1,
            "string_count": 0,
            "functions": [],
            "strings": [],
        }), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(ghidra, "_run_headless", fake_run)
    result = ghidra._run_one(headless, binary, "Payload/Demo.app/Demo", tmp_path / "out", 120, 1)
    command = captured["command"]
    assert command[0] == str(pyghidra)
    assert command[1] == str(support.parent)
    assert command[2] == "--headless"
    assert command[command.index("-preScript") + 1] == ghidra.PRE_ANALYSIS_SCRIPT_PATH.name
    assert command[command.index("-postScript") + 1] == "ExportAnalysis.py"
    assert result["decompiled_count"] == 1
