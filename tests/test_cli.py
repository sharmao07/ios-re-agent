from __future__ import annotations

import subprocess

from ios_re_agent import cli


def test_decompile_auto_uses_rea_when_installed(monkeypatch, tmp_path) -> None:
    calls = {}

    def fake_rea(source, output, *, provider, timeout, max_binaries):
        calls.update({"source": source, "output": output, "provider": provider, "timeout": timeout, "max_binaries": max_binaries})
        return {"backend": "upstream REA", "components_analyzed": 1, "components_failed": 0}

    monkeypatch.setattr(cli, "find_rea_cli", lambda: "/usr/local/bin/rea")
    monkeypatch.setattr(cli, "analyze_ipa_with_rea", fake_rea)
    monkeypatch.setattr(cli, "decompile_artifact", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Ghidra fallback should not run")))

    status = cli.main([
        "decompile", str(tmp_path / "Demo.ipa"), "--out", str(tmp_path / "out"),
        "--backend", "auto", "--provider", "ghidra", "--timeout", "120", "--max-binaries", "3",
    ])
    assert status == 0
    assert calls["output"] == tmp_path / "out"
    assert calls["provider"] == "ghidra"
    assert calls["timeout"] == 120
    assert calls["max_binaries"] == 3


def test_decompile_auto_falls_back_to_ghidra_when_rea_missing(monkeypatch, tmp_path) -> None:
    calls = {}

    def fake_ghidra(source, output, **kwargs):
        calls["kwargs"] = kwargs
        return {"backend": "Ghidra", "components_analyzed": 1, "components_failed": 0}

    monkeypatch.setattr(cli, "find_rea_cli", lambda: None)
    monkeypatch.setattr(cli, "decompile_artifact", fake_ghidra)
    status = cli.main(["decompile", str(tmp_path / "Demo.ipa"), "--backend", "auto"])
    assert status == 0
    assert calls["kwargs"]["timeout"] == 900


def test_rea_command_forwards_arguments_without_shell(monkeypatch) -> None:
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command
        captured["check"] = check
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(cli, "find_rea_cli", lambda: "/usr/local/bin/rea")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert cli.main(["rea", "--", "analyze", "/tmp/demo", "--provider", "ghidra", "--json"]) == 7
    assert captured["command"] == ["/usr/local/bin/rea", "analyze", "/tmp/demo", "--provider", "ghidra", "--json"]
    assert captured["check"] is False


def test_decompile_returns_failure_when_backend_reports_failed_components(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "find_rea_cli", lambda: None)
    monkeypatch.setattr(
        cli,
        "decompile_artifact",
        lambda *args, **kwargs: {"backend": "Ghidra", "components_analyzed": 0, "components_failed": 1},
    )
    assert cli.main(["decompile", str(tmp_path / "Demo.ipa"), "--backend", "ghidra"]) == 1
