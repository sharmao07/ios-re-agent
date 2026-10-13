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
