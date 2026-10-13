from __future__ import annotations

import json
import zipfile

from ios_re_agent.analyzer import AnalysisError, analyze
from ios_re_agent.report import write_json, write_markdown
from tests.helpers import write_app_bundle, write_ipa


def test_analyzes_ipa_without_extracting(tmp_path) -> None:
    ipa = write_ipa(tmp_path / "Demo.ipa")
    report = analyze(ipa)
    assert report["input"]["type"] == "ipa"
    assert report["app"]["bundle_identifier"] == "org.example.Demo"
    assert report["app"]["url_schemes"] == ["demoapp"]
    assert "api.example.test" in report["network_indicators"]["candidate_hosts"]
    assert all("do-not-print" not in endpoint for endpoint in report["network_indicators"]["candidate_endpoints"])
    assert any("<redacted>" in endpoint for endpoint in report["network_indicators"]["candidate_endpoints"])
    assert "do-not-print" not in json.dumps(report)
    assert "pathsecret" not in json.dumps(report)
    assert "user:pass" not in json.dumps(report)
    assert report["inventory"]["file_count"] >= 4
    with zipfile.ZipFile(ipa) as zf:
        assert "Payload/Demo.app/Demo" in zf.namelist()


def test_analyzes_app_bundle_framework_extension_and_privacy(tmp_path) -> None:
    app = write_app_bundle(tmp_path / "Demo.app")
    report = analyze(app)
    assert report["input"]["type"] == "app_bundle"
    assert "DemoKit.framework" in report["inventory"]["frameworks_and_dynamic_libraries"]
    assert report["inventory"]["app_extensions"][0]["extension_point"] == "com.apple.share-services"
    assert report["inventory"]["privacy_manifests"][0]["tracking"] is False
    assert report["app"]["privacy_usage_descriptions"][0]["key"] == "NSCameraUsageDescription"
    assert report["macho"]["slices"][0]["architecture"] == "arm64"


def test_report_files_are_written(tmp_path) -> None:
    report = analyze(write_ipa(tmp_path / "Demo.ipa"))
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "REPORT.md"
    write_json(report, json_path)
    write_markdown(report, md_path)
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "1.0"
    assert "Limitations and interpretation" in md_path.read_text(encoding="utf-8")


def test_rejects_non_app_directory(tmp_path) -> None:
    folder = tmp_path / "not-an-app"
    folder.mkdir()
    try:
        analyze(folder)
    except AnalysisError as exc:
        assert "must be an .app" in str(exc)
    else:
        raise AssertionError("Expected AnalysisError")


def test_rejects_malformed_ipa_archive(tmp_path) -> None:
    broken = tmp_path / "broken.ipa"
    broken.write_bytes(b"not a zip file")
    try:
        analyze(broken)
    except AnalysisError as exc:
        assert "Could not open archive" in str(exc)
    else:
        raise AssertionError("Expected AnalysisError")


def test_binary_input_reports_type(tmp_path) -> None:
    from tests.helpers import make_macho

    binary = tmp_path / "Demo"
    binary.write_bytes(make_macho())
    report = analyze(binary)
    assert report["input"]["type"] == "macho_binary"
    assert report["macho"]["slices"][0]["architecture"] == "arm64"
