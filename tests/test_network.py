from __future__ import annotations

from ios_re_agent.network import classify_url, extract_url_findings, sanitize_url, valid_hostname


def test_hostname_validation_rejects_suffix_noise_and_accepts_test_domains() -> None:
    assert valid_hostname("api.example.test")
    assert valid_hostname("api.pinterest.com")
    assert not valid_hostname("www.css")
    assert not valid_hostname("according")
    assert not valid_hostname("api..example.com")


def test_url_sanitization_removes_query_and_opaque_path_tokens() -> None:
    result = sanitize_url(b"https://api.example.test/v1/token=supersecret?access_token=private")
    assert result is not None
    assert "supersecret" not in result
    assert "private" not in result
    assert "<redacted>" in result


def test_url_findings_include_evidence_provenance() -> None:
    data = b"x https://api.example.test/v1/search?secret=abc y https://developer.apple.com/documentation"
    findings = extract_url_findings(data, "Frameworks/Demo.framework/Demo")
    assert len(findings) == 2
    assert findings[0]["source_path"] == "Frameworks/Demo.framework/Demo"
    assert findings[0]["byte_offset"] == 2
    assert findings[0]["classification"] == "possible_service_endpoint"
    assert classify_url("https://developer.apple.com/documentation") == "documentation_or_reference"
