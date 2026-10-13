"""Network-string normalization and conservative classification.

All results are static string evidence. This module never connects to discovered hosts.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

URL_RE = re.compile(rb"https?://[^\x00-\x20\"'<>\\]{4,512}", re.IGNORECASE)
SENSITIVE_PATH_SEGMENT = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|session|authorization)[=:_-].+"
)
LONG_OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{28,}$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".pdf", ".html", ".htm", ".mp4", ".m3u8", ".json",
)
DOC_HOST_FRAGMENTS = (
    "developer.apple.com", "developer.mozilla.org", "developers.google.com", "developers.facebook.com",
    "chromium.googlesource.com", "tools.ietf.org", "w3.org", "webkit.org", "github.com",
)
PLACEHOLDER_HOSTS = {
    "example.com", "example.org", "example.net", "example.invalid", "put.your.url.here",
    "localhost", "test.local", "report-example.test", "my-pac-script.invalid",
}
SERVICE_HOST_HINTS = (
    "api", "graphql", "analytics", "events", "event", "tracking", "trk", "ads", "auth",
    "oauth", "login", "sessions", "crash", "bugsnag", "sentry", "telemetry", "metrics",
    "pintrace", "pinadmin", "firebase", "appsflyer",
)
SERVICE_PATH_HINTS = ("/api/", "/graphql", "/oauth", "/token", "/v1/", "/v2/", "/v3/", "/events", "/track", "/session")
NON_TLD_SUFFIXES = {"css", "js", "mjs", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "html", "htm", "json", "xml", "pdf", "mp4", "m3u8", "icon", "map"}


def valid_hostname(hostname: str | None) -> bool:
    """Reject malformed / low-quality candidates without assuming a host is reachable."""
    if not hostname:
        return False
    host = hostname.rstrip(".").lower()
    if len(host) > 253 or not host or ".." in host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        return False
    tld = labels[-1]
    # Real DNS names generally have alphabetic IDNA TLDs. Preserve test domains
    # for fixtures and research examples, but reject suffix-like noise such as .css.
    return ((len(tld) >= 2 and (tld.isalpha() or tld.startswith("xn--")) and tld not in NON_TLD_SUFFIXES)
            or tld in {"test", "invalid", "localhost"})


def sanitize_url(raw: bytes | str) -> str | None:
    """Return a conservative URL with secrets in path/query values redacted."""
    text = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else raw
    text = text.rstrip(".,);]}>\x00")
    try:
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not valid_hostname(parsed.hostname):
            return None
        host = (parsed.hostname or "").lower().rstrip(".")
        if host == "www.apple.com" and parsed.path.startswith("/DTDs/PropertyList-"):
            return None
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        segments: list[str] = []
        for segment in parsed.path.split("/"):
            if SENSITIVE_PATH_SEGMENT.search(segment) or LONG_OPAQUE_SEGMENT.fullmatch(segment):
                segments.append("<redacted>")
            else:
                segments.append(segment[:120])
        path = "/".join(segments)[:400]
        suffix = "?<redacted>" if parsed.query else ""
        return urlunsplit((parsed.scheme.lower(), host + port, path, "", "")) + suffix
    except (ValueError, UnicodeError):
        return None


def classify_url(url: str) -> str:
    """Classify a sanitized URL as a clue, not a claim about actual network traffic."""
    try:
        parsed = urlsplit(url.replace("?<redacted>", ""))
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
    except ValueError:
        return "low_quality"
    if host in PLACEHOLDER_HOSTS or host.endswith((".example", ".invalid")):
        return "placeholder_or_test"
    if any(fragment in host for fragment in DOC_HOST_FRAGMENTS):
        return "documentation_or_reference"
    if path.endswith(STATIC_SUFFIXES):
        return "static_asset_or_document"
    host_labels = set(host.split("."))
    if any(hint in label for label in host_labels for hint in SERVICE_HOST_HINTS) or any(hint in path for hint in SERVICE_PATH_HINTS):
        return "possible_service_endpoint"
    if path in {"", "/", "/login", "/privacy", "/privacy-policy", "/terms"}:
        return "site_or_landing_page"
    return "unclassified_url"


def extract_url_findings(data: bytes, source_path: str, max_urls: int = 200) -> list[dict[str, object]]:
    """Extract sanitized URL clues with source paths and byte offsets."""
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(data):
        clean = sanitize_url(match.group(0))
        if not clean or clean in seen:
            continue
        seen.add(clean)
        try:
            host = urlsplit(clean.replace("?<redacted>", "")).hostname
        except ValueError:
            host = None
        results.append({
            "url": clean,
            "host": (host or "").lower(),
            "classification": classify_url(clean),
            "source_path": source_path,
            "byte_offset": match.start(),
            "confidence": "low",
            "interpretation": "Static string only; this does not prove the URL is requested at runtime.",
        })
        if len(results) >= max_urls:
            break
    return results
