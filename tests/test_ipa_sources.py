from __future__ import annotations

import json

from ios_re_agent.ipa_sources import discover_github_ipa_releases, load_sources, search_sources


def test_catalog_contains_unverified_source_warning() -> None:
    rows = load_sources()
    community = next(item for item in rows if item["id"] == "ipa-library-community-index")
    assert community["trust_level"] == "unverified-third-party"
    assert "not endorsed" in community["safety_notes"]
    assert search_sources("community")


def test_github_discovery_returns_ipa_links_without_downloading() -> None:
    calls = []
    responses = [
        {"items": [{"full_name": "example/demo", "html_url": "https://github.com/example/demo", "license": {"spdx_id": "MIT"}}]},
        [{"name": "Demo 1.0", "tag_name": "v1", "html_url": "https://github.com/example/demo/releases/tag/v1", "published_at": "2026-01-01T00:00:00Z", "assets": [{"name": "Demo.ipa", "browser_download_url": "https://github.com/example/demo/releases/download/v1/Demo.ipa", "size": 1234}]}],
    ]

    class Response:
        def __init__(self, payload):
            self.payload = payload
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self, _limit):
            return json.dumps(self.payload).encode()

    def fake_open(request, timeout=0):
        calls.append((request.full_url, timeout))
        return Response(responses.pop(0))

    results = discover_github_ipa_releases("demo", opener=fake_open)
    assert len(results) == 1
    assert results[0]["asset_name"] == "Demo.ipa"
    assert results[0]["verification_status"].startswith("github_release_asset_found")
    assert len(calls) == 2
