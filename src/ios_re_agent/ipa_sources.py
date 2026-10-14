"""Outbound IPA discovery. No binaries are downloaded or mirrored by this module."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


def _catalog_path() -> Path:
    # Source checkout path is used in development. A packaged install may configure
    # IOS_RE_AGENT_SOURCES_FILE to point at a maintained catalog.
    import os
    override = os.environ.get("IOS_RE_AGENT_SOURCES_FILE")
    if override:
        return Path(override).expanduser()
    packaged = Path(__file__).resolve().parent / "data" / "ipa_sources.json"
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "sources" / "ipa_sources.json"


def load_sources(path: Path | None = None) -> list[dict[str, Any]]:
    catalog = path or _catalog_path()
    try:
        payload = json.loads(catalog.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read IPA source catalog at {catalog}: {exc}") from exc
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(sources, list):
        raise ValueError("IPA source catalog must contain a 'sources' list.")
    return [item for item in sources if isinstance(item, dict) and item.get("id") and item.get("url")]


def search_sources(query: str, path: Path | None = None) -> list[dict[str, Any]]:
    terms = {term.lower() for term in query.split() if term.strip()}
    results = []
    for source in load_sources(path):
        haystack = " ".join(str(source.get(key, "")) for key in ("name", "description", "kind", "safety_notes", "id")).lower()
        if not terms or all(term in haystack for term in terms):
            results.append(source)
    return results


def discover_github_ipa_releases(
    query: str,
    *,
    max_repositories: int = 8,
    timeout: float = 8.0,
    opener: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """Search public GitHub repo metadata then inspect recent release asset names.

    The function returns links only. It never downloads assets. Requests go to
    api.github.com and disclose the search query to GitHub. An injectable opener
    keeps tests deterministic and avoids network access in the test suite.
    """
    term = query.strip()
    if not term:
        raise ValueError("Provide an app or project name to search for public IPA releases.")
    if max_repositories < 1 or max_repositories > 20:
        raise ValueError("max_repositories must be between 1 and 20.")
    request_open = opener or urllib.request.urlopen

    def get_json(url: str) -> Any:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "ios-re-agent/0.3.0"},
        )
        try:
            with request_open(request, timeout=timeout) as response:
                payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"GitHub discovery request failed: {exc}") from exc
        if not isinstance(payload, (dict, list)):
            raise RuntimeError("GitHub returned an unexpected response.")
        return payload

    search_q = urllib.parse.urlencode({"q": f"{term} ipa in:name,description", "sort": "stars", "order": "desc", "per_page": str(max_repositories)})
    repos_payload = get_json(f"https://api.github.com/search/repositories?{search_q}")
    items = repos_payload.get("items", []) if isinstance(repos_payload, dict) else []
    if not isinstance(items, list):
        return []
    results: list[dict[str, Any]] = []
    for repo in items[:max_repositories]:
        if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str):
            continue
        # A repository license is a minimum signal for source-project provenance,
        # not proof that the attached binary itself may be redistributed.
        license_info = repo.get("license")
        if not isinstance(license_info, dict) or not license_info.get("spdx_id") or license_info.get("spdx_id") in {"NOASSERTION", "NONE"}:
            continue
        owner_repo = str(repo["full_name"])
        releases_url = f"https://api.github.com/repos/{owner_repo}/releases?per_page=5"
        releases_payload = get_json(releases_url)
        releases = releases_payload if isinstance(releases_payload, list) else releases_payload.get("items", [])
        if not isinstance(releases, list):
            continue
        for release in releases:
            if not isinstance(release, dict):
                continue
            assets = release.get("assets", [])
            if not isinstance(assets, list):
                continue
            for asset in assets:
                if not isinstance(asset, dict):
                    continue
                name = str(asset.get("name", ""))
                if name.lower().endswith(".ipa") and isinstance(asset.get("browser_download_url"), str):
                    results.append({
                        "repository": owner_repo,
                        "repository_url": repo.get("html_url"),
                        "release": release.get("name") or release.get("tag_name"),
                        "release_url": release.get("html_url"),
                        "published_at": release.get("published_at"),
                        "asset_name": name,
                        "asset_url": asset["browser_download_url"],
                        "asset_size_bytes": asset.get("size"),
                        "license_spdx_id": (repo.get("license") or {}).get("spdx_id") if isinstance(repo.get("license"), dict) else None,
                        "verification_status": "github_release_asset_found_not_security_or_license_verified",
                        "note": "Link only. Verify the project owner, release notes, redistribution rights, checksum/signature and package safety before use.",
                    })
    results.sort(key=lambda item: (item.get("published_at") or "", item.get("repository", "")), reverse=True)
    return results[:50]
