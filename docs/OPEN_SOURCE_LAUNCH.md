# Open-source launch checklist

Use this checklist before tagging a public release. Version 0.2.0 is a preview until host-specific Ghidra tests and release checks are complete.

## 1. Repository hygiene

- [ ] Confirm the repository contains source code, synthetic fixtures and documentation only.
- [ ] Confirm no `.ipa`, `.app`, `.xcarchive`, private reports, tokens, certificates, API keys or personal paths are committed.
- [ ] Review `git status --short` and `git diff --check`.
- [ ] Review all outbound IPA sources. Keep trust/verification labels and do not mirror the binary files.
- [ ] Confirm the MIT license is appropriate for the original code; keep third-party licenses/attributions separate.

## 2. Automated checks

Run locally from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m build
```

If `python -m build` isn't available, install the `build` development tool in the environment and retry. CI should be green before a release tag.

## 3. Test the workflows

- [ ] Analyze the synthetic `.ipa` fixture and check report JSON schema.
- [ ] Confirm token-like path segments and query values are not present in reports.
- [ ] Confirm source paths/byte offsets point to the expected fixture locations.
- [ ] Start MCP from the client configuration and verify `tools/list` and local tools.
- [ ] If Ghidra is installed, decompile a redistributable test binary and an authorized sample `.app`; inspect root and per-module reports.
- [ ] Test Ghidra with an encrypted/unreadable or unsupported binary and verify the report says what failed instead of implying success.
- [ ] Confirm `sources discover` sends a query to GitHub only when explicitly invoked and never downloads an IPA asset.

## 4. Documentation and scope

- [ ] Make the README install instructions work in a fresh virtual environment.
- [ ] Document supported Python/Ghidra versions based on tests, not guesses.
- [ ] State that decompiler pseudocode is approximate and cannot guarantee full original source recovery.
- [ ] Clearly label candidate network indicators and feature hypotheses.
- [ ] Review `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `CHANGELOG.md` and `docs/ROADMAP.md`.
- [ ] Include a screenshot/gif only if it contains no third-party app binary content or private data.

## 5. Release

- [ ] Merge the final reviewed changes to `main`.
- [ ] Create a version tag consistent with `pyproject.toml` and `src/ios_re_agent/__init__.py`.
- [ ] Publish release notes with known limitations and test environment details.
- [ ] Attach only source packages/release artifacts you own and are licensed to distribute. Never attach a target app's IPA or analysis report without permission.
- [ ] Monitor issues for false positives, unsupported binaries, Ghidra compatibility and false claims in documentation.

## Suggested release note template

```markdown
## iOS-RE Agent vX.Y.Z

### Added
- ...

### Changed
- ...

### Verification
- Python versions:
- macOS version/architecture:
- Ghidra version (if tested):
- Tests and lint:

### Known limitations
- Ghidra pseudocode is approximate, not source recovery.
- Encrypted/obfuscated/unsupported components may be incomplete.
- IPA-source links are external and are not security/license endorsements.
```
