# Changelog

Notable project changes are documented here. Until the first stable release, changes may be breaking.

## 0.1.0 — 2026-10-13

- Initial public-ready MVP of iOS-RE Agent.
- Read-only inspection of IPA archives, `.app` bundle directories, and standalone Mach-O files.
- Parse common app metadata and basic thin/universal Mach-O load commands.
- Inventory embedded frameworks, dynamic libraries, app extensions, localization directories, and privacy manifests.
- Add bounded candidate-URL scanning, best-effort URL redaction, and keyword-category counts.
- Emit Markdown and JSON reports with scan coverage and limitations.
- Add CLI, agent skill instructions, synthetic fixtures, unit tests, security policy, roadmap, and GitHub Actions CI.
