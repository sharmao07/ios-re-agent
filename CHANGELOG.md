# Changelog

Notable project changes are documented here. Until a stable release, changes may be breaking.

## 0.2.0 — 2026-10-14 (preview)

- Improve URL validation and classify likely service endpoints separately from reference/static URLs.
- Add source file + byte-offset evidence to URL findings and path-level keyword provenance.
- Generate conservative feature-map hypotheses with confidence labels and evidence paths.
- Add optional Ghidra headless component analysis for recognized app, extension, framework and dylib Mach-O binaries.
- Export function names, approximate pseudocode, direct call edges and available string data into per-component native reports.
- Add MCP stdio server for package analysis, native analysis, report search, feature maps and source discovery.
- Add an outbound IPA-source catalog and explicit GitHub release-asset discovery; no binary downloading or hosting.
- Add test coverage for network sanitization, evidence provenance, feature hypotheses, sources, MCP registration and Mach-O component staging.
- Add open-source launch checklist and update README/architecture/roadmap.

## 0.1.0 — 2026-10-13

- Initial MVP of read-only IPA/app-bundle inventory and reporting.
- Parse app metadata, thin/universal Mach-O headers, frameworks, extensions, localization directories and privacy manifest declarations.
- Add bounded candidate URL scanning, best-effort redaction and keyword-category counts.
- Emit JSON/Markdown reports with scan coverage and limitations.
- Add CLI, agent skill, synthetic fixtures, tests, security policy, roadmap and GitHub Actions CI.
