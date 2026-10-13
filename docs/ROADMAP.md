# Roadmap

The roadmap is aspirational. Items are not implemented until they are documented in the README and covered by tests.

## v0.1 — static inventory and report (current)

- [x] Read IPA archives without extracting them.
- [x] Inspect app bundle metadata and selected privacy declarations.
- [x] Parse basic thin/universal Mach-O headers and selected load commands.
- [x] Inventory frameworks, extensions, file types, and localization directories.
- [x] Emit sanitized candidate network indicators and JSON/Markdown reports.
- [x] Bound archive entries, file reads, and scan coverage.
- [x] Add synthetic fixtures, CLI, tests, and CI.

## v0.2 — comparison and deeper metadata

- [ ] Compare two authorized builds and report added/removed resources, framework changes, metadata changes, and binary hashes.
- [ ] Improve handling of large universal binaries by reading Mach-O headers/slices with random access rather than a fixed prefix.
- [ ] Add more tests for malformed ZIPs, malformed property lists, universal Mach-O inputs, and redaction edge cases.
- [ ] Add explicit report provenance for every finding (path, parser, and byte offset when available).
- [ ] Improve privacy manifest validation against current Apple documentation.

## v0.3 — optional native-tool adapters

- [ ] Optional read-only handoff to user-installed Ghidra for authorized binaries.
- [ ] Optional `otool` metadata adapter on macOS, with captured tool version/output and explicit opt-in.
- [ ] Add a tool interface so optional analyzers can be tested and disabled cleanly.
- [ ] Compare debug builds or developer-provided symbol files when supplied by the app owner.

## Later — authorized runtime evidence

- [ ] Define a separate, opt-in design for collecting observations from an owner-controlled simulator/test device.
- [ ] Label static and runtime findings independently, with timestamps and repeatability notes.
- [ ] Require explicit user selection of the target device and actions before any runtime interaction.

## Non-goals

- Bypassing FairPlay or other app encryption.
- Defeating code-signing, device protections, access controls, or authentication.
- Stealing credentials or using discovered endpoints to access third-party accounts.
- Claiming universal recovery of original source code from arbitrary iOS apps.
