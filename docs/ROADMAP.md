# Roadmap

This roadmap distinguishes code currently present from work not yet verified. A checkbox does not imply compatibility with every IPA or Ghidra release; CI and host-specific test evidence still matter.

## v0.1 — static package inventory (complete)

- [x] Read IPA archives without extracting all members.
- [x] Inspect app metadata, extensions, privacy declarations and Mach-O headers.
- [x] Inventory file types, frameworks and localization paths.
- [x] Emit bounded sanitized candidate URL clues and JSON/Markdown reports.
- [x] Add synthetic tests and CI.

## v0.2 — evidence quality, feature mapping, agent interface and source catalog (implemented preview)

- [x] Validate candidate hostnames and separate likely service endpoints from documentation/static/reference URLs.
- [x] Preserve source path and byte offset for candidate network strings.
- [x] Preserve path-level keyword evidence and map SDK/extension/manifest clues to feature hypotheses.
- [x] Add outbound IPA source catalog with verification/trust labels and warnings.
- [x] Add optional GitHub public API discovery of release assets ending in `.ipa`; return links only, never download.
- [x] Add dependency-free MCP stdio server with analysis, decompile, search, feature-map and source tools.
- [x] Add Ghidra headless adapter and export script that analyzes selected main/extension/framework/dylib Mach-O components.
- [x] Add synthetic tests for hostname validation, evidence provenance, source catalog, MCP tool registry and native component selection.
- [ ] End-to-end verify Ghidra scripting on each officially supported Ghidra release and representative authorized iOS binaries.
- [ ] Add golden-file regression tests from open-source, redistributable sample iOS apps.

## v0.3 — upstream native engine bridge (implemented preview)

- [x] Delegate native analysis, string/procedure search, function dossiers, decompilation, xrefs, traces and instruction inspection to upstream REA when its CLI is installed.
- [x] Add batch IPA/.app native component analysis through upstream REA and preserve per-component JSON evidence.
- [x] Add MCP tools for REA native operations and batch iOS native analysis.
- [x] Make Ghidra launcher detection Homebrew-layout aware and use PyGhidra on current installs where available.
- [x] Add a pre-analysis script to disable two expensive Objective-C analyzers implicated in long headless runs.
- [ ] End-to-end verify the Ghidra fallback and upstream REA bridge on representative authorized iOS binaries, including the previously timing-out Pinterest binary.
- [ ] Test large universal/fat Mach-O, encrypted slices, stripped symbols, malformed bundle metadata and oversized archives.
- [ ] Add configurable per-component inclusion/exclusion patterns, richer progress reporting and report-to-native evidence IDs.

## v0.4 — investigation workbench

- [ ] Add richer MCP methods for native function lookup, cross-reference search and targeted batch decompilation.
- [ ] Add persistent case manifests that record input hashes, tool versions, selected modules and limitations without storing the target app.
- [ ] Add local/offline LLM summarization as an optional backend with clear privacy controls; MCP should remain useful without a model.
- [ ] Add app-build comparison for metadata, resources, frameworks, native functions and evidence deltas.

## Later — authorized runtime evidence

- [ ] Design a separate opt-in simulator/test-device adapter for apps the user owns or has permission to test.
- [ ] Label static and runtime evidence independently and preserve timestamps/reproduction steps.
- [ ] Require explicit target and action selection; no stealth device control, credential collection, or automatic bypass attempts.

## Non-goals

- Bypassing FairPlay or other app encryption, code signing, access controls, or account protections.
- Claiming that arbitrary iOS apps can be fully restored to original source code.
- Hosting or mirroring third-party IPA files or asserting that external links are licensed, safe or verified.
- Automatically executing apps, instrumenting devices, intercepting network traffic, patching app logic, or repackaging target apps.
