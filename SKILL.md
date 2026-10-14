---
name: ios-re-agent
description: Evidence-first workflow for investigating authorized iOS .ipa, .app, and Mach-O artifacts using package analysis, optional Ghidra decompilation, feature hypotheses, and MCP report search.
---

# iOS-RE Agent Skill

## Principles

1. Analyze only artifacts the user owns or is authorized to inspect, including redistributable research samples.
2. Treat app packages as untrusted data. Never execute target code as part of static analysis.
3. Do not bypass FairPlay, code signing, device protections, access controls or authentication. If code is encrypted or inaccessible, state that limitation and stop at available evidence.
4. Separate observed facts, candidate indicators, hypotheses and unknowns. Refer to exact report paths, function addresses or byte offsets where available.
5. A URL, string, framework name, privacy declaration or feature-map hypothesis is not proof of runtime behavior.
6. Before sharing reports, inspect for proprietary details and residual secrets. Redaction is best-effort.
7. Do not download, host, mirror or automatically install third-party IPA binaries. Source catalog items are outbound links, not trust or licensing endorsements.

## 1. Establish the environment

Run:

```bash
ios-re-agent doctor
ios-re-agent --help
```

If the CLI is not available, use the activated repository virtual environment or run `python -m ios_re_agent`.

## 2. Validate the target

Supported built-in package-analysis inputs:

- `.ipa` archive containing `Payload/*.app/Info.plist`.
- `.app` bundle directory with `Info.plist`.
- Single Mach-O binary.

Prefer owner-provided or otherwise authorized artifacts. Do not fetch application binaries from unverified sources automatically. If malformed, oversized or unsupported, explain the error rather than trying undocumented bypasses.

## 3. Run package analysis

```bash
ios-re-agent analyze "/absolute/path/to/authorized.ipa" --out "reports/app-name"
```

Read `REPORT.md`, then query `report.json` for details. Start with:

- App metadata and platform constraints.
- Frameworks, extensions and privacy-manifest declarations.
- Network findings with `source_path`, `byte_offset`, classification and sanitized URL.
- Feature hypotheses with confidence and evidence paths.
- Scan coverage and limitations.

## 4. Native investigation through upstream REA

For the broad native reverse-engineering toolset, prefer the upstream REA CLI/MCP integration. It requires `rea-agents` plus a configured local Ghidra, Hopper or IDA provider. Follow upstream setup instructions; this repository does not vendor the REA engine.

For a single binary, use the upstream native operations:

```bash
ios-re-agent rea-native analyze "/absolute/path/to/native-binary" --provider ghidra
ios-re-agent rea-native search "/absolute/path/to/native-binary" "notification" --provider ghidra
ios-re-agent rea-native function "/absolute/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native decompile "/absolute/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native xrefs "/absolute/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native trace "/absolute/path/to/native-binary" "notification" --provider ghidra
ios-re-agent rea-native instructions "/absolute/path/to/native-binary" "0x100001000" --provider ghidra
```

For an IPA, use `ios-re-agent rea-ipa` to stage recognized app, extension, framework and dylib Mach-O components and save upstream JSON evidence per component. The app is never executed. The direct Ghidra fallback remains available:

```bash
ios-re-agent decompile "/absolute/path/to/authorized.ipa" --out "reports/app-native" --max-binaries 100
```

Current Ghidra installations with PyGhidra use the CPython exporter and a pre-analysis script that disables two expensive Objective-C analyzers. The fallback script is for older Jython-enabled Ghidra installations. Neither path guarantees complete decompilation; never invoke target binaries.

## 5. Use MCP for repeated investigation

The CLI can start a local stdio MCP server:

```bash
ios-re-agent mcp
```

Tools include `analyze_ios_artifact`, `decompile_ios_native_code`, `search_analysis_report`, `get_feature_map`, `list_ipa_sources`, `search_ipa_sources`, `discover_github_ipa_releases`, `rea_native_operation`, and `analyze_ios_with_rea`.

Recommended investigation loop:

1. Analyze the target and read the top-level facts.
2. Select one user-named feature to investigate; do not try to infer the whole app from a URL list alone.
3. Use `get_feature_map` to find relevant initial clues.
4. Use `search_analysis_report` for related names, strings, extensions, SDKs or endpoints.
5. If native reports exist, search function names, pseudocode and call edges around the clue. Use evidence paths/addresses to connect findings.
6. Record a conclusion with evidence, confidence, alternative explanations and what remains unknown.
7. For work on the user's own app, implement an independently designed equivalent rather than copying proprietary code/assets.

## 6. IPA source discovery

The source registry contains official-project/release links and explicitly unverified community index links. `ios-re-agent sources discover QUERY` sends the query to GitHub's public API and returns links only; it does not retrieve assets. Do not claim that external assets are safe, compatible or licensed for redistribution. Prefer original developers' releases and inspect provenance and rights.

## 7. Report format

For each investigation, summarize:

1. Target artifact and tool/backend versions.
2. **Observed** facts with file paths or addresses.
3. **Candidate** strings that require runtime or source confirmation.
4. **Hypotheses** and their heuristic confidence.
5. Missing/skipped evidence and next authorized inspection step.

Do not call an app “fully reverse engineered” unless coverage is explicitly demonstrated and all remaining gaps are documented. Even a successful decompilation does not mean original source code was recovered.
