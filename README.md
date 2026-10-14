# iOS-RE Agent

**Investigate iOS apps with an AI agent, from package metadata down to native pseudocode.**

iOS-RE Agent is an open-source, local-first toolkit for evidence-led analysis of iOS `.ipa` packages, `.app` bundles and Mach-O binaries. It combines package inventory, evidence-backed feature hypotheses, optional Ghidra decompilation, and an MCP server that lets compatible AI agents call the analysis tools.

> **Status: 0.3.0 preview.** This is an iOS-focused investigation layer, not a reimplementation of a decompiler. It provides bounded IPA inventory and evidence reporting, then can delegate deeper native analysis to upstream [REA](https://github.com/morluto/rea) through its documented CLI. A local Ghidra fallback is also available. No tool can recover original source code for every app or prove runtime behavior from static evidence alone.

## What it does

- Reads IPA ZIP members without extracting the entire package or executing the app.
- Identifies bundle metadata, URL schemes, app extensions, framework/dylib names, privacy manifests, resource types and localization directories.
- Parses thin and universal Mach-O headers and selected load commands.
- Extracts sanitized URL clues with source paths and byte offsets, and separates likely service endpoints from documentation/static/reference URLs to reduce noise.
- Records keyword-match provenance by file and builds a conservative feature map (sharing, notifications, integrations, media, networking, analytics clues, and related areas) with evidence paths and confidence labels.
- Optionally uses local Ghidra for bounded native pseudocode extraction. On Ghidra installations with PyGhidra, it uses the CPython script runtime and runs a pre-analysis script to disable two expensive Objective-C analyzers that have caused headless timeouts.
- Delegates generic native investigation to upstream REA when installed, including its documented CLI operations for binary analysis, search, function dossiers, decompilation, xrefs, traces and instruction inspection.
- Exposes package analysis and REA-backed native investigation through an MCP stdio server, so an agent can follow evidence instead of relying on a one-shot report.
- Provides a catalog of external IPA-source and release-discovery links. It never hosts, mirrors, installs, or automatically downloads IPA binaries.
- Produces reproducible `report.json` and `REPORT.md` output while recording scan coverage and limitations.

## The investigation loop

```text
INPUT ARTIFACT
   │
   ├── IPA / .app / Mach-O inventory
   │      ├── metadata, resources, frameworks, extensions
   │      ├── privacy declarations and URL schemes
   │      └── candidate strings with file + byte-offset evidence
   │
   ├── Optional Ghidra native analysis
   │      ├── main executable + embedded Mach-O components
   │      ├── function names and approximate pseudocode
   │      └── call edges and recovered strings
   │
   └── JSON report + Markdown report + feature hypotheses
            │
            ▼
       MCP tools let an AI agent search evidence, inspect likely code paths,
       compare clues, and write a reasoned investigation with uncertainty stated.
```

The intended workflow is **decompile → understand → recreate a function for your own project**, not to claim that original source has been recovered or to copy a complete proprietary application. This project takes inspiration from evidence-driven reverse-engineering workflows such as [REA](https://github.com/morluto/rea); it is an independent implementation and does not include REA code.

## Requirements

- Python 3.10 or newer.
- macOS is the primary development host. File-based static inspection also uses Python's standard library on other operating systems.
- Ghidra is optional for package inventory. Native inspection can use upstream REA with an installed/configured Ghidra, Hopper or IDA provider; the bundled fallback uses a local Ghidra installation.
- Upstream REA is installed separately and currently requires Node.js 22.19+, 24.11+, or 26+. Native-provider setup is documented in [REA's README](https://github.com/morluto/rea). `ios-re-agent doctor` warns when Node is below these versions.

Runtime dependencies are standard-library only. Development extras install `pytest` and `ruff`.

## Install on macOS

```bash
git clone https://github.com/sharmao07/ios-re-agent.git
cd ios-re-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

Check the environment and supported commands:

```bash
ios-re-agent doctor
ios-re-agent --help
```

If the CLI is unavailable, ensure the virtual environment is activated. You can also run it as `python -m ios_re_agent`.

## 1. Package analysis

Analyze an IPA:

```bash
ios-re-agent analyze "/path/to/authorized-app.ipa" --out "reports/my-app"
```

Analyze an extracted `.app` bundle or a Mach-O binary:

```bash
ios-re-agent analyze "/path/to/MyApp.app" --out "reports/my-app"
ios-re-agent analyze "/path/to/MyApp.app/MyApp" --out "reports/main-binary"
```

Output:

```text
reports/my-app/
├── REPORT.md
└── report.json
```

The Markdown report is a readable overview. The JSON report is the canonical machine-readable result for scripts and agent investigation. Network entries include `source_path`, `byte_offset`, a classification and a reminder that static string matches do not prove a request occurs.

## 2. Native analysis with upstream REA or the Ghidra fallback

The `decompile` command uses `--backend auto` by default: it prefers upstream REA if the `rea` CLI is installed, and otherwise uses the bundled Ghidra adapter. You can select `--backend rea` or `--backend ghidra` explicitly.

For the standalone Ghidra fallback, install Ghidra from its official project/release channels. The tool detects common Homebrew layouts; if needed, set `GHIDRA_HOME` to either the Ghidra distribution root or its `Ghidra` application directory. Confirm `support/analyzeHeadless` exists:

```bash
export GHIDRA_HOME="/path/to/ghidra"
ios-re-agent doctor
```

Start with an authorized sample app:

```bash
ios-re-agent decompile "/path/to/authorized-app.ipa" \
  --out "reports/my-app-native" \
  --backend ghidra \
  --max-binaries 100 \
  --timeout 900
```

For an IPA or `.app`, the adapter finds bundle executables declared by `Info.plist` and embedded `.dylib` files. It stages only recognized Mach-O payloads to a temporary workspace, never the entire archive, and analyzes selected native components separately. Limits keep analysis bounded. Outputs include:

```text
reports/my-app-native/
├── NATIVE_ANALYSIS.md
├── native-analysis.json
└── modules/
    ├── 001_MyApp/
    │   ├── NATIVE_ANALYSIS.md
    │   └── analysis.json
    └── ...
```

Ghidra may fail to recover functions or pseudocode for encrypted, obfuscated, optimized, stripped or unsupported code. Native decompilation is approximate; it is not the original Swift/Objective-C source. The adapter does not bypass app encryption, code signing or device protections. No target code is executed. This command has not yet been validated against every Ghidra release or every iOS binary type; please report compatibility issues with reproducible synthetic or authorized fixtures.

## 3. Use upstream REA for interactive native reverse engineering

The project deliberately delegates generic native reverse-engineering operations to [REA](https://github.com/morluto/rea), rather than reimplementing its Ghidra/Hopper/IDA bridges. The iOS layer discovers executable components inside an IPA, stages bounded Mach-O files temporarily, and records REA evidence per component.

Install upstream REA separately using its supported Node.js version, then configure a provider according to the upstream documentation:

```bash
npm install --global rea-agents
rea --help
rea providers --json
rea capabilities --json
rea doctor --provider ghidra --json
```

You can pass any REA CLI command through the project, or run a native investigation directly:

```bash
# Pass through to the full upstream REA CLI.
ios-re-agent rea -- analyze "/path/to/native-binary" --provider ghidra --json

# Use the structured native-operation wrapper.
ios-re-agent rea-native analyze "/path/to/native-binary" --provider ghidra
ios-re-agent rea-native search "/path/to/native-binary" "notification" --provider ghidra
ios-re-agent rea-native function "/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native decompile "/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native xrefs "/path/to/native-binary" "0x100001000" --provider ghidra
ios-re-agent rea-native trace "/path/to/native-binary" "notification" --provider ghidra
ios-re-agent rea-native instructions "/path/to/native-binary" "0x100001000" --provider ghidra
```

Analyze the native components from an IPA as a batch:

```bash
ios-re-agent rea-ipa "/path/to/authorized-app.ipa" \
  --out "reports/rea-native-analysis" \
  --provider ghidra \
  --max-binaries 20 \
  --timeout 300
```

This writes `REA_NATIVE_ANALYSIS.md`, `rea-native-analysis.json`, and per-component evidence under `modules/`. `rea-evidence.json` preserves the upstream JSON response; `rea-command.json` records command status and diagnostics. Output schemas can change with upstream REA versions, and a timeout or failed provider remains a failure rather than a completed analysis. The command inventories declared bundle executables and embedded `.dylib` files; it does not guarantee every Mach-O in every vendor-specific bundle layout is found.

For agent integration, upstream REA's own MCP server exposes its full tool catalog. Register it as a separate MCP server using the instructions in [REA's setup guide](https://github.com/morluto/rea/blob/main/docs/installation.md). This project's MCP server also exposes `rea_native_operation` and `analyze_ios_with_rea` if you prefer the iOS workflow in one server.

## 4. Ask an AI agent to investigate the app

The MCP server exposes these tools:

- `analyze_ios_artifact` — run the built-in report pipeline and return a concise summary.
- `decompile_ios_native_code` — optional Ghidra pass over native components.
- `search_analysis_report` — find relevant functions, symbols, strings, URLs and evidence paths in a report.
- `get_feature_map` — return feature hypotheses and their supporting evidence.
- `list_ipa_sources` / `search_ipa_sources` — search the outbound source catalog.
- `discover_github_ipa_releases` — query GitHub's public API for repositories with `.ipa` release assets; this returns links only and does not verify redistribution rights.
- `rea_native_operation` — call upstream REA for native analysis, search, function dossiers, decompilation, xrefs, traces and instructions.
- `analyze_ios_with_rea` — discover IPA/app Mach-O components and preserve per-component upstream REA evidence.

Start the server manually to test its availability:

```bash
ios-re-agent mcp
```

The command uses JSON-RPC over standard input/output; it is meant to be launched by an MCP-compatible client, not used as an interactive shell command. To expose REA's complete upstream MCP tool catalog, register the separate `rea` server too (see the integration instructions above); this project's adapter only wraps its documented native CLI operations.

Example generic MCP client configuration (replace the paths with absolute paths on your Mac):

```json
{
  "mcpServers": {
    "ios-re-agent": {
      "command": "/absolute/path/to/ios-re-agent/.venv/bin/ios-re-agent",
      "args": ["mcp"]
    }
  }
}
```

Use the configuration location documented by your MCP client, restart it, then ask something like:

> Investigate the notification flow in this authorized iOS app. Start from the feature map, search the report for notification-related symbols and components, inspect relevant native component reports if available, and cite every claim with its evidence path. Distinguish observations, hypotheses and unknowns.

An AI agent can organize findings and choose follow-up queries. It should not treat a feature-map label as proof of a working feature. Dynamic behavior still requires a separately designed, explicitly authorized simulator/device workflow, which is not included in this release.

## 5. Find external sources for IPA files

List or search the configured catalog:

```bash
ios-re-agent sources list
ios-re-agent sources search official
ios-re-agent sources search community
```

Discover public GitHub release assets for a project name:

```bash
ios-re-agent sources discover "open source iOS app" --max-repositories 8
```

The discovery command sends the query to GitHub's public API. It requires an Internet connection and can be affected by API rate limits. It only returns external repository/release links; it never downloads or installs the IPA. Catalog entries are explicitly labelled by source/trust status. The [IPAlibrary/IPA index](https://github.com/IPAlibrary/IPA) is listed as an **unverified community index**, not an endorsed or audited source; its README includes modified/jailbreak-related categories, so review the source, provenance, licensing and device compatibility carefully. Neither this project nor a GitHub repository license is proof that each attached IPA can legally be redistributed.

Prefer assets published by an application's original developers, check licenses and release notes, verify checksums/signatures where available, and do not upload someone else's IPA or generated report to a public repository without permission.

## Evidence interpretation and limits

- **Observed:** data parsed from an artifact, such as an `Info.plist` key, Mach-O load command or manifest declaration.
- **Candidate:** a string or heuristic match that requires confirmation.
- **Hypothesis:** a possible feature suggested by multiple clues; confidence describes heuristic support, not statistical certainty.
- **Unknown:** skipped, unsupported, encrypted, unavailable or untested evidence.
- **Privacy manifests:** statements reported from packaged manifests, not verification of actual collection.
- **URLs:** a recovered string may be stale, embedded in third-party code, used only in a debug context, or never requested.
- **Code:** decompiler output can contain invented or incorrect names/types and may miss optimized, stripped or dynamically dispatched logic.
- **Coverage:** reports show bounded scan limits, paths scanned and skipped files. Absence from the report is not proof that an app lacks a feature.

This project is for apps you own or are authorized to inspect, public research targets, and interoperability/security work allowed by the relevant terms and law. Review reports before sharing: binary/resource metadata and decompiled pseudocode may be confidential or copyright-protected.

## Tests and quality checks

```bash
python -m pytest
python -m ruff check .
```

GitHub Actions runs tests and lint. The Ghidra export script requires a local Ghidra installation, so the regular CI suite validates component selection and report logic with synthetic fixtures; an end-to-end Ghidra run must be tested separately on supported hosts.

## Open-source launch checklist

See [`docs/OPEN_SOURCE_LAUNCH.md`](docs/OPEN_SOURCE_LAUNCH.md) for release, documentation, provenance and issue-triage steps. Do not call this universal or fully complete until native integration has been verified on real authorized samples and its limitations are documented.

## License

MIT. See [LICENSE](LICENSE). Upstream REA is a separate MIT-licensed project with its own license, release lifecycle and third-party notices; it is not vendored here. Ghidra and other analysis providers retain their own licenses and are not bundled with this project.
