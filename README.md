# iOS-RE Agent

**Investigate iOS apps with an AI agent, from package metadata down to native pseudocode.**

iOS-RE Agent is an open-source, local-first toolkit for evidence-led analysis of iOS `.ipa` packages, `.app` bundles and Mach-O binaries. It combines package inventory, evidence-backed feature hypotheses, optional Ghidra decompilation, and an MCP server that lets compatible AI agents call the analysis tools.

> **Status: 0.2.0 preview.** This is an early research tool. It can inspect many shipped artifacts and decompile readable native code with Ghidra, but it cannot recover the original source code of every app or prove runtime behavior from static evidence alone.

## What it does

- Reads IPA ZIP members without extracting the entire package or executing the app.
- Identifies bundle metadata, URL schemes, app extensions, framework/dylib names, privacy manifests, resource types and localization directories.
- Parses thin and universal Mach-O headers and selected load commands.
- Extracts sanitized URL clues with source paths and byte offsets, and separates likely service endpoints from documentation/static/reference URLs to reduce noise.
- Records keyword-match provenance by file and builds a conservative feature map (sharing, notifications, integrations, media, networking, analytics clues, and related areas) with evidence paths and confidence labels.
- Optionally uses a local Ghidra installation to inspect the main executable, extension executables, framework executables and embedded dynamic libraries. Each selected native component gets its own JSON and Markdown report, with recognized functions, approximate pseudocode, call edges and string clues when Ghidra can recover them.
- Exposes analysis, report search, feature-map, native-decompile and IPA-source discovery tools through an MCP stdio server.
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
- Ghidra is optional. Without it, package inventory and the built-in Mach-O parser still work; the native pseudocode command needs `analyzeHeadless` from an installed Ghidra distribution.

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

## 2. Native decompilation with Ghidra

Install Ghidra from its official project/release channels, then set `GHIDRA_HOME` to the Ghidra installation directory. Confirm `support/analyzeHeadless` exists and is executable:

```bash
export GHIDRA_HOME="/path/to/ghidra"
ios-re-agent doctor
```

Start with an authorized sample app:

```bash
ios-re-agent decompile "/path/to/authorized-app.ipa" \
  --out "reports/my-app-native" \
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

## 3. Ask an AI agent to investigate the app

The MCP server exposes these tools:

- `analyze_ios_artifact` — run the built-in report pipeline and return a concise summary.
- `decompile_ios_native_code` — optional Ghidra pass over native components.
- `search_analysis_report` — find relevant functions, symbols, strings, URLs and evidence paths in a report.
- `get_feature_map` — return feature hypotheses and their supporting evidence.
- `list_ipa_sources` / `search_ipa_sources` — search the outbound source catalog.
- `discover_github_ipa_releases` — query GitHub's public API for repositories with licensed source metadata and `.ipa` release assets; this returns links only and does not verify that the binary is licensed for redistribution.

Start the server manually to test its availability:

```bash
ios-re-agent mcp
```

The command uses JSON-RPC over standard input/output; it is meant to be launched by an MCP-compatible client, not used as an interactive shell command.

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

## 4. Find external sources for IPA files

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

MIT. See [LICENSE](LICENSE). Ghidra and any other optional tool retain their own licenses and are not bundled with this project.
