# Architecture

## Principles

- **Read-only target handling:** the target app is never executed; IPA contents are read from ZIP members and only selected native executables are staged into temporary space for Ghidra.
- **Bounded:** archive entries, plist sizes, string scan files/bytes, native binary count, binary size and total native staging size are capped.
- **Evidence-first:** findings preserve source paths, byte offsets when extracted from raw strings, classifications and limitations.
- **Local-first:** package analysis and native decompilation run locally. Only the explicit `sources discover` command and corresponding MCP tool contact GitHub's public API.
- **Composable:** JSON is the primary report format, with Markdown views generated from the same report objects.
- **No universal decompilation claim:** original source is rarely recoverable verbatim from compiled apps; Ghidra pseudocode is a model for reasoning, not original Swift/Objective-C source.

## Data flow

```text
Authorized IPA / .app / Mach-O
           │
           ├── package reader (no full IPA extraction)
           │      ├── Info.plist / extension / framework inventory
           │      ├── privacy manifest declarations
           │      └── bounded string scan + byte-offset provenance
           │
           ├── Mach-O parser
           │      └── architecture, load commands, linked libraries, flags
           │
           ├── feature-map heuristics
           │      └── hypotheses with evidence paths and confidence labels
           │
           └── optional Ghidra adapter
                  ├── identify executable bundles / dylibs
                  ├── stage recognized Mach-O files into temporary storage
                  ├── run analyzeHeadless independently per module
                  └── export function names, pseudocode, call edges and strings
                           │
                           ▼
                JSON + Markdown reports
                           │
                           ▼
                 MCP server (stdio)
                  ├── run analysis/decompilation
                  ├── search report evidence
                  ├── retrieve feature map
                  └── outbound IPA source discovery
```

## Modules

- `src/ios_re_agent/analyzer.py`: safe artifact reader, app metadata, inventory, privacy manifest parsing, bounded scan and report assembly.
- `src/ios_re_agent/network.py`: URL sanitization, hostname validation, conservative classification and file/byte-offset provenance.
- `src/ios_re_agent/features.py`: heuristic feature hypotheses with concrete evidence paths.
- `src/ios_re_agent/macho.py`: dependency-free parser for thin/universal Mach-O headers and selected load commands.
- `src/ios_re_agent/ghidra.py`: optional Ghidra `analyzeHeadless` orchestration, safe target selection/staging and aggregate report generation.
- `src/ios_re_agent/data/ExportAnalysis.py`: Ghidra/Jython post-script to export function metadata, approximate pseudocode, direct call edges and string data.
- `src/ios_re_agent/ipa_sources.py`: curated outbound catalog and optional GitHub API search for release assets ending in `.ipa`. It never downloads binaries.
- `src/ios_re_agent/mcp_server.py`: dependency-free MCP stdio server; protocol responses are written to stdout and diagnostics are written to stderr.
- `src/ios_re_agent/report.py`: JSON and Markdown report serialization.
- `src/ios_re_agent/cli.py`: command-line front end.
- `SKILL.md`: evidence-first agent workflow instructions.

## Limits and boundaries

- IPA scanning reads entries by path in the archive; the package itself is not extracted. Ghidra staging copies only selected Mach-O components to a temporary directory.
- The analyzer caps archive entries, scan paths, bytes per file and total string-scan bytes. The Ghidra adapter caps binary count, bytes per binary and total bytes staged.
- Native decompilation currently depends on a separately installed Ghidra `analyzeHeadless`. The included script is designed for Ghidra's Jython-compatible script environment; compatibility must be validated against actual supported Ghidra releases.
- Functions are discovered only where Ghidra's analysis finds them. The tool does not guarantee correct Swift/Objective-C semantic reconstruction, complete call graphs, recovery of original symbols, or full coverage of every bundle resource.
- Candidate URLs can still be false positives. Feature-map confidence is heuristic support rather than a probability.
- The source directory is an external link registry; it does not host binaries. Online discovery queries GitHub's API only when explicitly invoked, sends the search query to GitHub, and does not verify that a given binary is redistributable or safe.
- No runtime instrumentation, traffic capture, code-signing bypass, FairPlay decryption, access-control bypass, app patching or repackaging is implemented.

## Extension guidelines

1. Start from a reproducible failing case and record exactly what the target artifact proves.
2. Add a small helper with explicit output schema and size/work limits.
3. Preserve source provenance and redact likely secrets before writing reports.
4. Write synthetic fixture tests for valid, malformed and adversarial inputs.
5. Update the JSON schema, README and changelog.
6. State unimplemented backend behavior clearly; don't turn a link or heuristic into a claim of verified behavior.
