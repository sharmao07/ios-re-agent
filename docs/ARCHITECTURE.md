# Architecture

## Design goals

- **Read-only:** app artifacts are inspected as data and are never executed.
- **Bounded:** archive entries, per-file reads, total scan bytes, and the number of scanned files are limited.
- **Evidence-first:** output distinguishes parsed metadata from candidate indicators and calls out missing evidence.
- **Local-first:** the runtime uses Python's standard library and does not upload artifacts to a service.
- **Composable:** report output is JSON first-class, with Markdown generated from the same finding object.

## Data flow

```text
Authorized input (.ipa / .app / Mach-O)
                |
                v
      ArtifactReader (read-only)
    - ZIP member reads; no extraction
    - app directory traversal; skip symlinks
    - bounded reads and path checks
                |
                v
        Analysis pipeline
    - Info.plist metadata
    - bundle inventory / extensions
    - privacy manifest declarations
    - Mach-O header and load commands
    - bounded strings and candidate URL scan
                |
                v
         Normalized report object
                |
          +-----+-----+
          |           |
          v           v
      report.json  REPORT.md
```

## Modules

- `src/ios_re_agent/analyzer.py`: input validation, bounded artifact reader, package inventory, plist parsing, indicator scanning, report object assembly.
- `src/ios_re_agent/macho.py`: dependency-free parser for thin and universal Mach-O headers plus selected load commands.
- `src/ios_re_agent/report.py`: serialize the normalized result to JSON or Markdown.
- `src/ios_re_agent/cli.py`: command-line options, environment diagnostics, output directory handling.
- `SKILL.md`: workflow instructions for an AI coding agent; it does not itself install tools or invoke external services.

## Limits and parser boundaries

- Input type is inferred from the `.ipa` extension/archive structure, `.app` directory, or fallback single-file path. A random binary may return `format: unknown`.
- IPA members are read in place from the ZIP and are not extracted. No app executable is launched.
- The Mach-O parser reads CPU type, file type, command counts, dylib load paths, rpaths, build platform/minimum OS, and encryption flags when those commands are present and well-formed. It is not an instruction decoder or decompiler.
- String scan selects the main executable, common text/plist file extensions, and some framework files. It is capped at 180 selected files and 256 MiB in total, with a 64 MiB per-file cap.
- Each plist parse is capped at 2 MiB; the inventory examines at most 50 extension manifests and 50 privacy manifests.
- Network findings are de-duplicated and capped at 500 candidate URL strings and 300 hostnames.
- Keyword categories report capped match counts only. Raw matched strings are not included in that section.
- Candidate URLs have userinfo, query values and fragments removed. Token-looking path segments are redacted heuristically. This is defense-in-depth, not a guarantee that arbitrary secrets will always be detected.

## Extending the analyzer

1. Add a small parsing function that consumes bytes or a normalized finding object; do not add unbounded file reads.
2. Attach provenance to each finding where practical: artifact path, parser, and byte offset/command identifier.
3. Define what a positive match means and document false positives and false negatives.
4. Add synthetic fixture tests for both valid and malformed inputs.
5. Add the finding to JSON output and update the JSON schema/report documentation.
6. Keep runtime behavior opt-in and separate from static analysis. Any future runtime adapter needs explicit target selection, user approval, visible effects, and dedicated tests.
