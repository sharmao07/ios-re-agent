# iOS-RE Agent

**Evidence-first static analysis for authorized iOS app artifacts.** iOS-RE Agent inspects `.ipa` packages, `.app` bundle directories, and individual Mach-O binaries, then writes a human-readable `REPORT.md` and machine-readable `report.json`.

> **Project status: early MVP (v0.1.0).** This is a read-only inspector and report generator, not a universal decompiler. It does not decrypt App Store binaries, bypass platform protections, execute the target app, control a device, or claim that static strings prove runtime behavior.

## What it does

- Reads standard iOS `.ipa` archives **without extracting their contents to disk**.
- Reads `.app` bundle directories and individual Mach-O files.
- Extracts common `Info.plist` metadata, URL schemes, declared background modes, and `*UsageDescription` keys.
- Parses basic thin and universal Mach-O headers and selected load commands: architectures, linked dylibs, rpaths, build platform, minimum OS version, and the encryption flag when present.
- Inventories bundle file types, `.framework`/`.dylib` names, `.appex` extensions, localization directories, and `PrivacyInfo.xcprivacy` declarations.
- Collects **candidate** HTTP(S) URL/host strings from a bounded selection of files. Query values, URL credentials, and some token-like path segments are redacted before they enter the report.
- Emits bounded keyword-category counts for common SDK/integration clues without storing the matched raw strings.
- Writes both Markdown and JSON reports with scan coverage and limitations.
- Uses only the Python standard library at runtime.

## What it does not do

- Fully decompile Swift or Objective-C source code.
- Recover source code that has been stripped, obfuscated, or never shipped in the package.
- Decrypt FairPlay-protected executable sections or defeat code-signing/device protections.
- Run the app, perform runtime instrumentation, intercept traffic, or prove that a discovered endpoint is used.
- Replace a mobile security review or establish whether an app is safe.

The goal of this first version is to produce reliable, traceable starting evidence for further authorized investigation. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for implementation boundaries and [docs/ROADMAP.md](docs/ROADMAP.md) for planned extensions.

## Requirements

- Python **3.10 or newer**.
- macOS is the primary intended host. The Python package itself also supports other systems for file-based static analysis.
- An `.ipa`, `.app` bundle directory, or Mach-O binary that you are authorized to inspect.

There are no required third-party runtime dependencies. `otool`, `plutil`, and Ghidra are optional ecosystem tools; the current MVP does not invoke them.

## Install on macOS

Open Terminal, move into the downloaded/cloned repository, and run:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Check the environment:

```bash
ios-re-agent doctor
```

If the `ios-re-agent` command is not available in the current shell, use the module form instead:

```bash
python -m ios_re_agent doctor
```

## Quick start

### Analyze an IPA

```bash
ios-re-agent analyze "/path/to/MyApp.ipa" --out "reports/MyApp"
```

### Analyze an extracted `.app` bundle

```bash
ios-re-agent analyze "/path/to/MyApp.app" --out "reports/MyApp"
```

### Inspect one Mach-O executable

```bash
ios-re-agent analyze "/path/to/MyApp.app/MyApp" --out "reports/MyApp-binary"
```

Each successful analysis writes:

```text
reports/MyApp/
├── REPORT.md
└── report.json
```

Choose one output format if needed:

```bash
ios-re-agent analyze MyApp.ipa --out reports/MyApp --json-only
ios-re-agent analyze MyApp.ipa --out reports/MyApp --markdown-only
```

Get help at any time:

```bash
ios-re-agent --help
ios-re-agent analyze --help
```

If not installed, use `python -m ios_re_agent` in place of `ios-re-agent`.

## Install from a downloaded ZIP

1. Download this repository ZIP from GitHub and extract it.
2. Open Terminal and `cd` into the extracted `ios-re-agent` folder.
3. Run the install commands above.
4. Run `python -m ios_re_agent analyze "/full/path/to/MyApp.ipa" --out reports/MyApp`.
5. Open `reports/MyApp/REPORT.md`; use `report.json` for scripts and agent workflows.

## Upload this project to GitHub

1. Create an empty GitHub repository named `ios-re-agent` (or your chosen name). Do not add a README or license there, because these are included.
2. Extract the project ZIP downloaded from this repository template/artifact.
3. In Terminal, `cd` into the extracted project folder, then run:

   ```bash
   git init
   git add .
   git commit -m "Initial iOS reverse engineering analysis toolkit"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/ios-re-agent.git
   git push -u origin main
   ```

4. Replace `YOUR-USERNAME` with your GitHub username. Keep app packages, private test apps, reports, signing material, and credentials out of the public repository. The included `.gitignore` already excludes common `.ipa`, `.app`, and report paths.

## Tests and code quality

```bash
python -m pytest
python -m ruff check .
```

Runtime code has no third-party dependencies. The development extra installs pytest and Ruff. GitHub Actions runs tests and lint on pushes and pull requests.

## Report interpretation

- **Declarations are not behavior.** `Info.plist` and privacy manifest values are what the package declares; they are not independent verification of runtime behavior.
- **Strings are leads, not proof.** A URL or SDK keyword can be stale, unused, environment-specific, or inside a third-party library.
- **Absence is not proof of absence.** Encrypted, compressed, dynamically assembled, or unscanned data may not appear in the output.
- **Scan is bounded.** The tool limits archive entry counts, selected-file counts, and bytes read to reduce resource-exhaustion risk. The report records selected paths and skipped files.
- **Sensitive data:** query values and likely opaque token segments are redacted from candidate URL output, but automated redaction is not perfect. Review output before sharing reports publicly.

## Agent skill

The workflow is described in [`SKILL.md`](SKILL.md), also packaged as `.agents/skills/ios-re-agent/SKILL.md`. It is intended to guide an AI coding agent through a cautious, evidence-first investigation with this CLI. The skill is documentation/instructions; it does not by itself install an MCP server or modify any agent configuration.

## Safety and authorization

Use this project only on applications and artifacts you own or are explicitly authorized to analyze. Respect app licenses, privacy, intellectual property, and applicable law. Do not use it to collect secrets, target other people's accounts, or bypass technical protections. Read [SECURITY.md](SECURITY.md) before reporting a security issue.

## License

MIT. See [LICENSE](LICENSE). Third-party tools mentioned in documentation retain their own licenses and are not bundled with this project.
