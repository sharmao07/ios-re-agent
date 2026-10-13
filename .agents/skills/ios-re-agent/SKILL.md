---
name: ios-re-agent
description: Evidence-first workflow for static inspection of authorized iOS .ipa, .app, and Mach-O artifacts. Use when a user needs package inventory, metadata, framework/linkage clues, privacy-manifest declarations, candidate endpoint strings, or a structured report.
---

# iOS-RE Agent Skill

## Principles

1. Analyze only artifacts the user owns or is authorized to inspect.
2. Treat the target as untrusted data. Never execute the target application or any extracted executable as part of static analysis.
3. Start with read-only package inspection. Do not attempt to decrypt protected code, bypass signing/device controls, or alter/repackage the app.
4. Separate observed facts from inferences. Cite the specific report section or artifact path that supports each conclusion.
5. A static URL, keyword, manifest declaration, or linked library is a clue—not proof of runtime behavior.
6. Before sharing reports, review them for proprietary details or residual secrets. Built-in redaction is best-effort, not a guarantee.

## Workflow

### 1. Establish the environment

Run:

```bash
python -m ios_re_agent doctor
```

If the module is unavailable, check the repository instructions and install the project into a virtual environment. Do not install optional tools without user approval.

### 2. Validate the target

Confirm the path exists and is one of:

- An `.ipa` archive containing `Payload/*.app/Info.plist`.
- An `.app` bundle directory containing `Info.plist`.
- A single Mach-O binary.

If the target appears to be malformed, is too large for the configured bounded reader, or isn't a supported format, report that limitation rather than trying undocumented bypasses.

### 3. Run analysis

Prefer a new output directory per target:

```bash
python -m ios_re_agent analyze "/absolute/path/to/authorized.ipa" --out "/absolute/path/to/reports/app-name"
```

If the user specifically asks for machine-readable results, add `--json-only`. Do not store target packages or sensitive reports in the repository by default.

### 4. Read report evidence

Inspect `REPORT.md` first, then `report.json` as needed. Explain findings using these labels:

- **Observed:** directly parsed from a bundle, plist, or Mach-O load command.
- **Candidate:** a string or keyword that may be relevant but is not independently verified.
- **Unknown/not inspected:** missing, inaccessible, encrypted, skipped, or unsupported evidence.

For app structure, inspect metadata, package inventory, extension bundles, frameworks, and privacy manifests. For native binary clues, inspect the Mach-O format, slices, linked libraries, build platform, minimum OS, and encryption flag status. For network clues, report candidate hosts/endpoints as strings only, with query values presumed redacted.

### 5. State limitations

Always mention limitations relevant to the user's question. The current CLI is static-only, does not execute an app, is not a complete Swift/Objective-C decompiler, and cannot establish actual runtime network or privacy behavior. Report scan omissions and encrypted-flag findings when present.

### 6. Follow-up investigation

Suggest the narrowest authorized next step (for example, inspect a specific plist, compare two provided builds, or review an app owner-provided debug build). Don't automate device instrumentation, traffic interception, code decryption, or patching in this MVP.

## Response format

A useful summary includes:

1. What artifact was analyzed.
2. Confirmed package/binary facts with paths or report sections.
3. Candidate indicators clearly labeled as unverified.
4. Missing/skipped evidence and practical limitations.
5. A link/path to `REPORT.md` and `report.json`.
