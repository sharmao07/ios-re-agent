# Guidance for coding agents

- Read `README.md`, `SKILL.md`, and `SECURITY.md` before changing behavior.
- Keep the core package standard-library-only unless a design note justifies a new dependency.
- The analyzer must remain read-only and must not execute the target app/binary.
- Do not add decryption, signing bypass, app patching, credential extraction, or traffic interception functionality.
- Treat package names, paths, plist values, binary strings, and endpoint strings as untrusted input.
- Preserve bounded read sizes, archive-entry limits, path validation, URL redaction, and report limitations.
- Add tests for parser changes and malformed/truncated input. Run `python -m pytest` before proposing a change.
- Do not commit target apps, private reports, credentials, provisioning profiles, signing keys, or user data.
- Report discoveries as observed facts, candidates, or unknowns; never describe string matches as proof of behavior.
