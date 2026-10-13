# Contributing

Thanks for helping improve iOS-RE Agent.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

## Guidelines

- Keep static analysis deterministic where practical and document limitations.
- Prefer small, tested helpers over shelling out to external commands.
- Preserve compatibility with Python 3.10+ and avoid required runtime dependencies.
- Treat all package contents as untrusted; don't extract ZIP archives or execute target code.
- Never add features intended to break app encryption, code signing, access controls, or account protections.
- When adding a new finding category, explain false-positive/false-negative risks and avoid dumping raw matched strings by default.
- Add fixtures using synthetic data. Do not commit third-party app packages or private production artifacts.

## Pull requests

Include the problem statement, approach, limitations, and tests run. For parser changes, include a malformed-input test where relevant.
