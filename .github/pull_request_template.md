## Summary

Describe the change and the problem it solves.

## Evidence and limitations

- [ ] Findings remain clearly separated into observed facts, candidate indicators, and unknowns.
- [ ] Any new scan output avoids raw secrets by default.
- [ ] Bounded reads and safe handling of untrusted artifacts are preserved.

## Validation

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`

## Checklist

- [ ] No private app packages, reports, credentials, signing material, or user data included.
- [ ] Documentation is updated where behavior or limits changed.
