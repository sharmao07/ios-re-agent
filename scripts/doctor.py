#!/usr/bin/env python3
"""Run the iOS-RE Agent environment check from a source checkout."""

from ios_re_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["doctor"]))
