#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the reviewed UAC fixes using isolated regression fixtures."""

import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    return subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_shell_fixes.py", "-v"],
        cwd=args.repository.resolve(strict=True),
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
