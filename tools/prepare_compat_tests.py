#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Migrate one pinned upstream expectation that encoded the old backslash loss."""

from pathlib import Path
import sys


def main():
    path = Path(sys.argv[1]) / "tests/lib/test_replace_placeholder_shell_fragment.sh"
    text = path.read_text()
    old = "  assertEquals 'echo \"a" + "\\" * 2 + "b\"' \"${__test_actual}\""
    new = "  assertEquals 'echo \"a" + "\\" * 4 + "b\"' \"${__test_actual}\""
    if text.count(old) == 1:
        path.write_text(text.replace(old, new, 1))
    elif text.count(new) != 1:
        raise SystemExit("Pinned compatibility fixture changed; review the migration before testing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
