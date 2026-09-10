"""Executable entrypoint for the Python HTTP suite."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


def main() -> int:
    here = Path(__file__).resolve().parent
    top = here.parents[1]
    suite = unittest.defaultTestLoader.discover(str(here), top_level_dir=str(top))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
