"""Canonical CLI exit codes for the passport commands (spec §02).

These are a contract with CI: a pipeline greps the exit code, not the text.

    0  success / SHIP / VALID / CLEAN
    1  general runtime error
    2  invalid arguments
    3  license required (a paid feature used without an active license)
    4  check failed: DON'T SHIP (gate) / INVALID (verify) / threat found (scan)
"""

from __future__ import annotations

OK = 0
ERROR = 1
BAD_ARGS = 2
LICENSE_REQUIRED = 3
CHECK_FAILED = 4
