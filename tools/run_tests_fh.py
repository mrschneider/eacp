"""Test-suite runner with a faulthandler watchdog.

CI-only helper: runs the unittest discovery exactly like
``python -m unittest discover tests -v``, but arms
``faulthandler.dump_traceback_later`` so a hung test dumps EVERY
thread's stack to stderr and exits while the job can still produce a
readable log. Without this, a Windows-only hang (proactor drain /
wait_closed) burns the whole job timeout and leaves no stack.
"""

import faulthandler
import sys
import unittest

DUMP_AFTER_SECONDS = 90

if __name__ == "__main__":
    faulthandler.dump_traceback_later(DUMP_AFTER_SECONDS, exit=True)
    result = unittest.main(
        module=None,
        argv=["unittest", "discover", "tests", "-v"],
        exit=False,
    )
    sys.exit(0 if result.result.wasSuccessful() else 1)
