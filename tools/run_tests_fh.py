"""Test-suite runner with a hang watchdog that prints coroutine stacks.

CI-only helper: runs the unittest discovery exactly like
``python -m unittest discover tests -v``. A watchdog thread fires after
90s: faulthandler dumps the C stacks (loop state) and then we print the
Python await-stack of EVERY live asyncio.Task — a hung test on Windows
(proactor drain / wait_closed) otherwise burns the job timeout with no
stack at all. Then exit non-zero so the job goes red fast.
"""

import faulthandler
import gc
import asyncio
import os
import sys
import threading
import time
import unittest

DUMP_AFTER_SECONDS = 90


def _dump_and_die() -> None:
    print("==== HANG WATCHDOG: C stacks ====", flush=True)
    faulthandler.dump_traceback()
    print("==== HANG WATCHDOG: asyncio task stacks ====", flush=True)
    seen = set()
    for obj in gc.get_objects():
        if isinstance(obj, asyncio.Task) and id(obj) not in seen:
            seen.add(id(obj))
            try:
                print(f"--- Task {obj!r} state={obj._state}", flush=True)
                stack = obj.get_stack(limit=None)
                if not stack:
                    print("    (suspended, no frames captured)", flush=True)
                for fr in stack:
                    print(
                        f"    {fr.f_code.co_filename}:{fr.f_lineno} in {fr.f_code.co_name}",
                        flush=True,
                    )
                    co = fr.f_locals.get(".asyncio_future_blocking")
                    # surface the awaited future when present
                    for name, val in fr.f_locals.items():
                        if isinstance(val, asyncio.Future):
                            print(f"      awaiting future: {val!r} done={val.done()}", flush=True)
            except Exception as exc:  # pragma: no cover - diagnostics only
                print(f"    (dump error: {exc})", flush=True)
    print("==== END HANG WATCHDOG ====", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(70)


if __name__ == "__main__":
    watchdog = threading.Timer(DUMP_AFTER_SECONDS, _dump_and_die)
    watchdog.daemon = True
    watchdog.start()
    started = time.monotonic()
    result = unittest.main(
        module=None,
        argv=["unittest", "discover", "tests", "-v"],
        exit=False,
    )
    watchdog.cancel()
    print(f"suite finished in {time.monotonic() - started:.1f}s", flush=True)
    sys.exit(0 if result.result.wasSuccessful() else 1)
