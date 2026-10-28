"""Test-suite runner with a hang watchdog that prints coroutine stacks.

CI-only helper: runs the unittest discovery exactly like
``python -m unittest discover tests -v``. A watchdog thread fires after
90s: it walks every live asyncio event loop found in the GC, prints
every task with its awaited future (``task._fut_waiter``) and Python
await-stack, dumps the C stacks via faulthandler, then exits non-zero.
A Windows-only hang (proactor drain / wait_closed) otherwise burns the
whole job timeout with no stack at all.
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


def _dump_tasks_on_loop(loop) -> None:
    print(f"--- loop {loop!r} closed={loop.is_closed()} running={loop.is_running()}", flush=True)
    try:
        tasks = asyncio.all_tasks(loop)
    except Exception as exc:
        print(f"    all_tasks failed: {exc}", flush=True)
        return
    for task in tasks:
        try:
            waiter = getattr(task, "_fut_waiter", None)
            print(
                f"    Task {task.get_name()} coro={task.get_coro()} state={task._state} "
                f"waiter={waiter!r}",
                flush=True,
            )
            for fr in task.get_stack(limit=None):
                print(
                    f"      {fr.f_code.co_filename}:{fr.f_lineno} in {fr.f_code.co_name}",
                    flush=True,
                )
        except Exception as exc:  # pragma: no cover - diagnostics only
            print(f"    (task dump error: {exc})", flush=True)


def _dump_and_die() -> None:
    print("==== HANG WATCHDOG: asyncio loops and task stacks ====", flush=True)
    seen = set()
    for obj in gc.get_objects():
        if isinstance(obj, asyncio.AbstractEventLoop) and id(obj) not in seen:
            seen.add(id(obj))
            _dump_tasks_on_loop(obj)
    print("==== HANG WATCHDOG: C stacks ====", flush=True)
    faulthandler.dump_traceback()
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
