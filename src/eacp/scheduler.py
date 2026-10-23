"""
EACP Concurrency Subsystem: Symbian EKA2 ActiveScheduler, CActive objects, and CleanupStack.
"""

from __future__ import annotations
import inspect
from contextlib import contextmanager
from typing import Any, Callable, List, Optional

from .constants import ActivePriority, RequestStatus


class TRequestStatus:
    """
    Asynchronous request completion status.
    KRequestPending indicates the request is still outstanding.
    """

    def __init__(self, initial_code: int = RequestStatus.KRequestPending):
        self._code: int = int(initial_code)

    @property
    def code(self) -> int:
        return self._code

    def is_pending(self) -> bool:
        return self._code == int(RequestStatus.KRequestPending)

    def is_complete(self) -> bool:
        return not self.is_pending()

    def complete(self, code: int = RequestStatus.KErrNone) -> None:
        self._code = int(code)

    def __repr__(self) -> str:
        return f"TRequestStatus({self._code})"


class CleanupItem:
    """
    Guarded item on the CleanupStack. If RunL leaves, cleanup is invoked.
    """

    def __init__(self, resource: Any, cleanup_fn: Optional[Callable[[Any], None]] = None):
        self.resource = resource
        self.cleanup_fn = cleanup_fn

    def destroy(self) -> None:
        if self.cleanup_fn:
            self.cleanup_fn(self.resource)
        elif hasattr(self.resource, "close") and callable(self.resource.close):
            self.resource.close()
        elif hasattr(self.resource, "cleanup") and callable(self.resource.cleanup):
            self.resource.cleanup()
        elif hasattr(self.resource, "cancel") and callable(self.resource.cancel):
            self.resource.cancel()


class CleanupStack:
    """
    Symbian-style CleanupStack for two-phase resource management and deterministic rollback.
    """

    def __init__(self):
        self._stack: List[CleanupItem] = []

    def push(self, resource: Any, cleanup_fn: Optional[Callable[[Any], None]] = None) -> None:
        self._stack.append(CleanupItem(resource, cleanup_fn))

    def pop(self) -> Any:
        if not self._stack:
            return None
        return self._stack.pop().resource

    def pop_and_destroy(self, count: int = 1) -> None:
        for _ in range(count):
            if not self._stack:
                break
            item = self._stack.pop()
            try:
                item.destroy()
            except Exception:
                pass

    def pop_all_and_destroy(self) -> None:
        self.pop_and_destroy(len(self._stack))

    def __len__(self) -> int:
        return len(self._stack)

    @contextmanager
    def push_guard(self, resource: Any, cleanup_fn: Optional[Callable[[Any], None]] = None):
        self.push(resource, cleanup_fn)
        try:
            yield resource
        except Exception:
            self.pop_and_destroy(1)
            raise
        else:
            self.pop()


class CActive:
    """
    Symbian CActive base class for non-preemptive cooperative event handling.
    """

    def __init__(self, priority: ActivePriority = ActivePriority.EPriorityStandard):
        self.priority: ActivePriority = priority
        self.status: TRequestStatus = TRequestStatus(RequestStatus.KErrNone)
        self._is_active: bool = False
        self.scheduler: Optional[ActiveScheduler] = None

    def is_active(self) -> bool:
        return self._is_active

    def set_active(self) -> None:
        if self._is_active:
            raise RuntimeError("Active object already active (E32USER-CBase 42)")
        self._is_active = True
        self.status.complete(RequestStatus.KRequestPending)

    def cancel(self) -> None:
        """Aborts ongoing asynchronous operation cleanly."""
        if not self._is_active:
            return
        try:
            self.do_cancel()
        finally:
            self._is_active = False
            self.status.complete(RequestStatus.KErrCancel)

    def do_cancel(self) -> None:
        """Abstract cancel implementation for subclasses."""
        pass

    def run_l(self) -> None:
        """Event dispatch callback when request completes. May leave (raise exception)."""
        pass

    def run_error(self, error: Exception) -> int:
        """
        Invoked if RunL() leaves. Return KErrNone if handled, or error code.
        Default re-raises error.
        """
        return RequestStatus.KErrGeneral


class ActiveScheduler:
    """
    Symbian ActiveScheduler: cooperative non-preemptive priority scheduler.
    """

    _current: Optional[ActiveScheduler] = None

    def __init__(self):
        self._actives: List[CActive] = []
        self._running: bool = False
        self.cleanup_stack: CleanupStack = CleanupStack()

    @classmethod
    def current(cls) -> ActiveScheduler:
        if cls._current is None:
            cls._current = ActiveScheduler()
        return cls._current

    @classmethod
    def install(cls, scheduler: ActiveScheduler) -> None:
        cls._current = scheduler

    def add(self, active: CActive) -> None:
        if active in self._actives:
            return
        active.scheduler = self
        self._actives.append(active)
        # Sort descending by priority value
        self._actives.sort(key=lambda a: int(a.priority), reverse=True)

    def remove(self, active: CActive) -> None:
        if active in self._actives:
            self._actives.remove(active)
            active.scheduler = None

    def run_one_cycle(self) -> bool:
        """
        Runs one scheduling round: finds highest-priority ready CActive.
        Returns True if an active object was dispatched, False otherwise.
        """
        for active in list(self._actives):
            if active.is_active() and active.status.is_complete():
                active._is_active = False
                stack_depth_before = len(self.cleanup_stack)
                try:
                    active.run_l()
                except Exception as exc:
                    # Automatic rollback of any items pushed to cleanup stack during RunL
                    items_to_clean = len(self.cleanup_stack) - stack_depth_before
                    if items_to_clean > 0:
                        self.cleanup_stack.pop_and_destroy(items_to_clean)
                    res = active.run_error(exc)
                    if res != RequestStatus.KErrNone:
                        raise
                return True
        return False

    def start(self, max_iterations: Optional[int] = None) -> None:
        self._running = True
        iterations = 0
        while self._running:
            dispatched = self.run_one_cycle()
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break
            if not dispatched and not any(a.is_active() for a in self._actives):
                break

    def stop(self) -> None:
        self._running = False
