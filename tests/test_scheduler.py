"""
Unit tests for ActiveScheduler, CActive objects, and CleanupStack.
"""

import asyncio
import unittest

from eacp.constants import ActivePriority, RequestStatus
from eacp.scheduler import (
    ActiveScheduler,
    AsyncActive,
    AsyncActiveScheduler,
    CActive,
    CleanupItem,
    CleanupStack,
    TRequestStatus,
)


class MockResource:
    def __init__(self, name: str):
        self.name = name
        self.cleaned: bool = False

    def close(self):
        self.cleaned = True


class MockActive(CActive):
    def __init__(self, priority: ActivePriority, name: str, execution_log: list):
        super().__init__(priority=priority)
        self.name = name
        self.execution_log = execution_log
        self.cancelled: bool = False

    def do_cancel(self):
        self.cancelled = True

    def run_l(self):
        self.execution_log.append(self.name)


class FaultyActive(CActive):
    def __init__(self, resource: MockResource, cleanup_stack: CleanupStack):
        super().__init__()
        self.resource = resource
        self.cleanup_stack = cleanup_stack

    def run_l(self):
        # Push resource to cleanup stack during execution
        self.cleanup_stack.push(self.resource)
        # Leave / raise error
        raise RuntimeError("Inference memory overflow simulated")


class TestEacpScheduler(unittest.TestCase):
    def test_request_status_lifecycle(self):
        status = TRequestStatus()
        self.assertTrue(status.is_pending())
        self.assertFalse(status.is_complete())
        self.assertEqual(status.code, int(RequestStatus.KRequestPending))

        status.complete(RequestStatus.KErrNone)
        self.assertFalse(status.is_pending())
        self.assertTrue(status.is_complete())
        self.assertEqual(status.code, int(RequestStatus.KErrNone))

    def test_active_object_lifecycle_and_cancel(self):
        log = []
        active = MockActive(ActivePriority.EPriorityStandard, "worker", log)
        self.assertFalse(active.is_active())

        active.set_active()
        self.assertTrue(active.is_active())
        self.assertTrue(active.status.is_pending())

        # Calling set_active again must raise
        with self.assertRaises(RuntimeError):
            active.set_active()

        # Cancel cleanly
        active.cancel()
        self.assertFalse(active.is_active())
        self.assertTrue(active.cancelled)
        self.assertEqual(active.status.code, int(RequestStatus.KErrCancel))

    def test_priority_scheduling(self):
        scheduler = ActiveScheduler()
        log = []

        low = MockActive(ActivePriority.EPriorityLow, "low", log)
        high = MockActive(ActivePriority.EPriorityHigh, "high", log)
        std = MockActive(ActivePriority.EPriorityStandard, "std", log)

        scheduler.add(low)
        scheduler.add(high)
        scheduler.add(std)

        # Mark all complete & active
        for a in (low, high, std):
            a.set_active()
            a.status.complete(RequestStatus.KErrNone)

        # Run scheduler until all dispatched
        scheduler.start()

        # High priority must run first, then std, then low
        self.assertEqual(log, ["high", "std", "low"])

    def test_cleanup_stack_deterministic_rollback(self):
        stack = CleanupStack()
        res1 = MockResource("res1")
        res2 = MockResource("res2")

        stack.push(res1)
        stack.push(res2)
        self.assertEqual(len(stack), 2)

        # Pop res2 without destroying
        popped = stack.pop()
        self.assertEqual(popped, res2)
        self.assertFalse(res2.cleaned)

        # Destroy res1
        stack.pop_and_destroy(1)
        self.assertTrue(res1.cleaned)
        self.assertEqual(len(stack), 0)

    def test_cleanup_stack_guard_context(self):
        stack = CleanupStack()
        res = MockResource("guard_res")

        try:
            with stack.push_guard(res):
                self.assertEqual(len(stack), 1)
                raise ValueError("Simulated abort")
        except ValueError:
            pass

        # Upon exception, push_guard should have destroyed the resource
        self.assertTrue(res.cleaned)
        self.assertEqual(len(stack), 0)

    def test_scheduler_automatic_rollback_on_leave(self):
        scheduler = ActiveScheduler()
        res = MockResource("leak_candidate")
        faulty = FaultyActive(res, scheduler.cleanup_stack)

        scheduler.add(faulty)
        faulty.set_active()
        faulty.status.complete(RequestStatus.KErrNone)

        # When faulty.run_l() leaves, scheduler must pop and destroy pushed resources
        with self.assertRaises(RuntimeError):
            scheduler.run_one_cycle()

        self.assertTrue(res.cleaned)
        self.assertEqual(len(scheduler.cleanup_stack), 0)


class TestAsyncActiveScheduler(unittest.IsolatedAsyncioTestCase):
    async def test_async_active_bridge_execution(self):
        scheduler = AsyncActiveScheduler()
        active_dispatched = []

        class ComputeActive(AsyncActive):
            def run_l(self):
                active_dispatched.append(self.result)

        obj = ComputeActive(priority=ActivePriority.EPriorityHigh)
        scheduler.add(obj)

        async def async_worker():
            await asyncio.sleep(0.01)
            return "async_result_42"

        obj.start_async(async_worker())
        self.assertTrue(obj.is_active())

        # Wait deterministically for async completion (no fixed-sleep races)
        for _ in range(200):
            if obj.status.is_complete():
                break
            await asyncio.sleep(0.01)
        await scheduler.run_until_idle()

        self.assertEqual(active_dispatched, ["async_result_42"])
        self.assertFalse(obj.is_active())


if __name__ == "__main__":
    unittest.main()
