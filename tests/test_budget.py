"""
Token Budget Enforcement tests — escrow, settlement, overflow, cascade, refund.
"""

import asyncio
import unittest

from eacp.budget import (
    BudgetError,
    PayloadTokenMeter,
    TokenBudgetLedger,
    create_downstream_constraints,
)
from eacp.client import RSessionBase
from eacp.constants import Capability, EacpError
from eacp.frame import EacpFrame, ExecutionConstraints
from eacp.primitives import EacpRendezvousException, MsgSend
from eacp.relay import EacpRelay
from eacp.security import AgentIdentity


class TestTokenBudgetLedger(unittest.TestCase):
    def test_escrow_commit_settlement(self):
        """Escrow reserves the ceiling; commit releases unused portion."""
        ledger = TokenBudgetLedger(ledger_capacity=1000)
        ledger.escrow(txn_id=1, budget=300)
        self.assertEqual(ledger.reserved, 300)

        remaining = ledger.consume(1, 120)
        self.assertEqual(remaining, 180)

        remaining = ledger.commit(1)
        self.assertEqual(remaining, 180)      # unused budget returned to caller
        self.assertEqual(ledger.reserved, 0)  # capacity fully released
        self.assertEqual(ledger.active_transactions, 0)

    def test_refund_on_failure_is_total(self):
        """Failed transaction leaves the ledger exactly as it was."""
        ledger = TokenBudgetLedger(ledger_capacity=1000)
        ledger.escrow(txn_id=1, budget=500)
        ledger.consume(1, 200)
        ledger.refund(1)
        self.assertEqual(ledger.reserved, 0)
        self.assertEqual(ledger.active_transactions, 0)

        # Refunding twice must be a no-op, not an error
        ledger.refund(1)

    def test_hard_overflow_no_partial_overdraw(self):
        """The spend that exceeds the escrow is refused atomically."""
        ledger = TokenBudgetLedger(ledger_capacity=1000)
        ledger.escrow(txn_id=1, budget=100)
        ledger.consume(1, 80)

        with self.assertRaises(BudgetError):
            ledger.consume(1, 30)  # 80 + 30 > 100

        # State unchanged after the refused spend
        self.assertEqual(ledger.remaining(1), 20)
        ledger.consume(1, 20)
        self.assertEqual(ledger.remaining(1), 0)

    def test_ledger_capacity_blocks_oversubscription(self):
        """N concurrent escrows cannot claim more than the agent's capacity."""
        ledger = TokenBudgetLedger(ledger_capacity=1000)
        ledger.escrow(txn_id=1, budget=600)
        ledger.escrow(txn_id=2, budget=400)  # capacity exactly reached

        with self.assertRaises(BudgetError):
            ledger.escrow(txn_id=3, budget=1)

        # After one commits, room opens up again: reserved = 400, available = 600
        ledger.consume(1, 50)
        ledger.commit(1)
        with self.assertRaises(BudgetError):
            ledger.escrow(txn_id=3, budget=650)  # 400 + 650 > 1000
        ledger.escrow(txn_id=3, budget=600)      # exactly fits
        self.assertEqual(ledger.reserved, 1000)

    def test_unlimited_budget_bypasses_envelope_not_capacity(self):
        """token_budget=0 means unlimited envelope; unlimited escrows do not reserve capacity."""
        ledger = TokenBudgetLedger(ledger_capacity=10)
        ledger.escrow(txn_id=1, budget=0)
        ledger.consume(1, 999_999)  # unlimited: no overflow
        self.assertEqual(ledger.commit(1), 0)


class TestBudgetMeter(unittest.TestCase):
    def test_payload_meter_is_deterministic(self):
        meter = PayloadTokenMeter()
        frame = EacpFrame(verb="echo", data={"text": "A" * 400})
        usage1 = meter.measure(frame, {"echoed": 400})
        usage2 = meter.measure(frame, {"echoed": 400})
        self.assertEqual(usage1, usage2)
        self.assertGreater(usage1, 90)  # ~400+ bytes payload at 4 bytes/token

    def test_cascade_constraints_shrink_envelope(self):
        frame = EacpFrame(
            constraints=ExecutionConstraints(token_budget=1000, timeout_ms=2000, max_depth_hops=5)
        )
        child = create_downstream_constraints(frame, parent_usage=250)
        self.assertEqual(child.token_budget, 750)
        self.assertEqual(child.max_depth_hops, 4)
        self.assertEqual(child.timeout_ms, 2000)

        grandchild = create_downstream_constraints(
            EacpFrame(constraints=child), parent_usage=100
        )
        self.assertEqual(grandchild.token_budget, 650)
        self.assertEqual(grandchild.max_depth_hops, 3)

    def test_cascade_unlimited_stays_unlimited(self):
        frame = EacpFrame()  # default: token_budget=0 (unlimited)
        child = create_downstream_constraints(frame, parent_usage=500)
        self.assertEqual(child.token_budget, 0)
        self.assertEqual(child.max_depth_hops, 9)


class TestBudgetOverWire(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = 18999
        self.relay = EacpRelay()
        await self.relay.start(host="127.0.0.1", port=self.port)

    async def asyncTearDown(self):
        await self.relay.stop()

    async def test_escrow_refused_before_compute(self):
        """Over-budget request is denied without executing the handler."""
        server = RSessionBase(token_ledger_capacity=100)
        ran = []

        def handler(frame):
            ran.append(True)
            return "ok"

        server.register_handler("work", handler)

        sender = RSessionBase()
        await server.connect(port=self.port)
        await sender.connect(port=self.port)

        with self.assertRaises(EacpRendezvousException) as ctx:
            await MsgSend(
                sender,
                target_pin=server.pin,
                verb="work",
                constraints=ExecutionConstraints(token_budget=500),  # > capacity 100
            )
        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_TOKEN_OVERFLOW)
        self.assertEqual(ran, [])  # handler never executed

        await sender.close()
        await server.close()

    async def test_overflow_mid_transaction_refunds(self):
        """Handler exceeding its envelope gets EACP_ERR_TOKEN_OVERFLOW; ledger rolls back."""
        server = RSessionBase(token_ledger_capacity=10_000)

        async def hungry_handler(frame):
            # Spend incrementally: 3 x 400 against a 1000 budget
            for _ in range(3):
                server.spend_tokens(frame.transaction_id, 400)
            return "should never get here"

        server.register_handler("hungry", hungry_handler)

        sender = RSessionBase()
        await server.connect(port=self.port)
        await sender.connect(port=self.port)

        with self.assertRaises(EacpRendezvousException) as ctx:
            await MsgSend(
                sender,
                target_pin=server.pin,
                verb="hungry",
                constraints=ExecutionConstraints(token_budget=1000),
            )
        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_TOKEN_OVERFLOW)

        # Ledger fully refunded: capacity available again
        self.assertEqual(server.ledger.reserved, 0)
        self.assertEqual(server.ledger.active_transactions, 0)

        await sender.close()
        await server.close()

    async def test_settlement_reports_remaining_budget(self):
        """Successful reply carries the unused budget in slot 2 for cascading."""
        server = RSessionBase(token_ledger_capacity=100_000)
        server.register_handler("compact", lambda f: {"tiny": 1})

        sender = RSessionBase()
        await server.connect(port=self.port)
        await sender.connect(port=self.port)

        reply = await MsgSend(
            sender,
            target_pin=server.pin,
            verb="compact",
            constraints=ExecutionConstraints(token_budget=5000),
        )
        self.assertEqual(reply.status, EacpError.EACP_SUCCESS)
        # PayloadTokenMeter charges for invocation + reply; far below 5000
        self.assertGreater(reply.constraints.token_budget, 4000)
        self.assertLess(reply.constraints.token_budget, 5000)

        await sender.close()
        await server.close()

    async def test_concurrent_escrows_share_capacity(self):
        """Parallel handlers cannot collectively oversubscribe the ledger."""
        server = RSessionBase(token_ledger_capacity=1000)

        async def sleeper(frame):
            await asyncio.sleep(0.05)
            return {"done": True}

        server.register_handler("sleep", sleeper)

        senders = [RSessionBase() for _ in range(4)]
        await server.connect(port=self.port)
        for s in senders:
            await s.connect(port=self.port)

        results = await asyncio.gather(*[
            MsgSend(
                s,
                target_pin=server.pin,
                verb="sleep",
                constraints=ExecutionConstraints(token_budget=400),
            )
            for s in senders
        ], return_exceptions=True)

        # 4 x 400 = 1600 > capacity 1000: at least one escrow must be refused
        overflows = [r for r in results if isinstance(r, EacpRendezvousException)
                     and r.code == EacpError.EACP_ERR_TOKEN_OVERFLOW]
        successes = [r for r in results if not isinstance(r, Exception)]
        self.assertGreater(len(overflows), 0)
        self.assertGreater(len(successes), 0)

        for s in senders:
            await s.close()
        await server.close()


if __name__ == "__main__":
    unittest.main()
