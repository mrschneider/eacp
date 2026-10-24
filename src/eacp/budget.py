"""
EACP Token Budget Enforcement — kernel-resource accounting model.

Design (mirrors microkernel memory allocator + QNX resource manager semantics):

1. **Escrow model** — a handler never spends tokens directly. On dispatch the
   runtime reserves (escrows) the frame's `token_budget` against the agent's
   `ledger_capacity`. This makes budget oversubscription structurally
   impossible: N concurrent handlers each claiming the full budget cannot
   exceed the agent's ledger capacity, so a malicious sender cannot inflate
   cumulative claimed spend beyond what the agent is provisioned for.

2. **Settlement, not assertion** — after the handler runs, the pluggable
   `TokenMeter` reports actual usage. `commit()` settles the escrow:
   only the consumed amount is deducted from capacity; the remainder is
   released. Unused budget is never burned (no over-billing).

3. **Deterministic rollback** — on handler exception, cancel or timeout the
   escrow is refunded in full (CleanupStack discipline): a failed transaction
   leaves the ledger exactly as it was.

4. **Hard overflow** — `consume()` refuses the spend that would exceed the
   escrowed amount with `EACP_ERR_TOKEN_OVERFLOW`. Work is denied *before*
   the next unit of compute; there is no partial overdraw.

5. **Cascade accounting** — a handler that calls downstream agents propagates
   the *remaining* budget (parent budget − own usage) with a decremented
   hop count, so the whole delegation tree shares one budget envelope.

`token_budget == 0` means "unlimited" (frame carries no budget constraint) —
enforcement then reduces to ledger capacity only.
"""

from __future__ import annotations
import json
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Protocol

from .constants import EacpError
from .frame import EacpFrame, ExecutionConstraints

UNLIMITED_BUDGET = 0


class BudgetError(Exception):
    """Token budget violation. Carries the protocol error code."""

    def __init__(self, detail: str = ""):
        self.code = EacpError.EACP_ERR_TOKEN_OVERFLOW
        self.detail = detail
        super().__init__(f"{self.code.name}: {detail}")


class TokenMeter(Protocol):
    """Pluggable usage source. Returns tokens consumed by one handler run."""

    def measure(self, frame: EacpFrame, result: object) -> int:  # pragma: no cover
        ...


class PayloadTokenMeter:
    """
    Default deterministic meter, independent of any LLM provider:
    usage = invocation payload + reply payload, estimated at 4 bytes/token.
    Bounded and reproducible — suitable for tests and non-LLM tools.
    """

    def measure(self, frame: EacpFrame, result: object) -> int:
        try:
            req = len(json.dumps(frame.data or {}).encode("utf-8"))
        except (TypeError, ValueError):
            req = 0
        try:
            res = len(json.dumps(result, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            res = 0
        return (req + res + 3) // 4


@dataclass
class EscrowEntry:
    budget: int            # escrowed ceiling (0 = unlimited)
    consumed: int = 0      # tokens actually spent so far
    committed: bool = False


class TokenBudgetLedger:
    """
    Per-agent token ledger with escrow semantics. Thread-safe (a handler may
    run on any executor). Enforces both per-transaction budget and aggregate
    ledger capacity.
    """

    def __init__(self, ledger_capacity: int = 1_000_000):
        if ledger_capacity < 0:
            raise ValueError("ledger_capacity must be >= 0")
        self._capacity = ledger_capacity
        self._reserved = 0            # sum of active (non-unlimited) escrows
        self._escrows: Dict[int, EscrowEntry] = {}
        self._lock = threading.Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def reserved(self) -> int:
        with self._lock:
            return self._reserved

    @property
    def active_transactions(self) -> int:
        with self._lock:
            return len(self._escrows)

    # ---- lifecycle -------------------------------------------------------
    def escrow(self, txn_id: int, budget: int) -> None:
        """Reserves the transaction's budget ceiling against ledger capacity."""
        with self._lock:
            if txn_id in self._escrows:
                raise BudgetError(f"txn {txn_id} already escrowed")
            if budget != UNLIMITED_BUDGET:
                if budget < 0:
                    raise BudgetError("negative token budget")
                if self._reserved + budget > self._capacity:
                    raise BudgetError(
                        f"ledger capacity exceeded: reserved {self._reserved} "
                        f"+ requested {budget} > capacity {self._capacity}"
                    )
                self._reserved += budget
            self._escrows[txn_id] = EscrowEntry(budget=budget)

    def consume(self, txn_id: int, tokens: int) -> int:
        """
        Spends `tokens` against the escrow. Returns the remaining budget.
        Raises BudgetError if the spend exceeds the escrowed ceiling.
        """
        if tokens < 0:
            raise BudgetError("negative token spend")
        with self._lock:
            entry = self._escrows.get(txn_id)
            if entry is None:
                raise BudgetError(f"txn {txn_id} has no active escrow")
            if entry.committed:
                raise BudgetError(f"txn {txn_id} already committed")
            if entry.budget == UNLIMITED_BUDGET:
                entry.consumed += tokens
                return UNLIMITED_BUDGET
            if entry.consumed + tokens > entry.budget:
                raise BudgetError(
                    f"budget overflow on txn {txn_id}: "
                    f"used {entry.consumed} + spend {tokens} > escrowed {entry.budget}"
                )
            entry.consumed += tokens
            return entry.budget - entry.consumed

    def commit(self, txn_id: int) -> int:
        """
        Settles the transaction: releases the unused escrow from capacity and
        returns the remaining budget (0 for unlimited-budget transactions).
        """
        with self._lock:
            entry = self._escrows.pop(txn_id, None)
            if entry is None:
                raise BudgetError(f"txn {txn_id} has no active escrow")
            if entry.budget != UNLIMITED_BUDGET:
                self._reserved -= entry.budget
            return entry.budget - entry.consumed if entry.budget != UNLIMITED_BUDGET else 0

    def refund(self, txn_id: int) -> None:
        """Full deterministic rollback of the escrow (failure path)."""
        with self._lock:
            entry = self._escrows.pop(txn_id, None)
            if entry and entry.budget != UNLIMITED_BUDGET:
                self._reserved -= entry.budget

    def remaining(self, txn_id: int) -> Optional[int]:
        """Current remaining budget for an active escrow (None if unknown)."""
        with self._lock:
            entry = self._escrows.get(txn_id)
            if entry is None:
                return None
            if entry.budget == UNLIMITED_BUDGET:
                return UNLIMITED_BUDGET
            return entry.budget - entry.consumed


def create_downstream_constraints(
    frame: EacpFrame,
    parent_usage: int,
    timeout_ms: Optional[int] = None,
) -> ExecutionConstraints:
    """
    Builds the child constraints for a downstream MsgSend issued inside a
    handler: the budget envelope shrinks by the parent's own usage and the
    hop count decrements, so the whole delegation tree shares one envelope.
    """
    parent = frame.constraints
    parent_budget = parent.token_budget if parent else UNLIMITED_BUDGET
    child_budget = UNLIMITED_BUDGET if parent_budget == UNLIMITED_BUDGET else max(0, parent_budget - parent_usage)
    return ExecutionConstraints(
        token_budget=child_budget,
        timeout_ms=timeout_ms if timeout_ms is not None else (parent.timeout_ms if parent else 30_000),
        max_depth_hops=max(0, (parent.max_depth_hops if parent else 10) - 1),
    )
