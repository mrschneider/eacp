#!/usr/bin/env python3
"""Profile ledger.record_async cost in isolation."""
from __future__ import annotations
import os, sys, time, asyncio

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from eacp.ledger import AuditLedger

async def main():
    ledger = AuditLedger(file_path=None)  # sync fast path
    n = 5000
    args = dict(tx_id=12345, sender_pin=0x1, target_pin=0x2, verb="echo",
                capabilities_mask=1, status=0, data_payload=b"x" * 64)
    for _ in range(200):
        ledger.record_async(**args)
    t0 = time.perf_counter()
    for _ in range(n):
        await ledger.record_async(**args)
    t1 = time.perf_counter()
    print(f"record_async (file=None, sync): {(t1-t0)/n*1e6:.3f} us")

    ledger2 = AuditLedger(file_path=None, write_queue_size=16)
    for _ in range(200):
        await ledger2.record_async(**args)
    t0 = time.perf_counter()
    for _ in range(n):
        await ledger2.record_async(**args)
    t1 = time.perf_counter()
    print(f"record_async (executor, async): {(t1-t0)/n*1e6:.3f} us")

if __name__ == "__main__":
    asyncio.run(main())
