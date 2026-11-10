#!/usr/bin/env python3
"""PROOF: does synchronous Ed25519 verify block the asyncio event loop?

A 'tick' task measures the max gap between consecutive loop turns.
Scenario A: verify() runs inline on the loop.
Scenario B: verify() runs via asyncio.to_thread.
If the loop blocks in A and stays responsive in B, offloading is a real win.
"""
from __future__ import annotations
import os, sys, asyncio, time, statistics
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, OpCode

def signed_wire(i, ident):
    f = EacpFrame(msg_type=MsgType.MSG_SEND, opcode=OpCode.OP_ACTION_INVOKE,
                  sender_pin=ident.pin, target_pin=2, transaction_id=i,
                  capabilities_mask=1, verb="echo", data={"n": i, "pad": "x" * 200})
    ident.sign_frame(f)
    return f.pack()

async def measure(verifier, wires, mode):
    gap_max, gap_sum, n = 0.0, 0.0, 0
    stop = False
    async def tick():
        nonlocal gap_max, gap_sum, n, stop
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(0)
            now = time.perf_counter()
            g = now - last
            if g > gap_max: gap_max = g
            gap_sum += g
            n += 1
            last = now
    t = asyncio.create_task(tick())
    # warm
    for w in wires[:50]:
        if mode == "inline":
            verifier.verify_frame(EacpFrame.unpack(w))
        else:
            await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(w))
    for w in wires:
        if mode == "inline":
            verifier.verify_frame(EacpFrame.unpack(w))
        else:
            await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(w))
    stop = True
    await t
    gavg = (gap_sum / n) * 1e6 if n else float("inf")
    return gap_max * 1e6, gavg, n

async def main():
    priv = Ed25519PrivateKey.generate()
    ident = AgentIdentity.from_private_bytes(priv.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    verifier = AgentVerifier.from_public_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    wires = [signed_wire(i, ident) for i in range(300)]
    for mode in ("inline", "to_thread"):
        gmax, gavg, n = await measure(verifier, wires, mode)
        print(f"{mode:9s}  loop-turn max={gmax:7.1f}us  avg={gavg:6.2f}us  (ticks={n})")

if __name__ == "__main__":
    asyncio.run(main())
