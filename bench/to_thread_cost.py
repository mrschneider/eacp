#!/usr/bin/env python3
"""Micro-bench: to_thread overhead vs inline verify (hit & miss).
Informs how to offload without taxing the common replay (cache-hit) path."""
from __future__ import annotations
import os, sys, asyncio, time
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

async def main():
    priv = Ed25519PrivateKey.generate()
    ident = AgentIdentity.from_private_bytes(priv.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    verifier = AgentVerifier.from_public_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    hit_wire = signed_wire(1, ident)      # same frame -> cache hit after warm
    miss_wires = [signed_wire(1000 + i, ident) for i in range(200)]  # unique
    mi = [0]

    # to_thread overhead with a trivial body
    for _ in range(30): await asyncio.to_thread(lambda: 1)
    t0 = time.perf_counter()
    for _ in range(2000): await asyncio.to_thread(lambda: 1)
    print(f"{'to_thread overhead (trivial)':34s} {(time.perf_counter()-t0)/2000*1e6:8.1f} us/op")

    # inline hit vs inline miss (sync, on loop)
    for _ in range(30): verifier.verify_frame(EacpFrame.unpack(hit_wire))
    t0 = time.perf_counter()
    for _ in range(500): verifier.verify_frame(EacpFrame.unpack(hit_wire))
    print(f"{'inline verify  CACHE HIT':34s} {(time.perf_counter()-t0)/500*1e6:8.1f} us/op")
    for _ in range(30):
        verifier.verify_frame(EacpFrame.unpack(miss_wires[mi[0] % 200])); mi[0] += 1
    t0 = time.perf_counter()
    for _ in range(500):
        verifier.verify_frame(EacpFrame.unpack(miss_wires[mi[0] % 200])); mi[0] += 1
    print(f"{'inline verify  CACHE MISS':34s} {(time.perf_counter()-t0)/500*1e6:8.1f} us/op")

    # via to_thread
    for _ in range(30): await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(hit_wire))
    t0 = time.perf_counter()
    for _ in range(500): await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(hit_wire))
    print(f"{'to_thread verify CACHE HIT':34s} {(time.perf_counter()-t0)/500*1e6:8.1f} us/op")
    for _ in range(30):
        w = miss_wires[mi[0] % 200]; mi[0] += 1
        await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(w))
    t0 = time.perf_counter()
    for _ in range(500):
        w = miss_wires[mi[0] % 200]; mi[0] += 1
        await asyncio.to_thread(verifier.verify_frame, EacpFrame.unpack(w))
    print(f"{'to_thread verify CACHE MISS':34s} {(time.perf_counter()-t0)/500*1e6:8.1f} us/op")

asyncio.run(main())
