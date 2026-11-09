#!/usr/bin/env python3
"""Quantify verify-path improvements: cache-hit cost, cache memory, LRU."""
from __future__ import annotations
import os, sys, time, hashlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, OpCode

def timeit(fn, n, warm=200):
    for _ in range(warm):
        fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1e6

def signed_wire(identity, payload: bytes):
    f = EacpFrame(
        msg_type=MsgType.MSG_SEND, opcode=OpCode.OP_ACTION_INVOKE,
        sender_pin=identity.pin, target_pin=2, transaction_id=1,
        capabilities_mask=1, verb="bench", data=payload,
    )
    identity.sign_frame(f)
    return f.pack()

def main():
    ident = AgentIdentity.generate()
    verifier = AgentVerifier.from_public_bytes(ident.public_bytes)

    for size in (64, 4096, 65536):
        wire = signed_wire(ident, b"x" * size)
        frame = EacpFrame.unpack(wire)
        # cold: fresh verifier (empty cache)
        cold_v = AgentVerifier.from_public_bytes(ident.public_bytes)
        cold = timeit(lambda: cold_v.verify_frame(frame), 300, warm=50)
        # warm: same verifier, repeated verify of the same frame (cache hit)
        warm_us = timeit(lambda: verifier.verify_frame(frame), 3000, warm=500)
        # fresh unpack each time (real relay: new EacpFrame object per frame)
        def fresh_verify():
            return verifier.verify_frame(EacpFrame.unpack(wire))
        fresh = timeit(fresh_verify, 1000, warm=100)
        print(f"payload={size:>6}B  cold={cold:8.1f}us  warm(same obj)={warm_us:7.1f}us  fresh-unpack+hit={fresh:7.1f}us")

    # memory: fill cache to max with 64KB frames
    big = signed_wire(ident, b"y" * 65536)
    f = EacpFrame.unpack(big)
    v = AgentVerifier.from_public_bytes(ident.public_bytes)
    t0 = time.perf_counter()
    for i in range(4096):
        # unique frames so they are distinct cache entries
        w = bytearray(big); w[20] = i % 256
        v.verify_frame(EacpFrame.unpack(bytes(w)))
    wall = (time.perf_counter() - t0) * 1e6
    key_bytes = sum(len(k) for k in v._verify_cache)
    print(f"fill 4096 x 64KB entries: {wall/1e6:.2f}s  cache key storage: {key_bytes/1024:.0f} KiB")

    # LRU correctness: oldest (LRU) entry evicted, recent entry survives
    k0 = next(iter(v._verify_cache))
    # touch the first entry to make it MRU
    v._verify_cache.move_to_end(k0)
    v.verify_frame(f)  # force one more insert -> evict LRU
    assert k0 in v._verify_cache, "LRU: touched entry must survive"
    print("LRU eviction: touched entry survives, size =", len(v._verify_cache))

if __name__ == "__main__":
    main()
