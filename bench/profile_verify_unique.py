#!/usr/bin/env python3
"""Real relay workload: UNIQUE frames (fresh wire -> unpack -> verify).
Honest before/after: OldVerifier = pre-change design (dict keyed on the full
signed bytes, first-inserted eviction); New = AgentVerifier (digest+sig key,
LRU, frame-level signed-bytes/digest memo)."""
from __future__ import annotations
import os, sys, time, threading

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from cryptography.exceptions import InvalidSignature
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, FrameFlags, OpCode


class OldVerifier:
    """Pre-change semantics, replicated verbatim for comparison."""
    def __init__(self, verifier: AgentVerifier):
        self._v = verifier
        self._cache = {}
        self._lock = threading.Lock()
        self._max = 4096

    def verify_frame(self, frame):
        if frame.sender_pin != self._v.pin:
            return False
        if not (frame.flags & FrameFlags.FLAG_SIGNED):
            return False
        if not frame.envelope or not frame.envelope.signature:
            return False
        # OLD: no frame memo -> get_signed_bytes re-derives + dict key = full bytes
        data = frame.get_signed_bytes()
        cached = self._cache.get(data)
        if cached is not None:
            return cached
        try:
            self._v._public_key.verify(frame.envelope.signature, data)
            result = True
        except InvalidSignature:
            result = False
        with self._lock:
            self._cache[data] = result
            if len(self._cache) > self._max:
                del self._cache[next(iter(self._cache))]
        return result


def timeit(fn, n, warm=100):
    for _ in range(warm):
        fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1e6


def make_unique_wires(identity, size, count):
    out = []
    for i in range(count):
        f = EacpFrame(
            msg_type=MsgType.MSG_SEND, opcode=OpCode.OP_ACTION_INVOKE,
            sender_pin=identity.pin, target_pin=2, transaction_id=i,
            capabilities_mask=1, verb="bench",
            data=b"x" * max(1, size - 64) + i.to_bytes(8, "big"),
        )
        identity.sign_frame(f)
        out.append(f.pack())
    return out


def main():
    ident = AgentIdentity.generate()
    pub = ident.public_bytes
    for size in (64, 4096, 65536):
        wires = make_unique_wires(ident, size, 500)
        new_v = AgentVerifier.from_public_bytes(pub)
        old_v = OldVerifier(AgentVerifier.from_public_bytes(pub))

        idx = 0
        def run_new():
            nonlocal idx
            w = wires[idx % 500]; idx += 1
            return new_v.verify_frame(EacpFrame.unpack(w))
        idx = 0
        def run_old():
            nonlocal idx
            w = wires[idx % 500]; idx += 1
            return old_v.verify_frame(EacpFrame.unpack(w))

        n_us = timeit(run_new, 400)
        o_us = timeit(run_old, 400)
        print(f"payload={size:>6}B  old={o_us:8.1f}us ({1e6/o_us:7.0f} f/s)   new={n_us:8.1f}us ({1e6/n_us:7.0f} f/s)   speedup={o_us/n_us:5.2f}x")


if __name__ == "__main__":
    main()
