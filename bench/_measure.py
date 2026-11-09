"""Measure verify_frame cost: unique frames (no cache help) and replay (cache hit).
Usage: python3 bench/_measure.py <sys.path-dir> <label>
"""
import sys, timeit
sys.path.insert(0, sys.argv[1])
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, OpCode

def t(label, fn, n=400):
    fn(); fn()
    best = min(timeit.repeat(fn, number=n, repeat=5)) / n * 1e6
    print(f"{label:28s} {best:8.1f} us/op")

ident = AgentIdentity.generate()
v = AgentVerifier.from_public_bytes(ident.public_bytes)

def make_wires(size, count):
    out = []
    for i in range(count):
        f = EacpFrame(msg_type=MsgType.MSG_SEND, opcode=OpCode.OP_ACTION_INVOKE,
                      sender_pin=ident.pin, target_pin=2, transaction_id=i,
                      capabilities_mask=1, verb="bench",
                      data=b"x" * max(1, size - 64) + i.to_bytes(8, "big"))
        ident.sign_frame(f); out.append(f.pack())
    return out

for size in (65536,):
    wires = make_wires(size, 400)
    idx = [0]
    def unique():
        w = wires[idx[0] % 400]; idx[0] += 1
        v.verify_frame(EacpFrame.unpack(w))
    def replay():
        f = EacpFrame.unpack(wires[0])
        v.verify_frame(f)
    print(f"--- payload={size}B ---")
    t("unique frames", unique)
    t("replay (cache hit)", replay)
