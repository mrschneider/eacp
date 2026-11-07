#!/usr/bin/env python3
"""Profile the real hot-path costs: unpack -> verify_frame -> pack -> reply."""
from __future__ import annotations
import os
import sys
import time
import hashlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, FrameFlags, EacpError, OpCode


def make_signed_frame(identity):
    f = EacpFrame(
        msg_type=MsgType.MSG_SEND,
        opcode=OpCode.OP_ACTION_INVOKE,
        sender_pin=identity.pin,
        target_pin=0x0000_0000_0000_0002,
        transaction_id=123456789,
        capabilities_mask=1,
        verb="echo",
        data={"hello": "world", "n": 42, "items": list(range(20))},
    )
    identity.sign_frame(f)
    return f.pack(), f


def timeit(fn, n=20000, warm=2000):
    for _ in range(warm):
        fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    t1 = time.perf_counter()
    return (t1 - t0) / n * 1e6, n


def main():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    identity = AgentIdentity.from_private_bytes(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    verifier = AgentVerifier.from_public_bytes(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))

    wire, frame = make_signed_frame(identity)
    n = 20000

    print(f"unpack:            {timeit(lambda: EacpFrame.unpack(wire))[0]:.3f} us")
    print(f"verify_frame:      {timeit(lambda: verifier.verify_frame(EacpFrame.unpack(wire)))[0]:.3f} us")
    print(f"get_signed_bytes:  {timeit(lambda: frame.get_signed_bytes())[0]:.3f} us")
    print(f"pack:              {timeit(lambda: frame.pack())[0]:.3f} us")
    print(f"create_reply:      {timeit(lambda: frame.create_reply(result_data={'ok': True}))[0]:.3f} us")
    print(f"pack_frame:        {timeit(lambda: identity.pack_frame(frame))[0]:.3f} us")

    pk = identity.public_bytes
    us, _ = timeit(lambda: hashlib.sha256(pk).digest())
    print(f"sha256(pk):        {us:.3f} us")

    def full():
        fr = EacpFrame.unpack(wire)
        verifier.verify_frame(fr)
        reply = fr.create_reply(result_data={"ok": True})
        identity.pack_frame(reply)
    us, _ = timeit(full)
    print(f"full round-trip:   {us:.3f} us")


if __name__ == "__main__":
    main()
