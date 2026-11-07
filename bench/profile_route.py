#!/usr/bin/env python3
"""Profile the real route_frame dispatch path to find the 1.21ms p50 sink."""
from __future__ import annotations
import os, sys, time, asyncio

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.relay import EacpRelay, RelayClientSession
from eacp.constants import MsgType, FrameFlags, EacpError, OpCode


def make_signed_frame(identity, target=0x2, tx=1):
    f = EacpFrame(
        msg_type=MsgType.MSG_SEND,
        opcode=OpCode.OP_ACTION_INVOKE,
        sender_pin=identity.pin,
        target_pin=target,
        transaction_id=tx,
        capabilities_mask=1,
        verb="echo",
        data={"hello": "world", "n": 42, "items": list(range(20))},
    )
    identity.sign_frame(f)
    return f


async def main():
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

    relay = EacpRelay()
    target_sess = RelayClientSession(pin=0x2, verifier=verifier)
    relay.register_agent(0x2, target_sess, verifier)
    target_sess.closed = False

    src = make_signed_frame(identity, target=0x2, tx=1)
    session = RelayClientSession(pin=identity.pin, verifier=verifier)
    relay.register_agent(identity.pin, session, verifier)
    session.closed = False

    n = 2000
    base = 1_000_000

    # Warm (unique tx so replay buffer doesn't reject)
    for i in range(200):
        fr = make_signed_frame(identity, target=0x2, tx=base + i)
        await relay.route_frame(fr, session)

    t0 = time.perf_counter()
    for i in range(n):
        fr = make_signed_frame(identity, target=0x2, tx=base + 200 + i)
        await relay.route_frame(fr, session)
    t1 = time.perf_counter()
    us = (t1 - t0) / n * 1e6
    print(f"route_frame (full dispatch): {us:.3f} us/frame, {n} frames")
    print(f"  -> {n / (t1 - t0):.0f} req/s")

    fr = make_signed_frame(identity, target=0x2, tx=base)
    for _ in range(200):
        fr2 = EacpFrame.unpack(fr.pack())
        verifier.verify_frame(fr2)
    t0 = time.perf_counter()
    for _ in range(n):
        fr2 = EacpFrame.unpack(fr.pack())
        verifier.verify_frame(fr2)
    t1 = time.perf_counter()
    print(f"unpack+verify only:          {(t1-t0)/n*1e6:.3f} us/frame")


if __name__ == "__main__":
    asyncio.run(main())
