#!/usr/bin/env python3
"""Fine-grained cProfile of the route_frame dispatch path to locate the
~180us that sits on top of the 37us unpack+verify."""
from __future__ import annotations
import os, sys, time, asyncio, cProfile, pstats, io

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

    n = 1500
    base = 1_000_000

    for i in range(200):
        fr = make_signed_frame(identity, target=0x2, tx=base + i)
        await relay.route_frame(fr, session)

    pr = cProfile.Profile()
    pr.enable()
    for i in range(n):
        fr = make_signed_frame(identity, target=0x2, tx=base + 200 + i)
        await relay.route_frame(fr, session)
    pr.disable()

    sio = io.StringIO()
    ps = pstats.Stats(pr, stream=sio).sort_stats("cumulative")
    ps.print_stats(30)
    print(sio.getvalue())


if __name__ == "__main__":
    asyncio.run(main())
