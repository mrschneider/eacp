#!/usr/bin/env python3
"""Micro-profile the verify_frame sub-steps."""
from __future__ import annotations
import os, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eacp.frame import EacpFrame
from eacp.security import AgentIdentity, AgentVerifier
from eacp.constants import MsgType, OpCode

priv = Ed25519PrivateKey.generate()
identity = AgentIdentity.from_private_bytes(priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
))
verifier = AgentVerifier.from_public_bytes(priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
))

f = EacpFrame(
    msg_type=MsgType.MSG_SEND, opcode=OpCode.OP_ACTION_INVOKE,
    sender_pin=identity.pin, target_pin=0x2, transaction_id=12345,
    capabilities_mask=1, verb="echo",
    data={"hello": "world", "n": 42, "items": list(range(20))},
)
identity.sign_frame(f)
raw = f.pack()
sig = f.envelope.signature

n = 5000
for _ in range(200):
    verifier.verify_frame(f)
t0 = time.perf_counter()
for _ in range(n):
    verifier.verify_frame(f)
t1 = time.perf_counter()
print(f"verify_frame (cached hash): {(t1-t0)/n*1e6:.3f} us")

# get_signed_bytes alone
for _ in range(200):
    f.get_signed_bytes()
t0 = time.perf_counter()
for _ in range(n):
    f.get_signed_bytes()
t1 = time.perf_counter()
print(f"get_signed_bytes:           {(t1-t0)/n*1e6:.3f} us")

# verify (crypto) alone
for _ in range(200):
    verifier.verify(sig, f.get_signed_bytes())
t0 = time.perf_counter()
for _ in range(n):
    verifier.verify(sig, f.get_signed_bytes())
t1 = time.perf_counter()
print(f"crypto verify:              {(t1-t0)/n*1e6:.3f} us")

# full unpack
for _ in range(200):
    EacpFrame.unpack(raw)
t0 = time.perf_counter()
for _ in range(n):
    EacpFrame.unpack(raw)
t1 = time.perf_counter()
print(f"EacpFrame.unpack:           {(t1-t0)/n*1e6:.3f} us")

# pack
for _ in range(200):
    f.pack()
t0 = time.perf_counter()
for _ in range(n):
    f.pack()
t1 = time.perf_counter()
print(f"EacpFrame.pack:             {(t1-t0)/n*1e6:.3f} us")
