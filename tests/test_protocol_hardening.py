"""Regression battery for the external protocol/security analysis.

Every test here encodes a VERIFIED finding from the review of commit
33d872b: authorization claims, CA trust chain, signature enforcement,
replay, signing x compression, decompression bounds, real cancellation,
concurrent deadlock edges, the exhausted-budget delegation escape,
pre-dispatch estimates, offline-queue overflow/expiry, ledger recovery,
mesh request/reply, origin binding, trace propagation, TLS defaults.
"""

import asyncio
import json
import struct
import sys
import time
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eacp.constants import Capability, EACP_VERSION, EacpError, FrameFlags, MsgType, OpCode
from eacp.frame import EacpFrame, ExecutionConstraints, HEADER_STRUCT
from eacp.ledger import AuditLedger, LedgerIntegrityError
from eacp.mesh import RelayPeer
from eacp.primitives import EacpRendezvousException
from eacp.budget import BudgetError, create_downstream_constraints
from eacp.relay import DeadlockGraph, EacpRelay
from eacp.client import RSessionBase
from eacp.security import (
    AgentIdentity,
    EnterpriseCA,
    PlatSecGate,
    SecurityManifest,
    SignedManifest,
    create_client_ssl_context,
)
from eacp.telemetry import TraceContext


async def _wait(pred, timeout: float = 5.0) -> bool:
    """Async poll — time.sleep() here would freeze the event loop and the
    very I/O we are waiting for would never run."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


class HardenedRelayTestBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = EacpRelay(relay_id="relay-1")
        await self.relay.start(host="127.0.0.1", port=0)
        self.port = self.relay.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.relay.stop()


# --------------------------------------------------------------------------
# 3. Signing is coherent with compression (repro: sign -> pack -> unpack
#    -> verify returned False for a compressible payload)

class TestSigningCompressionContract(unittest.TestCase):
    def test_sign_compress_verify_roundtrip(self):
        ident = AgentIdentity.generate()
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            verb="big",
            sender_pin=ident.pin,
            target_pin=0x1234,
            transaction_id=4242,
            data={"blob": "A" * 3000},  # well past the 1KB threshold
            constraints=ExecutionConstraints(token_budget=100, timeout_ms=1000),
        )
        ident.sign_frame(frame)
        wire = frame.pack()
        self.assertTrue(frame.flags & FrameFlags.FLAG_COMPRESSED, "payload should compress")

        parsed = EacpFrame.unpack(wire)
        self.assertTrue(parsed.flags & FrameFlags.FLAG_COMPRESSED)
        # the heart of the fix: FLAG_COMPRESSED is excluded from the
        # authenticated header, so verification survives the wire encoding
        from eacp.security import AgentVerifier

        verifier = AgentVerifier.from_public_bytes(ident.public_bytes)
        self.assertTrue(verifier.verify_frame(parsed), "signature must survive compression")
        self.assertEqual(parsed.data, frame.data)

    def test_slot_repartition_rejected(self):
        # SEC-02: same concatenated bytes, different verb/args boundary —
        # the 16-byte length block is authenticated (signing contract v2)
        ident = AgentIdentity.generate()
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="read", sender_pin=ident.pin,
            target_pin=7, transaction_id=5,
            data={"a": "admin"},  # json starts with '{"a"' -> repartition target
        )
        ident.sign_frame(frame)
        wire = frame.pack()
        l0, l1, l2, l3 = struct.unpack(">IIII", wire[48:64])
        self.assertGreaterEqual(l1, 5)
        shift = 5
        new_lens = struct.pack(">IIII", l0 + shift, l1 - shift, l2, l3)
        repartitioned = wire[:48] + new_lens + wire[64:]

        from eacp.security import AgentVerifier

        original = EacpFrame.unpack(wire)
        forged = EacpFrame.unpack(repartitioned)
        self.assertNotEqual(original.verb, forged.verb, "repartition must change the parsed verb")
        self.assertEqual(original.raw_payload[16:], forged.raw_payload[16:],
                         "content bytes unchanged — only the boundary moved")
        verifier = AgentVerifier.from_public_bytes(ident.public_bytes)
        self.assertTrue(verifier.verify_frame(original))
        self.assertFalse(verifier.verify_frame(forged),
                         "repartitioned frame must fail: lengths are authenticated")

    def test_compression_bit_tamper_still_caught(self):
        # excluding the encoding bit must not excuse real tampering
        ident = AgentIdentity.generate()
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            verb="x",
            sender_pin=ident.pin,
            target_pin=7,
            transaction_id=1,
            data={"v": 1},
        )
        ident.sign_frame(frame)
        parsed = EacpFrame.unpack(frame.pack())
        parsed.data = {"v": 2}  # payload change after signing
        from eacp.security import AgentVerifier

        verifier = AgentVerifier.from_public_bytes(ident.public_bytes)
        self.assertFalse(verifier.verify_frame(parsed))


# --------------------------------------------------------------------------
# 3b. Decompression is bounded (repro: 16MB wire cap did not bound
#     decompressed memory)

class TestDecompressionBound(unittest.TestCase):
    def test_compression_bomb_refused(self):
        # 24 MB of zeros compresses to a few dozen KB: under the wire cap,
        # over the decompression limit
        raw = struct_lens_with_zeros(24 * 1024 * 1024)
        compressed = zlib.compress(raw, 9)
        self.assertLess(len(compressed), 1_048_576)  # wire fits the 16MB cap
        buffer = HEADER_STRUCT.pack(
            b"\xEA\xCF", EACP_VERSION, int(MsgType.MSG_SEND), 0x0100,
            int(FrameFlags.FLAG_COMPRESSED), 1, 2, 3, 0, 0, len(compressed),
        ) + compressed
        with self.assertRaises(ValueError) as ctx:
            EacpFrame.unpack(buffer, max_payload_size=1_048_576)
        self.assertIn("exceeds limit", str(ctx.exception))

    def test_bomb_allocation_stays_near_limit(self):
        # REL-01: the 7.7 MB peak vs a 64 KiB limit — bounded decompression
        # must reject WITHOUT expanding the remaining stream (flush-before-
        # check would expand everything first)
        import tracemalloc
        import zlib as _zlib

        raw = struct_lens_with_zeros(8 * 1024 * 1024)
        compressed = _zlib.compress(raw, 9)
        buffer = HEADER_STRUCT.pack(
            b"\xEA\xCF", EACP_VERSION, int(MsgType.MSG_SEND), 0x0100,
            int(FrameFlags.FLAG_COMPRESSED), 1, 2, 3, 0, 0, len(compressed),
        ) + compressed
        tracemalloc.start()
        try:
            with self.assertRaises(ValueError):
                EacpFrame.unpack(buffer, max_payload_size=4096)  # 64 KiB decomp limit
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        limit = 64 * 1024
        self.assertLess(
            peak, limit + 1024 * 1024,
            f"peak traced allocation {peak} B vs limit {limit} B — decompression must stop near the limit",
        )

    def test_truncated_and_trailing_streams_rejected(self):
        import zlib as _zlib

        raw = struct_lens_with_zeros(4096)
        compressed = _zlib.compress(raw, 6)
        base = HEADER_STRUCT.pack(
            b"\xEA\xCF", EACP_VERSION, int(MsgType.MSG_SEND), 0x0100,
            int(FrameFlags.FLAG_COMPRESSED), 1, 2, 3, 0, 0, 0,
        )
        # truncated stream (cut mid-stream)
        truncated = base[:44] + (len(compressed) - 10).to_bytes(4, "big") + compressed[:-10]
        with self.assertRaises(ValueError) as ctx:
            EacpFrame.unpack(truncated)
        self.assertIn("Truncated", str(ctx.exception))
        # trailing bytes after a complete stream (concatenated) -> reject
        trailing = base[:44] + (len(compressed) * 2).to_bytes(4, "big") + compressed + compressed
        with self.assertRaises(ValueError) as ctx:
            EacpFrame.unpack(trailing)
        self.assertIn("Trailing", str(ctx.exception))

    def test_legit_tight_wire_config_still_verifies(self):
        # a legitimately compressed frame whose DECOMPRESSED size exceeds a
        # small wire cap must still load (the conformance vector case)
        raw = struct_lens_with_zeros(5000)
        compressed = zlib.compress(raw, 6)
        buffer = HEADER_STRUCT.pack(
            b"\xEA\xCF", EACP_VERSION, int(MsgType.MSG_SEND), 0x0100,
            int(FrameFlags.FLAG_COMPRESSED), 1, 2, 3, 0, 0, len(compressed),
        ) + compressed
        frame = EacpFrame.unpack(buffer, max_payload_size=4096)
        self.assertTrue(frame.flags & FrameFlags.FLAG_COMPRESSED)


def struct_lens_with_zeros(n: int) -> bytes:
    """A slot block of n bytes: 16-byte lens header + zeros (parse-shaped)."""
    import struct as _s

    lens = _s.pack(">IIII", 0, n - 16, 0, 0)
    return lens + b"\x00" * (n - 16)


# --------------------------------------------------------------------------
# 1+2. Registration trust chain (unit: the exact bypasses from the review)

class TestRegistrationTrustChain(unittest.TestCase):
    def setUp(self):
        self.trusted = EnterpriseCA()
        self.relay = EacpRelay(relay_id="r", enterprise_ca=self.trusted)
        self.ident = AgentIdentity.generate()

    def _register_frame(self, sm_dict, signed=True):
        frame = EacpFrame(
            msg_type=MsgType.MSG_RELAY_CONTROL,
            opcode=OpCode.OP_RELAY_REGISTER,
            sender_pin=self.ident.pin,
            target_pin=0,
            transaction_id=1,
            capabilities_mask=int(Capability.NONE),
            data={"signed_manifest": sm_dict, "pub_bytes": self.ident.public_bytes.hex()},
        )
        if signed:
            self.ident.sign_frame(frame)
        return frame

    def test_attacker_ca_with_spoofed_pin_refused(self):
        # repro: manifest signed by an UNRELATED CA, ca_pin field replaced
        # with the trusted pin -> used to pass, must fail against the
        # CONFIGURED CA key
        attacker = EnterpriseCA()
        manifest = SecurityManifest(
            pin=self.ident.pin,
            allowed_capabilities=Capability.CAP_SYS_ADMIN,
            public_bytes=self.ident.public_bytes,
        )
        sm = attacker.sign_manifest(manifest)
        d = sm.to_dict()
        d["ca_pin"] = self.trusted.ca_pin
        d["ca_public_bytes"] = self.trusted.public_bytes.hex()
        _v, _g, err = self.relay._validate_registration(self._register_frame(d))
        self.assertIsNotNone(err)
        self.assertIn("configured Enterprise CA", err)

    def test_manifest_pin_binding(self):
        sm = self.trusted.sign_manifest(
            SecurityManifest(pin=self.ident.pin + 1, public_bytes=self.ident.public_bytes)
        )
        _v, _g, err = self.relay._validate_registration(self._register_frame(sm.to_dict()))
        self.assertIsNotNone(err)
        self.assertIn("pin does not match", err)

    def test_manifest_key_must_derive_pin(self):
        other = AgentIdentity.generate()
        sm = self.trusted.sign_manifest(
            SecurityManifest(pin=self.ident.pin, public_bytes=other.public_bytes)
        )
        _v, _g, err = self.relay._validate_registration(self._register_frame(sm.to_dict()))
        self.assertIsNotNone(err)
        self.assertIn("does not derive", err)

    def test_proof_of_possession_required(self):
        sm = self.trusted.sign_manifest(
            SecurityManifest(
                pin=self.ident.pin,
                allowed_capabilities=Capability.CAP_DISK_READ,
                public_bytes=self.ident.public_bytes,
            )
        )
        # frame NOT signed by the manifest key
        _v, _g, err = self.relay._validate_registration(self._register_frame(sm.to_dict(), signed=False))
        self.assertIsNotNone(err)
        self.assertIn("proof of possession", err)

    def test_valid_manifest_accepted_with_attested_grants(self):
        sm = self.trusted.sign_manifest(
            SecurityManifest(
                pin=self.ident.pin,
                allowed_capabilities=Capability.CAP_DISK_READ,
                public_bytes=self.ident.public_bytes,
            )
        )
        verifier, grants, err = self.relay._validate_registration(self._register_frame(sm.to_dict()))
        self.assertIsNone(err)
        self.assertIsNotNone(verifier)
        self.assertEqual(grants, int(Capability.CAP_DISK_READ))


# --------------------------------------------------------------------------
# 1. Authorization: claims must not exceed the authenticated grants

class TestClaimsBoundedByGrants(HardenedRelayTestBase):
    async def test_claim_beyond_registration_grants_refused_at_relay(self):
        caller = RSessionBase(allowed_capabilities=Capability.NONE)
        target = RSessionBase(allowed_capabilities=Capability.CAP_SYS_ADMIN)
        await caller.connect(host="127.0.0.1", port=self.port)
        await target.connect(host="127.0.0.1", port=self.port)
        try:
            with self.assertRaises(EacpRendezvousException) as ctx:
                await caller.send(
                    target_pin=target.pin,
                    verb="admin_op",
                    data={},
                    capabilities_mask=int(Capability.CAP_SYS_ADMIN),  # the repro's claim
                    constraints=ExecutionConstraints(timeout_ms=1500),
                )
            self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_CAPABILITY_DENIED)
            self.assertIn("registration grants", json.dumps(ctx.exception.frame.data))
        finally:
            await caller.close()
            await target.close()

    def test_gate_three_layers(self):
        gate = PlatSecGate(
            SecurityManifest(pin=1, allowed_capabilities=Capability.CAP_SYS_ADMIN),
            strict_mode=True,
        )
        gate.register_tool("admin", Capability.CAP_SYS_ADMIN)
        claim = int(Capability.CAP_SYS_ADMIN)
        # caller attested only NET_RAW -> denied even though claim+target fit
        ok, code = gate.evaluate(claim, "admin", caller_grants=int(Capability.CAP_NET_RAW))
        self.assertFalse(ok)
        self.assertEqual(code, EacpError.EACP_ERR_CAPABILITY_DENIED)
        # attested SYS_ADMIN -> allowed
        ok, code = gate.evaluate(claim, "admin", caller_grants=claim)
        self.assertTrue(ok)

    def test_caller_manifest_parsing(self):
        ca = EnterpriseCA()
        ident = AgentIdentity.generate()
        client = RSessionBase(identity=ident, enterprise_ca=ca)
        sm = ca.sign_manifest(
            SecurityManifest(pin=ident.pin, allowed_capabilities=Capability.CAP_NET_RAW,
                             public_bytes=ident.public_bytes)
        )
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="t", sender_pin=ident.pin, target_pin=2,
            transaction_id=1, data={"_caller_manifest": sm.to_dict()},
        )
        # SEC-01 PoP: valid manifest but UNSIGNED frame -> no grants
        self.assertEqual(client._caller_grants(frame), 0)
        # frame signed by the manifest key -> grants count
        ident.sign_frame(frame)
        self.assertEqual(client._caller_grants(frame), int(Capability.CAP_NET_RAW))
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="t", sender_pin=ident.pin, target_pin=2,
            transaction_id=2, data={"_caller_manifest": sm.to_dict()},
        )
        ident.sign_frame(frame)
        # wrong CA in the manifest -> 0 (fail closed, not wildcard)
        other = EnterpriseCA()
        sm_bad = other.sign_manifest(
            SecurityManifest(pin=ident.pin, allowed_capabilities=Capability.CAP_NET_RAW,
                             public_bytes=ident.public_bytes)
        )
        frame.data["_caller_manifest"] = sm_bad.to_dict()
        self.assertEqual(client._caller_grants(frame), 0)
        # no manifest at all in CA mode -> 0
        frame.data = {}
        self.assertEqual(client._caller_grants(frame), 0)


# --------------------------------------------------------------------------
# 2b. Signature enforcement + replay at the routing entrance

class TestSignatureAndReplayEnforcement(HardenedRelayTestBase):
    async def _registered_client(self, caps=Capability.CAP_DISK_READ):
        c = RSessionBase(allowed_capabilities=caps)
        await c.connect(host="127.0.0.1", port=self.port)
        return c

    async def test_unsigned_send_from_keyed_sender_refused(self):
        caller = await self._registered_client()
        try:
            tx = 770001
            fut = asyncio.get_running_loop().create_future()
            caller._pending_replies[tx] = fut
            unsigned = EacpFrame(
                msg_type=MsgType.MSG_SEND, verb="probe", sender_pin=caller.pin,
                target_pin=0x9999, transaction_id=tx,
                constraints=ExecutionConstraints(timeout_ms=1500),
            )
            caller.writer.write(unsigned.pack())
            await caller.writer.drain()
            reply = await asyncio.wait_for(fut, timeout=5)
            self.assertEqual(reply.status, EacpError.EACP_ERR_SIGNATURE_INVALID)
        finally:
            await caller.close()

    async def test_replayed_frame_refused(self):
        caller = await self._registered_client()
        target = await self._registered_client(Capability.CAP_TOOL_EXEC)
        try:
            tx = 770002
            fut = asyncio.get_running_loop().create_future()
            caller._pending_replies[tx] = fut
            frame = EacpFrame(
                msg_type=MsgType.MSG_SEND, verb="replay_me", sender_pin=caller.pin,
                target_pin=target.pin, transaction_id=tx,
                constraints=ExecutionConstraints(timeout_ms=1500),
            )
            caller.identity.sign_frame(frame)
            wire = frame.pack()
            caller.writer.write(wire)   # first delivery (accepted)
            await caller.writer.drain()
            caller.writer.write(wire)   # verbatim replay
            await caller.writer.drain()
            reply = await asyncio.wait_for(fut, timeout=5)
            self.assertEqual(reply.status, EacpError.EACP_ERR_REPLAY_DETECTED)
        finally:
            await caller.close()
            await target.close()


# --------------------------------------------------------------------------
# 5. Deadlock graph: concurrent transactions must not overwrite edges

class TestDeadlockPerTransaction(unittest.TestCase):
    def test_concurrent_edges_survive_and_cycles_detected(self):
        g = DeadlockGraph()
        self.assertTrue(g.add_dependency(0xA, 0xB, tx_id=1))
        self.assertTrue(g.add_dependency(0xA, 0xC, tx_id=2))  # would overwrite pre-fix
        # B calls back into A: cycle through the FIRST edge (still present)
        self.assertFalse(g.add_dependency(0xB, 0xA, tx_id=3))
        # reply to tx1 removes only tx1's edge
        g.remove_dependency(0xA, tx_id=1)
        self.assertFalse(g.would_deadlock(0xB, 0xA, tx_id=3))  # A->C only: no cycle
        self.assertTrue(g.add_dependency(0xB, 0xA, tx_id=3))
        # agent gone: all edges of A dropped
        g.remove_agent(0xC)
        self.assertFalse(g.is_blocked(0xA))


# --------------------------------------------------------------------------
# 5b. Budget: exhausted != unlimited; estimate before dispatch

class TestBudgetBoundary(unittest.IsolatedAsyncioTestCase):
    def test_exhausted_envelope_cannot_delegate(self):
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="v", sender_pin=1, target_pin=2,
            transaction_id=1, constraints=ExecutionConstraints(token_budget=10),
        )
        with self.assertRaises(BudgetError) as ctx:
            create_downstream_constraints(frame, parent_usage=10)
        self.assertIn("exhausted", str(ctx.exception))
        with self.assertRaises(BudgetError):
            create_downstream_constraints(frame, parent_usage=15)

    def test_unlimited_stays_unlimited_and_remaining_ok(self):
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="v", sender_pin=1, target_pin=2,
            transaction_id=1, constraints=ExecutionConstraints(token_budget=0),
        )
        child = create_downstream_constraints(frame, parent_usage=999)
        self.assertEqual(child.token_budget, 0)  # unconstrained envelope: by design
        frame.constraints.token_budget = 10
        child = create_downstream_constraints(frame, parent_usage=6)
        self.assertEqual(child.token_budget, 4)

    async def test_request_payload_refused_before_handler(self):
        relay = EacpRelay(relay_id="r-est")
        await relay.start(host="127.0.0.1", port=0)
        port = relay.server.sockets[0].getsockname()[1]
        ran = []
        server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        server.register_handler("heavy", lambda f: ran.append(1) or {"ok": True})
        caller = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        await server.connect(host="127.0.0.1", port=port)
        await caller.connect(host="127.0.0.1", port=port)
        try:
            with self.assertRaises(EacpRendezvousException) as ctx:
                await caller.send(
                    target_pin=server.pin,
                    verb="heavy",
                    data={"blob": "x" * 400},  # estimate ~100 tokens > budget
                    constraints=ExecutionConstraints(token_budget=10, timeout_ms=2000),
                )
            self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_TOKEN_OVERFLOW)
            self.assertIn("before handler execution", json.dumps(ctx.exception.frame.data))
            await asyncio.sleep(0.2)
            self.assertEqual(ran, [], "handler must never execute when the request alone exceeds the envelope")
        finally:
            await caller.close()
            await server.close()
            await relay.stop()


# --------------------------------------------------------------------------
# 6a. Offline queues: global budget, explicit overflow, periodic expiry

class TestOfflineQueueAccounting(HardenedRelayTestBase):
    async def _raw_registered(self, caps=Capability.CAP_DISK_READ):
        c = RSessionBase(allowed_capabilities=caps)
        await c.connect(host="127.0.0.1", port=self.port)
        return c

    async def test_overflow_is_explicit_not_silent(self):
        # tiny GLOBAL queue budget so the third frame must be refused
        relay = EacpRelay(relay_id="r-ovf", max_queue_total=2)
        await relay.start(host="127.0.0.1", port=0)
        port = relay.server.sockets[0].getsockname()[1]
        caller = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
        await caller.connect(host="127.0.0.1", port=port)
        try:
            tx3 = 880003
            fut = asyncio.get_running_loop().create_future()
            caller._pending_replies[tx3] = fut
            offline_pin = caller.pin + 0xDEAD
            for tx in (880001, 880002, tx3):
                frame = EacpFrame(
                    msg_type=MsgType.MSG_SEND, verb="offline", sender_pin=caller.pin,
                    target_pin=offline_pin, transaction_id=tx,
                    constraints=ExecutionConstraints(timeout_ms=10_000),
                )
                caller.identity.sign_frame(frame)
                caller.writer.write(frame.pack())
                await caller.writer.drain()
            reply = await asyncio.wait_for(fut, timeout=5)
            self.assertEqual(reply.status, EacpError.EACP_ERR_QUEUE_FULL)
            # global budget = 2 entries; the refused tx must not remain in
            # the deadlock graph (its dependency was released on refusal)
            self.assertEqual(relay._queued_total, 2)
            edges = relay.deadlock_graph._edges.get(caller.pin, {})
            self.assertNotIn(tx3, edges)
            self.assertEqual(len(edges), 2)
        finally:
            await caller.close()
            await relay.stop()

    async def test_expiry_answers_sender_and_frees_budget(self):
        relay = EacpRelay(relay_id="r-exp")
        await relay.start(host="127.0.0.1", port=0)
        port = relay.server.sockets[0].getsockname()[1]
        caller = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
        await caller.connect(host="127.0.0.1", port=port)
        try:
            tx = 890001
            fut = asyncio.get_running_loop().create_future()
            caller._pending_replies[tx] = fut
            frame = EacpFrame(
                msg_type=MsgType.MSG_SEND, verb="expiring", sender_pin=caller.pin,
                target_pin=caller.pin + 0xBEEF, transaction_id=tx,
                constraints=ExecutionConstraints(timeout_ms=30),
            )
            caller.identity.sign_frame(frame)
            caller.writer.write(frame.pack())
            await caller.writer.drain()
            await asyncio.sleep(0.1)  # let it buffer
            expired = await relay.expire_queued()
            self.assertEqual(len(expired), 1)
            reply = await asyncio.wait_for(fut, timeout=5)
            self.assertEqual(reply.status, EacpError.EACP_ERR_TIMEOUT)
            self.assertEqual(relay._queued_total, 0)
        finally:
            await caller.close()
            await relay.stop()


# --------------------------------------------------------------------------
# 4. Cancellation: timeout actually stops the handler

class TestCancellationStopsHandlers(HardenedRelayTestBase):
    async def test_pulse_cancel_stops_inflight_handler(self):
        finished = []
        server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)

        async def slow(frame):
            await asyncio.sleep(1.0)
            finished.append(frame.transaction_id)
            return {"done": True}

        server.register_handler("slow", slow)
        caller = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        await server.connect(host="127.0.0.1", port=self.port)
        await caller.connect(host="127.0.0.1", port=self.port)
        try:
            with self.assertRaises(EacpRendezvousException) as ctx:
                await caller.send(
                    target_pin=server.pin, verb="slow", data={},
                    constraints=ExecutionConstraints(timeout_ms=300),
                )
            self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_TIMEOUT)
            # PULSE_CANCEL was emitted by the timeout path; give it time to
            # land and the handler time it would need IF it were not cancelled
            await asyncio.sleep(1.3)
            self.assertEqual(finished, [], "handler must not continue after caller timeout")
            self.assertEqual(server._inflight, {}, "registry must be empty after cancellation")
            self.assertEqual(server.ledger.reserved, 0, "escrow must be refunded on cancel")
        finally:
            await caller.close()
            await server.close()

    async def test_bounded_concurrency(self):
        server = RSessionBase(
            allowed_capabilities=Capability.CAP_TOOL_EXEC, max_concurrent_handlers=1
        )
        state = {"cur": 0, "peak": 0}

        async def tracked(frame):
            state["cur"] += 1
            state["peak"] = max(state["peak"], state["cur"])
            await asyncio.sleep(0.15)
            state["cur"] -= 1
            return {"ok": True}

        server.register_handler("tracked", tracked)
        a = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        b = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        await server.connect(host="127.0.0.1", port=self.port)
        await a.connect(host="127.0.0.1", port=self.port)
        await b.connect(host="127.0.0.1", port=self.port)
        try:
            await asyncio.gather(
                a.send(target_pin=server.pin, verb="tracked",
                       constraints=ExecutionConstraints(timeout_ms=4000)),
                b.send(target_pin=server.pin, verb="tracked",
                       constraints=ExecutionConstraints(timeout_ms=4000)),
            )
            self.assertEqual(state["peak"], 1, "semaphore must serialize handlers")
        finally:
            await a.close()
            await b.close()
            await server.close()


# --------------------------------------------------------------------------
# 6b. Mesh: a REAL cross-relay request/reply + origin binding

class TestMeshEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def test_two_relay_request_reply(self):
        r1 = EacpRelay(relay_id="relay-1")
        r2 = EacpRelay(relay_id="relay-2")
        await r1.start(host="127.0.0.1", port=0)
        await r2.start(host="127.0.0.1", port=0)
        p1 = r1.server.sockets[0].getsockname()[1]
        p2 = r2.server.sockets[0].getsockname()[1]
        peer12 = RelayPeer("relay-2", "127.0.0.1", p2, psk=b"mesh-test-psk")
        peer21 = RelayPeer("relay-1", "127.0.0.1", p1, psk=b"mesh-test-psk")
        r1.mesh.add_peer(peer12)
        r2.mesh.add_peer(peer21)
        await peer12.connect()
        await peer21.connect()
        try:
            server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
            server.register_handler(
                "echo", lambda f: {"pong": {"hop": f.data.get("hop") if isinstance(f.data, dict) else None}}
            )
            await server.connect(host="127.0.0.1", port=p2)
            caller = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
            await caller.connect(host="127.0.0.1", port=p1)
            # announce propagation both ways
            self.assertTrue(await _wait(lambda: r1.mesh.get_peer_for_pin(server.pin) is peer12),
                            "relay-1 must learn the remote agent via announce")
            self.assertTrue(await _wait(lambda: r2.mesh.get_peer_for_pin(caller.pin) is peer21),
                            "relay-2 must learn the caller via announce")
            reply = await caller.send(
                target_pin=server.pin, verb="echo", data={"hop": 1},
                constraints=ExecutionConstraints(timeout_ms=4000),
            )
            self.assertEqual(reply.data, {"pong": {"hop": 1}})
        finally:
            await caller.close()
            await server.close()
            await r1.stop()
            await r2.stop()

    async def test_announce_origin_binding(self):
        r1 = EacpRelay(relay_id="relay-1")
        await r1.start(host="127.0.0.1", port=0)
        p1 = r1.server.sockets[0].getsockname()[1]
        r1.mesh.add_peer(RelayPeer("legit-peer", "127.0.0.1", 9))  # configured...
        c = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
        await c.connect(host="127.0.0.1", port=p1)
        try:
            forged = EacpFrame(
                msg_type=MsgType.MSG_RELAY_CONTROL,
                opcode=OpCode.OP_RELAY_ROUTE_ANNOUNCE,
                sender_pin=0, target_pin=0,
                verb="route_announce",
                data={"pin": 0xF00D, "action": "add", "origin_peer": "evil"},
            )
            c.writer.write(forged.pack())
            await c.writer.drain()
            await asyncio.sleep(0.2)
            self.assertIsNone(
                r1.mesh.get_peer_for_pin(0xF00D),
                "an announce from an unconfigured origin must be ignored",
            )
            # local routes must not be clobberable either
            r1.mesh.register_local(0xC0FFEE)
            r1.mesh.register_remote(0xC0FFEE, "legit-peer")
            self.assertTrue(r1.mesh.is_local(0xC0FFEE))
        finally:
            await c.close()
            await r1.stop()


# --------------------------------------------------------------------------
# 6c. Ledger: recovery + verification across restart

class TestLedgerRecovery(unittest.TestCase):
    def test_recover_verify_and_continue(self):
        import tempfile, os

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.log")
            led = AuditLedger(file_path=path, fsync_every=1)
            for i in range(3):
                led.record(tx_id=i, sender_pin=1, target_pin=2, verb="v",
                           capabilities_mask=0, status=0, data_payload=b"x")
            led.close()
            again = AuditLedger(file_path=path, fsync_every=1)
            self.assertEqual(len(again.entries), 3, "history must be recovered, not restarted")
            self.assertTrue(again.verify_chain())
            more = again.record(tx_id=9, sender_pin=1, target_pin=2, verb="v",
                                capabilities_mask=0, status=0)
            self.assertEqual(more.prev_hash, again.entries[2].entry_hash, "chain continues")
            again.close()

    def test_rotation_preserves_absolute_indices(self):
        # REL-02: segment ending at N -> restart -> append must NOT restart
        # the index at len(recovered); chain verification accepts rotated
        # segments and multiple restarts stay monotonic
        import tempfile, os

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.log")
            led = AuditLedger(file_path=path, fsync_every=1, rotate_bytes=750)
            first = [
                led.record(tx_id=i, sender_pin=1, target_pin=2, verb="v",
                           capabilities_mask=0, status=0).index
                for i in range(5)
            ]
            led.close()
            self.assertEqual(first, [0, 1, 2, 3, 4])
            self.assertTrue(os.path.exists(path + ".1"), "rotation must have rolled a segment")

            again = AuditLedger(file_path=path, fsync_every=1, rotate_bytes=750)
            self.assertEqual(again.entries[0].index, 3, "base segment starts mid-chain")
            nxt = again.record(tx_id=99, sender_pin=1, target_pin=2, verb="v",
                               capabilities_mask=0, status=0).index
            self.assertEqual(nxt, 5, "append continues the absolute sequence, not len(entries)")
            self.assertTrue(again.verify_chain())
            again.close()

            third = AuditLedger(file_path=path, fsync_every=1, rotate_bytes=750)
            self.assertTrue(third.verify_chain())
            indices = [e.index for e in third.entries]
            self.assertEqual(indices, list(range(indices[0], 6)),
                             f"monotonic absolute indices expected, got {indices}")
            third.close()

    def test_tampered_file_refuses_to_load(self):
        import tempfile, os

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.log")
            led = AuditLedger(file_path=path, fsync_every=1)
            for i in range(3):
                led.record(tx_id=i, sender_pin=1, target_pin=2, verb="v",
                           capabilities_mask=0, status=0)
            led.close()
            lines = open(path).read().splitlines()
            doctored = json.loads(lines[1])
            doctored["status"] = 666  # alter a historical record
            lines[1] = json.dumps(doctored)
            open(path, "w").write("\n".join(lines) + "\n")
            with self.assertRaises(LedgerIntegrityError):
                AuditLedger(file_path=path)


# --------------------------------------------------------------------------
# 6d. Tracing propagates on the wire; TLS defaults verify

class TestTraceAndTls(unittest.TestCase):
    def test_trace_header_travels_with_send(self):
        async def scenario():
            relay = EacpRelay(relay_id="r-tr")
            await relay.start(host="127.0.0.1", port=0)
            port = relay.server.sockets[0].getsockname()[1]
            seen = {}
            server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
            server.register_handler("traced", lambda f: seen.update(data=f.data) or {"ok": 1})
            caller = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
            await server.connect(host="127.0.0.1", port=port)
            await caller.connect(host="127.0.0.1", port=port)
            try:
                await caller.send(target_pin=server.pin, verb="traced", data={"q": 1},
                                  constraints=ExecutionConstraints(timeout_ms=3000))
            finally:
                await caller.close()
                await server.close()
                await relay.stop()
            return seen

        seen = asyncio.run(scenario())
        self.assertIn("_trace", seen["data"], "send() must put the trace context on the wire")
        tc = TraceContext.parse(seen["data"]["_trace"])
        self.assertIsNotNone(tc)
        self.assertEqual(len(tc.trace_id), 32)

    def test_client_tls_verifies_by_default(self):
        ctx = create_client_ssl_context()
        import ssl as _ssl

        self.assertEqual(ctx.verify_mode, _ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        insecure = create_client_ssl_context(verify_server=False)
        self.assertEqual(insecure.verify_mode, _ssl.CERT_NONE)  # explicit opt-out only


if __name__ == "__main__":
    unittest.main()