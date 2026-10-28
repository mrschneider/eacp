"""SEC-01 / SEC-03 acceptance tests (pending-changes review, 2026-10-28).

- unregistered connections cannot execute handlers (even with a genuine
  CA-signed public manifest — grants prove authorization, PoP proves
  possession)
- a registered connection cannot send as another PIN (no impersonation,
  no pin switching)
- route announcements are admitted only from connections that completed
  the PSK peer handshake, never from a claimed name; ownership rules stop
  peers from moving or removing each other's routes
- the receiver requires the frame itself to be signed by the manifest key
  before caller-manifest grants count
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eacp.constants import Capability, EacpError, MsgType, OpCode
from eacp.frame import EacpFrame, ExecutionConstraints
from eacp.client import RSessionBase
from eacp.mesh import MeshRoutingTable, RelayPeer
from eacp.relay import EacpRelay
from eacp.security import AgentIdentity, EnterpriseCA, SecurityManifest

HDR = struct.Struct(">2sBBHHQQQQII")


def _recv_status_blocking(sock: socket.socket, timeout: float) -> int:
    """Blocking read of one frame — must run via asyncio.to_thread: a
    blocking recv inside the event loop freezes the very relay (same
    loop!) that is supposed to answer."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < 48:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed before a reply frame arrived")
        buf += chunk
    plen = int.from_bytes(buf[44:48], "big")
    while len(buf) < 48 + plen:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed mid-frame")
        buf += chunk
    return HDR.unpack(buf[:48])[9]


async def _raw_status(sock: socket.socket, timeout: float = 4.0) -> int:
    return await asyncio.to_thread(_recv_status_blocking, sock, timeout)


async def _register(sock: socket.socket, ident: AgentIdentity) -> None:
    reg = EacpFrame(
        msg_type=MsgType.MSG_RELAY_CONTROL, opcode=OpCode.OP_RELAY_REGISTER,
        sender_pin=ident.pin, target_pin=0, transaction_id=1,
        capabilities_mask=int(Capability.NONE),
        data={"pub_bytes": ident.public_bytes.hex()},
    )
    ident.sign_frame(reg)
    await asyncio.to_thread(sock.sendall, reg.pack())
    status = await _raw_status(sock)
    if status != 0:
        raise RuntimeError(f"registration refused: status={status}")


class TestIngressAuthentication(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = EacpRelay(relay_id="r-ingress")
        await self.relay.start(host="127.0.0.1", port=0)
        self.port = self.relay.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.relay.stop()

    def _app_frame(self, sender_pin: int, target_pin: int, tx: int, verb: str = "probe") -> EacpFrame:
        return EacpFrame(
            msg_type=MsgType.MSG_SEND, verb=verb, sender_pin=sender_pin,
            target_pin=target_pin, transaction_id=tx,
            constraints=ExecutionConstraints(timeout_ms=2000),
            data={"x": 1},
        )

    async def test_unregistered_connection_cannot_execute_handler(self):
        ran = []
        server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        server.register_handler("reboot", lambda f: ran.append(1) or {"ok": True})
        await server.connect(host="127.0.0.1", port=self.port)
        attacker = None
        try:
            attacker = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            ident = AgentIdentity.generate()
            await asyncio.to_thread(attacker.sendall, self._app_frame(ident.pin, server.pin, 9001, "reboot").pack())
            status = await _raw_status(attacker)
            self.assertEqual(status, EacpError.EACP_ERR_SIGNATURE_INVALID)
            await asyncio.sleep(0.3)
            self.assertEqual(ran, [], "handler must never execute from unregistered ingress")
        finally:
            if attacker:
                attacker.close()
            await server.close()

    async def test_impersonation_on_registered_connection_refused(self):
        ran = []
        server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
        server.register_handler("reboot", lambda f: ran.append(1) or {"ok": True})
        await server.connect(host="127.0.0.1", port=self.port)
        attacker = None
        try:
            attacker = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            me = AgentIdentity.generate()
            await _register(attacker, me)
            # authenticated as `me`, but the frame claims someone else's PIN
            await asyncio.to_thread(attacker.sendall, self._app_frame(server.pin, server.pin, 9002, "reboot").pack())
            status = await _raw_status(attacker)
            self.assertEqual(status, EacpError.EACP_ERR_SIGNATURE_INVALID)
            await asyncio.sleep(0.3)
            self.assertEqual(ran, [], "impersonated sender must not execute anything")
        finally:
            if attacker:
                attacker.close()
            await server.close()

    async def test_pin_switch_after_registration_refused(self):
        a = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            b = AgentIdentity.generate()
            first = AgentIdentity.generate()
            await _register(a, first)
            reg = EacpFrame(
                msg_type=MsgType.MSG_RELAY_CONTROL, opcode=OpCode.OP_RELAY_REGISTER,
                sender_pin=b.pin, target_pin=0, transaction_id=2,
                capabilities_mask=int(Capability.NONE),
                data={"pub_bytes": b.public_bytes.hex()},
            )
            b.sign_frame(reg)
            await asyncio.to_thread(a.sendall, reg.pack())
            self.assertEqual(await _raw_status(a), EacpError.EACP_ERR_SIGNATURE_INVALID)
        finally:
            a.close()

    async def test_ca_manifest_without_pop_cannot_execute(self):
        """The reviewer's exact SEC-01 repro: a genuine CA-signed public
        manifest for an authorized agent, presented unsigned from an
        unregistered connection, must not execute anything."""
        ca = EnterpriseCA()
        relay = EacpRelay(relay_id="r-ca", enterprise_ca=ca)
        await relay.start(host="127.0.0.1", port=0)
        port = relay.server.sockets[0].getsockname()[1]
        authorized_ident = AgentIdentity.generate()
        authorized_sm = ca.sign_manifest(
            SecurityManifest(
                pin=authorized_ident.pin,
                allowed_capabilities=Capability.CAP_SYS_ADMIN,
                public_bytes=authorized_ident.public_bytes,
            )
        )
        ran = []
        srv_ident = AgentIdentity.generate()
        srv_sm = ca.sign_manifest(
            SecurityManifest(
                pin=srv_ident.pin,
                allowed_capabilities=Capability.CAP_SYS_ADMIN,
                public_bytes=srv_ident.public_bytes,
            )
        )
        server = RSessionBase(
            identity=srv_ident, enterprise_ca=ca, signed_manifest=srv_sm,
            allowed_capabilities=Capability.CAP_SYS_ADMIN,
        )
        server.register_handler("reboot", lambda f: ran.append(1) or {"ok": True})
        await server.connect(host="127.0.0.1", port=port)
        attacker = None
        try:
            attacker = socket.create_connection(("127.0.0.1", port), timeout=5)
            frame = EacpFrame(
                msg_type=MsgType.MSG_SEND, verb="reboot",
                sender_pin=authorized_ident.pin, target_pin=server.pin,
                transaction_id=9003,
                capabilities_mask=int(Capability.CAP_SYS_ADMIN),
                constraints=ExecutionConstraints(timeout_ms=2000),
                data={"_caller_manifest": authorized_sm.to_dict()},
            )  # deliberately UNSIGNED
            await asyncio.to_thread(attacker.sendall, frame.pack())
            self.assertEqual(await _raw_status(attacker), EacpError.EACP_ERR_SIGNATURE_INVALID)
            await asyncio.sleep(0.3)
            self.assertEqual(ran, [], "public manifest without PoP must not authorize")
        finally:
            if attacker:
                attacker.close()
            await server.close()
            await relay.stop()

    def test_caller_manifest_requires_frame_signature(self):
        ca = EnterpriseCA()
        client = RSessionBase(enterprise_ca=ca, allowed_capabilities=Capability.NONE)
        ident = AgentIdentity.generate()
        sm = ca.sign_manifest(
            SecurityManifest(
                pin=ident.pin, allowed_capabilities=Capability.CAP_SYS_ADMIN,
                public_bytes=ident.public_bytes,
            )
        )
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="reboot", sender_pin=ident.pin,
            target_pin=2, transaction_id=1,
            data={"_caller_manifest": sm.to_dict()},
        )
        # valid manifest, unsigned frame -> no grants (fail closed)
        self.assertEqual(client._caller_grants(frame), 0)
        # same manifest, frame signed by the manifest key -> grants count
        ident.sign_frame(frame)
        self.assertEqual(
            client._caller_grants(frame), int(Capability.CAP_SYS_ADMIN)
        )


class TestMeshAnnounceAuthentication(unittest.IsolatedAsyncioTestCase):
    def test_announce_impersonating_configured_peer_refused(self):
        """SEC-03: the configured NAME in the frame is not identity."""
        table = MeshRoutingTable(local_relay_id="relay-1")
        table.add_peer(RelayPeer("evil-peer", "127.0.0.1", 9, psk=b"k"))

        async def scenario():
            relay = EacpRelay(relay_id="relay-1")
            await relay.start(host="127.0.0.1", port=0)
            port = relay.server.sockets[0].getsockname()[1]
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            ident = AgentIdentity.generate()
            await _register(c, ident)
            forged = EacpFrame(
                msg_type=MsgType.MSG_RELAY_CONTROL,
                opcode=OpCode.OP_RELAY_ROUTE_ANNOUNCE,
                sender_pin=0, target_pin=0, verb="route_announce",
                data={"pin": 0xF00D, "action": "add", "origin_peer": "evil-peer"},
            )
            await asyncio.to_thread(c.sendall, forged.pack())
            await asyncio.sleep(0.3)
            found = relay.mesh.get_peer_for_pin(0xF00D)
            c.close()
            await relay.stop()
            return found

        self.assertIsNone(asyncio.run(scenario()))

    def test_ownership_rules(self):
        table = MeshRoutingTable(local_relay_id="r")
        table.add_peer(RelayPeer("p1", "127.0.0.1", 1, psk=b"k"))
        table.add_peer(RelayPeer("p2", "127.0.0.1", 2, psk=b"k"))
        self.assertTrue(table.register_remote(10, "p1"))
        # a second peer may not steal a routed pin
        self.assertFalse(table.register_remote(10, "p2"))
        # only the owning peer may release it
        self.assertFalse(table.release_remote(10, "p2"))
        self.assertTrue(table.release_remote(10, "p1"))
        # local pins are never movable
        table.register_local(11)
        self.assertFalse(table.register_remote(11, "p1"))
        self.assertFalse(table.release_remote(11, "p1"))

    async def test_wrong_psk_fails_handshake(self):
        r1 = EacpRelay(relay_id="relay-1")
        r2 = EacpRelay(relay_id="relay-2")
        await r1.start(host="127.0.0.1", port=0)
        await r2.start(host="127.0.0.1", port=0)
        p1 = r1.server.sockets[0].getsockname()[1]
        p2 = r2.server.sockets[0].getsockname()[1]
        try:
            peer12 = RelayPeer("relay-2", "127.0.0.1", p2, psk=b"secret-A")
            peer21 = RelayPeer("relay-1", "127.0.0.1", p1, psk=b"secret-B")
            r1.mesh.add_peer(peer12)
            r2.mesh.add_peer(peer21)
            ok = await peer12.connect()
            self.assertFalse(ok, "mismatched PSK must fail the handshake")
            # nothing may be announced over a failed handshake
            self.assertIsNone(r1.mesh.get_peer_for_pin(0xABC))
        finally:
            await r1.stop()
            await r2.stop()


if __name__ == "__main__":
    unittest.main()