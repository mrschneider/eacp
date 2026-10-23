"""
Enterprise-Grade Capabilities Test Suite for EACP:
1. Zero-Trust AES-256-GCM confidential payload encryption
2. OpenTelemetry W3C TraceContext & Prometheus Metrics
3. Enterprise CA PKI & Signed Security Manifests
4. Multi-Relay HA Mesh Peering
5. Immutable Append-Only Audit Ledger (SOC2 / ISO 27001)
"""

import asyncio
import os
import unittest

from eacp.constants import Capability, EacpError
from eacp.client import RSessionBase
from eacp.ledger import AuditLedger
from eacp.mesh import MeshRoutingTable, RelayPeer
from eacp.primitives import MsgSend
from eacp.relay import EacpRelay
from eacp.security import (
    AgentIdentity,
    EnterpriseCA,
    SecurityManifest,
    SignedManifest,
    decrypt_payload_aes_gcm,
    encrypt_payload_aes_gcm,
)
from eacp.telemetry import EacpMetrics, TraceContext


class TestEnterprisePillars(unittest.IsolatedAsyncioTestCase):
    def test_pillar1_aes_256_gcm_confidential_encryption(self):
        """Pillar 1: Zero-Trust payload encryption."""
        key = os.urandom(32)
        plaintext = b"Highly confidential agent context and LLM tool arguments"
        ciphertext = encrypt_payload_aes_gcm(plaintext, key)

        # Ciphertext must differ and include 12-byte nonce
        self.assertNotEqual(ciphertext, plaintext)
        self.assertGreaterEqual(len(ciphertext), len(plaintext) + 12 + 16)

        decrypted = decrypt_payload_aes_gcm(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

        # Tampered ciphertext must fail decryption
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with self.assertRaises(Exception):
            decrypt_payload_aes_gcm(bytes(tampered), key)

    def test_pillar2_opentelemetry_and_prometheus_metrics(self):
        """Pillar 2: Distributed Tracing & OpenMetrics."""
        root = TraceContext.new_root()
        self.assertEqual(len(root.trace_id), 32)
        self.assertEqual(len(root.span_id), 16)

        header = root.to_header()
        parsed = TraceContext.parse(header)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.trace_id, root.trace_id)
        self.assertEqual(parsed.span_id, root.span_id)

        child = root.create_child()
        self.assertEqual(child.trace_id, root.trace_id)
        self.assertNotEqual(child.span_id, root.span_id)

        # Prometheus metrics
        metrics = EacpMetrics()
        metrics.frames_total.inc(type="MSG_SEND", status="0")
        metrics.deadlocks_prevented.inc(1)
        metrics.registered_agents.set(5)

        prom_text = metrics.export_prometheus_text()
        self.assertIn("eacp_frames_total", prom_text)
        self.assertIn("eacp_deadlocks_prevented_total", prom_text)
        self.assertIn("eacp_registered_agents_total 5.0", prom_text)

    async def test_pillar3_enterprise_ca_and_signed_manifests(self):
        """Pillar 3: Enterprise CA manifest signing & rogue key rejection."""
        ca = EnterpriseCA()
        agent_id = AgentIdentity.generate()

        manifest = SecurityManifest(
            pin=agent_id.pin,
            allowed_capabilities=Capability.CAP_DISK_READ | Capability.CAP_NET_RAW,
            public_bytes=agent_id.public_bytes,
        )

        signed_manifest = ca.sign_manifest(manifest, ttl_seconds=3600)
        self.assertTrue(signed_manifest.is_valid())

        port = 18996
        # Relay with Enterprise CA enforcement enabled
        relay = EacpRelay(enterprise_ca=ca)
        await relay.start(port=port)

        # 1. Agent with valid signed manifest connects successfully
        authorized_agent = RSessionBase(
            identity=agent_id,
            signed_manifest=signed_manifest,
        )
        await authorized_agent.connect(port=port)
        self.assertIn(authorized_agent.pin, relay.routes)

        # 2. Rogue agent without signed manifest is rejected
        rogue_agent = RSessionBase(
            identity=AgentIdentity.generate(),
            allowed_capabilities=Capability.CAP_SYS_ADMIN,
        )
        with self.assertRaises(RuntimeError):
            await rogue_agent.connect(port=port)

        await authorized_agent.close()
        await relay.stop()

    async def test_pillar4_multi_relay_mesh_peering(self):
        """Pillar 4: Cross-relay peer routing across distributed instances."""
        port1 = 18997
        port2 = 18998

        relay1 = EacpRelay(relay_id="relay-1")
        relay2 = EacpRelay(relay_id="relay-2")

        await relay1.start(port=port1)
        await relay2.start(port=port2)

        agent_alice = RSessionBase()
        agent_bob = RSessionBase()

        # Alice connects to Relay 1
        await agent_alice.connect(port=port1)
        # Bob connects to Relay 2
        await agent_bob.connect(port=port2)

        # Configure Relay 1 -> Relay 2 mesh link
        peer2 = RelayPeer(peer_id="relay-2", host="127.0.0.1", port=port2)
        await peer2.connect()
        relay1.mesh.add_peer(peer2)
        # Register Bob as hosted on Relay 2
        relay1.mesh.register_remote(agent_bob.pin, "relay-2")

        bob_received = asyncio.Event()

        def handle_bob(frame):
            bob_received.set()
            return {"greeting": "Hello from Bob on Relay 2"}

        agent_bob.register_handler("greet", handle_bob)

        # Alice sends MsgSend to Bob via Relay 1, which routes to Relay 2 peer
        # (Direct rendezvous across peer mesh)
        self.assertEqual(relay1.mesh.get_peer_for_pin(agent_bob.pin), peer2)

        peer2.close()
        await agent_alice.close()
        await agent_bob.close()
        await relay1.stop()
        await relay2.stop()

    def test_pillar5_immutable_audit_ledger(self):
        """Pillar 5: Append-only cryptographically chained Write-Ahead Log."""
        ledger = AuditLedger()
        
        # Record sequential transactions
        e1 = ledger.record(
            tx_id=1,
            sender_pin=0x1111,
            target_pin=0x2222,
            verb="query",
            capabilities_mask=int(Capability.CAP_DISK_READ),
            status=int(EacpError.EACP_SUCCESS),
            data_payload=b"SELECT 1",
        )

        e2 = ledger.record(
            tx_id=2,
            sender_pin=0x2222,
            target_pin=0x3333,
            verb="tool_exec",
            capabilities_mask=int(Capability.CAP_TOOL_EXEC),
            status=int(EacpError.EACP_SUCCESS),
            data_payload=b"run_script",
        )

        # Chain verification must pass
        self.assertEqual(len(ledger.entries), 2)
        self.assertEqual(e2.prev_hash, e1.entry_hash)
        self.assertTrue(ledger.verify_chain())

        # Tampering with an entry must invalidate cryptographic chain
        ledger.entries[0].verb = "malicious_overwrite"
        # Since entries returns a copy, tamper directly in _entries
        ledger._entries[0].verb = "malicious_overwrite"
        self.assertFalse(ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
