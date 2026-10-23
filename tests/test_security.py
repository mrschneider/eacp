"""
Unit tests for EACP Security Subsystem: PlatSec capability enforcement and Ed25519 Agent-PIN.
"""

import unittest

from eacp.constants import Capability, EacpError, FrameFlags, MsgType, OpCode
from eacp.frame import EacpFrame, ExecutionConstraints
from eacp.security import (
    AgentIdentity,
    AgentVerifier,
    PlatSecException,
    PlatSecGate,
    SecurityManifest,
    compute_pin,
    format_pin,
)


class TestEacpSecurity(unittest.TestCase):
    def test_agent_pin_derivation(self):
        agent = AgentIdentity.generate()
        self.assertIsInstance(agent.pin, int)
        self.assertGreater(agent.pin, 0)

        # PIN must be 64-bit uint
        self.assertLessEqual(agent.pin, 0xFFFFFFFFFFFFFFFF)

        # Deterministic check from public bytes
        derived_pin = compute_pin(agent.public_bytes)
        self.assertEqual(agent.pin, derived_pin)

        # Check hex format
        hex_pin = agent.pin_hex
        self.assertTrue(hex_pin.startswith("0x"))
        self.assertEqual(len(hex_pin), 18 + 3)  # 0x + 16 hex chars + 3 underscores

    def test_frame_signing_and_verification(self):
        alice = AgentIdentity.generate()
        verifier = AgentVerifier.from_public_bytes(alice.public_bytes)
        self.assertEqual(alice.pin, verifier.pin)

        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_ACTION_INVOKE,
            sender_pin=alice.pin,
            target_pin=0x1234,
            transaction_id=1,
            capabilities_mask=int(Capability.CAP_DISK_READ),
            verb="read_file",
            data={"path": "/etc/hosts"},
        )

        alice.sign_frame(frame)
        self.assertTrue(frame.flags & FrameFlags.FLAG_SIGNED)
        self.assertEqual(len(frame.envelope.signature), 64)

        # Verification must succeed
        self.assertTrue(verifier.verify_frame(frame))

        # Tampering with data must invalidate signature
        tampered_packed = frame.pack()
        unpacked = EacpFrame.unpack(tampered_packed)
        unpacked.data = {"path": "/etc/shadow"}  # Tamper
        self.assertFalse(verifier.verify_frame(unpacked))

    def test_platsec_capability_gate_pass(self):
        manifest = SecurityManifest(
            pin=0x1234,
            allowed_capabilities=Capability.CAP_DISK_READ | Capability.CAP_TOOL_EXEC,
        )
        gate = PlatSecGate(manifest)
        gate.register_tool("cat_file", Capability.CAP_DISK_READ)
        gate.register_tool("run_test", Capability.CAP_TOOL_EXEC)

        # Allowed: sender claims DISK_READ and manifest permits DISK_READ
        frame = EacpFrame(
            sender_pin=0x1234,
            capabilities_mask=int(Capability.CAP_DISK_READ),
            verb="cat_file",
        )
        allowed, err = gate.evaluate(frame.capabilities_mask, "cat_file")
        self.assertTrue(allowed)
        self.assertEqual(err, EacpError.EACP_SUCCESS)

        # Must not raise
        gate.check_or_raise(frame, "cat_file")

    def test_platsec_capability_gate_denied(self):
        # Manifest only allows DISK_READ
        manifest = SecurityManifest(
            pin=0x1234,
            allowed_capabilities=Capability.CAP_DISK_READ,
        )
        gate = PlatSecGate(manifest)
        gate.register_tool("format_disk", Capability.CAP_SYS_ADMIN | Capability.CAP_DISK_WRITE)

        # Frame requests format_disk but lacks permissions
        frame = EacpFrame(
            sender_pin=0x1234,
            capabilities_mask=int(Capability.CAP_DISK_READ),
            verb="format_disk",
        )
        allowed, err = gate.evaluate(frame.capabilities_mask, "format_disk")
        self.assertFalse(allowed)
        self.assertEqual(err, EacpError.EACP_ERR_CAPABILITY_DENIED)

        with self.assertRaises(PlatSecException) as ctx:
            gate.check_or_raise(frame, "format_disk")
        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_CAPABILITY_DENIED)

    def test_platsec_ambient_authority_prevention(self):
        """
        If a rogue frame claims CAP_SYS_ADMIN, but the manifest only allows CAP_DISK_READ,
        the granted capabilities must be Frame.Caps & Manifest.Caps, preventing escalation.
        """
        manifest = SecurityManifest(
            pin=0x1234,
            allowed_capabilities=Capability.CAP_DISK_READ,  # Only read allowed
        )
        gate = PlatSecGate(manifest)
        gate.register_tool("admin_action", Capability.CAP_SYS_ADMIN)

        # Malicious frame trying to claim CAP_SYS_ADMIN
        frame = EacpFrame(
            sender_pin=0x1234,
            capabilities_mask=int(Capability.CAP_SYS_ADMIN | Capability.CAP_DISK_READ),
            verb="admin_action",
        )
        allowed, err = gate.evaluate(frame.capabilities_mask, "admin_action")
        self.assertFalse(allowed)
        self.assertEqual(err, EacpError.EACP_ERR_CAPABILITY_DENIED)


if __name__ == "__main__":
    unittest.main()
