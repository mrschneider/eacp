"""
Unit tests for EACP binary wire format and slot serialization.
"""

import struct
import unittest

from eacp.constants import (
    EACP_MAGIC,
    EACP_VERSION,
    HEADER_SIZE,
    Capability,
    EacpError,
    FrameFlags,
    MsgType,
    OpCode,
    PulseCode,
)
from eacp.frame import CryptoEnvelope, EacpFrame, ExecutionConstraints, HEADER_STRUCT


class TestEacpFrame(unittest.TestCase):
    def test_header_size(self):
        self.assertEqual(HEADER_STRUCT.size, 48)
        self.assertEqual(HEADER_SIZE, 48)

    def test_frame_pack_unpack_roundtrip(self):
        constraints = ExecutionConstraints(token_budget=2048, timeout_ms=3000, max_depth_hops=5)
        envelope = CryptoEnvelope(session_handle=42, signature=b"X" * 64)
        
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_ACTION_INVOKE,
            flags=FrameFlags.FLAG_SIGNED | FrameFlags.FLAG_URGENT,
            sender_pin=0x1122334455667788,
            target_pin=0x8877665544332211,
            transaction_id=1001,
            capabilities_mask=int(Capability.CAP_NET_RAW | Capability.CAP_DISK_READ),
            status=EacpError.EACP_SUCCESS,
            verb="query_database",
            data={"query": "SELECT * FROM agents", "limit": 10},
            constraints=constraints,
            envelope=envelope,
        )

        packed = frame.pack()
        self.assertGreater(len(packed), 48)

        unpacked = EacpFrame.unpack(packed)
        self.assertEqual(unpacked.magic, EACP_MAGIC)
        self.assertEqual(unpacked.version, EACP_VERSION)
        self.assertEqual(unpacked.msg_type, MsgType.MSG_SEND)
        self.assertEqual(unpacked.opcode, OpCode.OP_ACTION_INVOKE)
        self.assertEqual(unpacked.flags, FrameFlags.FLAG_SIGNED | FrameFlags.FLAG_URGENT)
        self.assertEqual(unpacked.sender_pin, 0x1122334455667788)
        self.assertEqual(unpacked.target_pin, 0x8877665544332211)
        self.assertEqual(unpacked.transaction_id, 1001)
        self.assertEqual(unpacked.capabilities_mask, int(Capability.CAP_NET_RAW | Capability.CAP_DISK_READ))
        self.assertEqual(unpacked.status, EacpError.EACP_SUCCESS)

        # Verify slots
        self.assertEqual(unpacked.verb, "query_database")
        self.assertEqual(unpacked.data, {"query": "SELECT * FROM agents", "limit": 10})
        self.assertEqual(unpacked.constraints.token_budget, 2048)
        self.assertEqual(unpacked.constraints.timeout_ms, 3000)
        self.assertEqual(unpacked.constraints.max_depth_hops, 5)
        self.assertEqual(unpacked.envelope.session_handle, 42)
        self.assertEqual(unpacked.envelope.signature, b"X" * 64)

    def test_pulse_frame(self):
        pulse = EacpFrame.create_pulse(
            sender_pin=0xAAAA_BBBB_CCCC_DDDD,
            target_pin=0x1111_2222_3333_4444,
            pulse_code=PulseCode.PULSE_CANCEL,
            pulse_value=0x12345678,
            tx_id=99,
        )

        packed = pulse.pack()
        self.assertEqual(len(packed), 48 + 8)  # Fixed 48-byte header + 8-byte pulse payload

        unpacked = EacpFrame.unpack(packed)
        self.assertTrue(unpacked.is_pulse())
        self.assertEqual(unpacked.msg_type, MsgType.MSG_PULSE)
        code, val = unpacked.get_pulse_data()
        self.assertEqual(code, int(PulseCode.PULSE_CANCEL))
        self.assertEqual(val, 0x12345678)

    def test_invalid_magic_raises(self):
        bad_header = b"\xFF\xFF" + b"\x00" * 46
        with self.assertRaises(ValueError) as ctx:
            EacpFrame.unpack(bad_header)
        self.assertIn("Invalid EACP magic", str(ctx.exception))

    def test_truncated_buffer_raises(self):
        with self.assertRaises(ValueError):
            EacpFrame.unpack(b"\xEA\xCF\x01")

    def test_create_reply(self):
        req = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_ACTION_INVOKE,
            flags=FrameFlags.FLAG_URGENT,
            sender_pin=0xAAAA,
            target_pin=0xBBBB,
            transaction_id=55,
            verb="echo",
            data="hello",
        )
        reply = req.create_reply(status=EacpError.EACP_SUCCESS, result_data="world")
        self.assertEqual(reply.msg_type, MsgType.MSG_REPLY)
        self.assertEqual(reply.sender_pin, 0xBBBB)
        self.assertEqual(reply.target_pin, 0xAAAA)
        self.assertEqual(reply.transaction_id, 55)
        self.assertEqual(reply.data, "world")
        self.assertFalse(reply.flags & FrameFlags.FLAG_URGENT)

    def test_transparent_compression(self):
        # Large repetitive payload (> 1KB) should be compressed automatically
        large_data = {"text": "A" * 5000, "tokens": list(range(500))}
        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            verb="large_context",
            data=large_data,
        )

        packed = frame.pack()
        # Verify FLAG_COMPRESSED was engaged
        unpacked = EacpFrame.unpack(packed)
        self.assertTrue(unpacked.flags & FrameFlags.FLAG_COMPRESSED)
        self.assertEqual(unpacked.data, large_data)
        # Packed size should be significantly smaller than uncompressed raw text
        self.assertLess(len(packed), 2000)

    def test_max_payload_size_dos_guard(self):
        # Frame declaring payload larger than allowed max
        fake_header = HEADER_STRUCT.pack(
            EACP_MAGIC,
            1,
            int(MsgType.MSG_SEND),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            100_000,  # 100KB payload
        )
        with self.assertRaises(ValueError) as ctx:
            EacpFrame.unpack(fake_header, max_payload_size=1024)  # Limit 1KB
        self.assertIn("exceeds max allowed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
