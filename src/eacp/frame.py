"""
EACP 48-byte binary frame and 4-slot payload serializer.
"""

from __future__ import annotations
import json
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from .constants import (
    COMPRESSION_THRESHOLD_BYTES,
    DEFAULT_MAX_PAYLOAD_SIZE,
    EACP_MAGIC,
    EACP_VERSION,
    HEADER_SIZE,
    EacpError,
    FrameFlags,
    MsgType,
    PulseCode,
)

# Fixed 48-byte header struct:
# 2s: Magic (0xEACF)
# B:  Version (0x01)
# B:  MsgType (8-bit)
# H:  OpCode (16-bit uint)
# H:  Flags (16-bit uint)
# Q:  Sender PIN (64-bit uint)
# Q:  Target PIN (64-bit uint)
# Q:  Transaction ID (64-bit uint)
# Q:  Capabilities Mask (64-bit uint)
# I:  Status / Error Code (32-bit uint)
# I:  Payload Length (32-bit uint)
HEADER_STRUCT = struct.Struct(">2sBBHHQQQQII")
assert HEADER_STRUCT.size == HEADER_SIZE == 48


@dataclass
class ExecutionConstraints:
    token_budget: int = 0
    timeout_ms: int = 5000
    max_depth_hops: int = 10

    def pack(self) -> bytes:
        return struct.pack(">IIB", self.token_budget, self.timeout_ms, self.max_depth_hops)

    @classmethod
    def unpack(cls, data: bytes) -> ExecutionConstraints:
        if len(data) < 9:
            return cls()
        token_budget, timeout_ms, max_depth_hops = struct.unpack(">IIB", data[:9])
        return cls(token_budget=token_budget, timeout_ms=timeout_ms, max_depth_hops=max_depth_hops)


@dataclass
class CryptoEnvelope:
    session_handle: int = 0
    signature: bytes = b""

    def pack(self) -> bytes:
        sig = self.signature or b""
        return struct.pack(">I", self.session_handle) + sig

    @classmethod
    def unpack(cls, data: bytes) -> CryptoEnvelope:
        if len(data) < 4:
            return cls(session_handle=0, signature=b"")
        session_handle = struct.unpack(">I", data[:4])[0]
        sig = data[4:]
        return cls(session_handle=session_handle, signature=sig)


@dataclass
class EacpFrame:
    magic: bytes = EACP_MAGIC
    version: int = EACP_VERSION
    msg_type: MsgType = MsgType.MSG_SEND
    opcode: int = 0
    flags: FrameFlags = FrameFlags.FLAG_NONE
    sender_pin: int = 0
    target_pin: int = 0
    transaction_id: int = 0
    capabilities_mask: int = 0
    status: int = EacpError.EACP_SUCCESS
    
    # Payload slots (TIpcArgs)
    verb: str = ""
    data: Any = None
    constraints: ExecutionConstraints = field(default_factory=ExecutionConstraints)
    envelope: CryptoEnvelope = field(default_factory=CryptoEnvelope)
    raw_payload: Optional[bytes] = None

    def __setattr__(self, name: str, value: object) -> None:
        """Post-construction mutation of any field invalidates the parsed
        wire cache (raw_payload): verification must still SEE tampering
        (test_frame_signing_and_verification re-encodes mutated fields),
        while the unmodified relay verify path keeps the zero-re-encode
        fast path in get_signed_bytes."""
        if name != "raw_payload" and self.__dict__.get("raw_payload") is not None:
            object.__setattr__(self, "raw_payload", None)
        object.__setattr__(self, name, value)

    def is_pulse(self) -> bool:
        return self.msg_type == MsgType.MSG_PULSE

    def get_pulse_data(self) -> Tuple[int, int]:
        """Extract (code, value) from 8-byte pulse payload."""
        if not self.raw_payload or len(self.raw_payload) < 8:
            return (0, 0)
        code = struct.unpack(">H", self.raw_payload[:2])[0]
        val_bytes = self.raw_payload[2:8]
        val = int.from_bytes(val_bytes, byteorder="big", signed=False)
        return (code, val)

    def pack_slots(self) -> bytes:
        """Serializes 4 slots: [lens(4x uint32)] + slot0 + slot1 + slot2 + slot3."""
        if self.is_pulse():
            return self.raw_payload or b"\x00" * 8

        # Slot 0: Verb string
        slot0 = self.verb.encode("utf-8") if self.verb else b""
        
        # Slot 1: Data (JSON or raw bytes)
        if self.data is None:
            slot1 = b""
        elif isinstance(self.data, bytes):
            slot1 = self.data
        elif isinstance(self.data, (dict, list, int, float, str, bool)):
            slot1 = json.dumps(self.data, separators=(",", ":")).encode("utf-8")
        else:
            slot1 = str(self.data).encode("utf-8")

        # Slot 2: Execution Constraints
        slot2 = (self.constraints or ExecutionConstraints()).pack()

        # Slot 3: Crypto Envelope
        slot3 = (self.envelope or CryptoEnvelope()).pack()

        lens = struct.pack(">IIII", len(slot0), len(slot1), len(slot2), len(slot3))
        raw_slots = lens + slot0 + slot1 + slot2 + slot3

        # Transparent compression if enabled or if exceeding threshold
        if (self.flags & FrameFlags.FLAG_COMPRESSED) or len(raw_slots) > COMPRESSION_THRESHOLD_BYTES:
            compressed = zlib.compress(raw_slots, level=6)
            if len(compressed) < len(raw_slots):
                self.flags |= FrameFlags.FLAG_COMPRESSED
                return compressed

        return raw_slots

    @classmethod
    def unpack_slots(cls, payload: bytes) -> Tuple[str, Any, ExecutionConstraints, CryptoEnvelope]:
        if len(payload) < 16:
            raise ValueError(f"Slot length block too short: {len(payload)} < 16")

        l0, l1, l2, l3 = struct.unpack(">IIII", payload[:16])
        offset = 16

        # Strict bounds check: declared slot lengths must fit the payload exactly.
        # Silent tolerance here would let malformed frames parse with truncated
        # slots — a conformance and interop hazard.
        total = l0 + l1 + l2 + l3
        if offset + total > len(payload):
            raise ValueError(
                f"Slot lengths exceed payload: need {offset + total}, have {len(payload)}"
            )

        slot0_bytes = payload[offset : offset + l0]
        offset += l0
        try:
            verb = slot0_bytes.decode("utf-8")  # strict: invalid UTF-8 is a protocol error
        except UnicodeDecodeError as e:
            raise ValueError(f"Verb slot is not valid UTF-8: {e}") from e

        slot1_bytes = payload[offset : offset + l1]
        offset += l1
        data = None
        if slot1_bytes:
            try:
                data = json.loads(slot1_bytes.decode("utf-8"))
            except Exception:
                data = slot1_bytes

        slot2_bytes = payload[offset : offset + l2]
        offset += l2
        constraints = ExecutionConstraints.unpack(slot2_bytes)

        slot3_bytes = payload[offset : offset + l3]
        envelope = CryptoEnvelope.unpack(slot3_bytes)

        return verb, data, constraints, envelope

    def get_signed_bytes(self) -> bytes:
        """
        Returns bytes used for Ed25519 signing/verifying:
        Header (48 bytes) with payload length matching slots[0..2] + slots 0..2.
        Slot 3 signature is excluded from the signature calculation.
        """
        # Fast path: a parsed frame already carries the exact wire slots
        # (raw_payload = the decompressed slot block). Slicing them costs
        # nothing and cannot drift from the bytes the peer signed — a
        # json re-encode here was pure per-frame waste on the verify path
        # (relay route_frame -> verify_frame, once per signed message).
        if not self.is_pulse() and self.raw_payload is not None and len(self.raw_payload) >= 16:
            l0, l1, l2, l3 = struct.unpack(">IIII", self.raw_payload[:16])
            if 16 + l0 + l1 + l2 + l3 == len(self.raw_payload):
                slots_012 = self.raw_payload[16 : 16 + l0 + l1 + l2]
                s3_head = self.raw_payload[16 + l0 + l1 + l2 : 20 + l0 + l1 + l2]
                if len(s3_head) == 4:
                    # Contract locked by the conformance vectors: the signed
                    # bytes are header + slots WITHOUT the 16-byte length
                    # block; the block only feeds the header's payload_len.
                    flags = int(self.flags) | int(FrameFlags.FLAG_SIGNED)
                    lens = struct.pack(">IIII", l0, l1, l2, 4)
                    payload_len_field = len(lens) + len(slots_012) + len(s3_head) + 64
                    hdr = HEADER_STRUCT.pack(
                        self.magic,
                        self.version,
                        int(self.msg_type),
                        self.opcode,
                        flags,
                        self.sender_pin,
                        self.target_pin,
                        self.transaction_id,
                        self.capabilities_mask,
                        int(self.status),
                        payload_len_field,
                    )
                    return hdr + slots_012 + s3_head
        slot0 = self.verb.encode("utf-8") if self.verb else b""
        if self.data is None:
            slot1 = b""
        elif isinstance(self.data, bytes):
            slot1 = self.data
        elif isinstance(self.data, (dict, list, int, float, str, bool)):
            slot1 = json.dumps(self.data, separators=(",", ":")).encode("utf-8")
        else:
            slot1 = str(self.data).encode("utf-8")
        slot2 = (self.constraints or ExecutionConstraints()).pack()

        # Header with FLAG_SIGNED ensured
        flags = int(self.flags) | int(FrameFlags.FLAG_SIGNED)
        
        # Calculate total payload for slots 0..2 + envelope prefix (session handle)
        slot3_prefix = struct.pack(">I", self.envelope.session_handle if self.envelope else 0)
        lens = struct.pack(">IIII", len(slot0), len(slot1), len(slot2), len(slot3_prefix))
        payload_subset = lens + slot0 + slot1 + slot2 + slot3_prefix

        # Use full signed payload length in header
        total_len = len(payload_subset) + (64 if (flags & FrameFlags.FLAG_SIGNED) else 0)
        hdr = HEADER_STRUCT.pack(
            self.magic,
            self.version,
            int(self.msg_type),
            self.opcode,
            flags,
            self.sender_pin,
            self.target_pin,
            self.transaction_id,
            self.capabilities_mask,
            int(self.status),
            total_len,
        )
        return hdr + slot0 + slot1 + slot2 + slot3_prefix

    def pack(self) -> bytes:
        payload = self.pack_slots()
        payload_len = len(payload)
        header = HEADER_STRUCT.pack(
            self.magic,
            self.version,
            int(self.msg_type),
            self.opcode,
            int(self.flags),
            self.sender_pin,
            self.target_pin,
            self.transaction_id,
            self.capabilities_mask,
            int(self.status),
            payload_len,
        )
        return header + payload

    @classmethod
    def unpack(cls, buffer: bytes, max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE) -> EacpFrame:
        if len(buffer) < HEADER_SIZE:
            raise ValueError(f"Buffer too short for EACP header: {len(buffer)} < {HEADER_SIZE}")
        
        magic, ver, msg_type_raw, opcode, flags_raw, sender_pin, target_pin, tx_id, cap_mask, status_raw, payload_len = HEADER_STRUCT.unpack(buffer[:HEADER_SIZE])
        
        if magic != EACP_MAGIC:
            raise ValueError(f"Invalid EACP magic: {magic!r} != {EACP_MAGIC!r}")
        if ver != EACP_VERSION:
            raise ValueError(f"Unsupported EACP version: {ver} != {EACP_VERSION}")

        if payload_len > max_payload_size:
            raise ValueError(f"Payload length {payload_len} exceeds max allowed {max_payload_size}")

        payload = buffer[HEADER_SIZE : HEADER_SIZE + payload_len]
        if len(payload) < payload_len:
            raise ValueError(f"Incomplete payload: expected {payload_len} bytes, got {len(payload)}")

        msg_type = MsgType(msg_type_raw)
        flags = FrameFlags(flags_raw)
        status = EacpError(status_raw)

        if msg_type == MsgType.MSG_PULSE:
            return cls(
                magic=magic,
                version=ver,
                msg_type=msg_type,
                opcode=opcode,
                flags=flags,
                sender_pin=sender_pin,
                target_pin=target_pin,
                transaction_id=tx_id,
                capabilities_mask=cap_mask,
                status=status,
                raw_payload=payload,
            )

        # Transparent decompression if FLAG_COMPRESSED is set
        effective_payload = payload
        if flags & FrameFlags.FLAG_COMPRESSED:
            effective_payload = zlib.decompress(payload)

        verb, data, constraints, envelope = cls.unpack_slots(effective_payload)
        return cls(
            magic=magic,
            version=ver,
            msg_type=msg_type,
            opcode=opcode,
            flags=flags,
            sender_pin=sender_pin,
            target_pin=target_pin,
            transaction_id=tx_id,
            capabilities_mask=cap_mask,
            status=status,
            verb=verb,
            data=data,
            constraints=constraints,
            envelope=envelope,
            raw_payload=effective_payload,
        )

    def create_reply(self, status: int = EacpError.EACP_SUCCESS, result_data: Any = None) -> EacpFrame:
        """Create a corresponding MSG_REPLY frame targeting the sender."""
        return EacpFrame(
            magic=self.magic,
            version=self.version,
            msg_type=MsgType.MSG_REPLY,
            opcode=self.opcode,
            flags=self.flags & ~FrameFlags.FLAG_URGENT,
            sender_pin=self.target_pin,
            target_pin=self.sender_pin,
            transaction_id=self.transaction_id,
            capabilities_mask=self.capabilities_mask,
            status=status,
            verb=self.verb,
            data=result_data,
            constraints=self.constraints,
            envelope=CryptoEnvelope(session_handle=self.envelope.session_handle if self.envelope else 0),
        )

    @classmethod
    def create_pulse(
        cls,
        sender_pin: int,
        target_pin: int,
        pulse_code: int | PulseCode,
        pulse_value: int = 0,
        tx_id: int = 0,
    ) -> EacpFrame:
        code_int = int(pulse_code)
        val_bytes = pulse_value.to_bytes(6, byteorder="big", signed=False)
        payload = struct.pack(">H", code_int) + val_bytes
        return cls(
            msg_type=MsgType.MSG_PULSE,
            sender_pin=sender_pin,
            target_pin=target_pin,
            transaction_id=tx_id,
            raw_payload=payload,
        )
