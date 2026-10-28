#!/usr/bin/env python3
"""
EACP cross-language conformance vector generator.

Produces `vectors.json` — the canonical, deterministic test vectors that ANY
language implementation (Python, Scala, Rust, Go, ...) must satisfy
byte-for-byte to interoperate with the EACP mesh.

Everything is deterministic: fixed Ed25519 seeds, fixed transaction ids, no
randomness. Re-running this script must produce a byte-identical file
(checked by verify.py).

Usage:
    PYTHONPATH=../src python3 generate.py     # regenerate vectors.json
    python3 verify.py                         # self-check against the suite
"""
import base64
import hashlib
import json
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from eacp.constants import (  # noqa: E402
    EACP_MAGIC, EACP_VERSION, HEADER_SIZE,
    Capability, EacpError, FrameFlags, MsgType, PulseCode,
)
from eacp.frame import (  # noqa: E402
    EacpFrame, ExecutionConstraints, CryptoEnvelope, HEADER_STRUCT,
)
from eacp.security import AgentIdentity  # noqa: E402

MAX_PAYLOAD = 4096  # tight limit for negative vectors
COMPRESSION_THRESHOLD = 1024


def h(b: bytes) -> str:
    return b.hex()


def frame_fields(f: EacpFrame) -> dict:
    return {
        "version": f.version,
        "msg_type": int(f.msg_type),
        "msg_type_name": f.msg_type.name,
        "opcode": f.opcode,
        "flags": int(f.flags),
        "sender_pin": f.sender_pin,
        "target_pin": f.target_pin,
        "transaction_id": f.transaction_id,
        "capabilities_mask": f.capabilities_mask,
        "status": int(f.status),
        "verb": f.verb,
        "data": f.data,
        "constraints": {
            "token_budget": f.constraints.token_budget,
            "timeout_ms": f.constraints.timeout_ms,
            "max_depth_hops": f.constraints.max_depth_hops,
        },
        "session_handle": f.envelope.session_handle,
    }


def main() -> None:
    # ------------------------------------------------------------------ keys
    # Deterministic seeds (no RNG anywhere).
    seed_a = bytes(range(32))                                  # 000102..1f
    seed_b = bytes((i * 7 + 11) % 256 for i in range(32))
    ida = AgentIdentity.from_private_bytes(seed_a)
    idb = AgentIdentity.from_private_bytes(seed_b)

    vectors = {
        "meta": {
            "protocol": "EACP",
            "protocol_version": EACP_VERSION,
            "header_size": HEADER_SIZE,
            "byte_order": "big-endian (network order)",
            "header_struct": ">2sBBHHQQQQII",
            "slot_layout": (
                "payload = len(s0):u16 | s0 | len(s1):u32 | s1 | "
                "len(s2):u32 | s2 | len(s3):u32 | s3  "
                "(s0=utf8 verb, s1=json invocation, s2=9-byte "
                "token_budget:u32/timeout_ms:u32/max_depth_hops:u8, "
                "s3=4-byte session_handle:u32 + 64-byte Ed25519 signature)"
            ),
            "signing_domain": (
                "Ed25519 signature covers the 48-byte header (with FLAG_SIGNED "
                "set and payload_len = len(slots 0..2) + 64) followed by slots "
                "0..2 and the 4-byte session_handle prefix of slot 3 "
                "(signature bytes excluded). See frame.get_signed_bytes()."
            ),
            "compression": (
                "If FLAG_COMPRESSED is set, the payload section is a zlib stream "
                "of the slot block described above (zlib level 6 in the reference "
                "implementation; decompression is level-agnostic)."
            ),
            "limits": {"max_payload_size_for_negative_vectors": MAX_PAYLOAD},
            "note": (
                "A conforming implementation MUST: (a) parse each positive "
                "'frame_hex' into exactly the listed fields; (b) re-encode its "
                "own frames to the same bytes; (c) verify Ed25519 signatures over "
                "the documented signing domain; (d) reject every negative vector "
                "with the listed error."
            ),
        },
    }

    # ------------------------------------------------------------- identity
    vectors["identity"] = {
        "pin_derivation": {
            "algorithm":
                "Agent-PIN = first 8 bytes of SHA-256(public_key) as big-endian uint64",
            "vectors": [
                {"private_seed_hex": h(seed), "public_key_hex": h(ident.public_bytes),
                 "pin_dec": ident.pin, "pin_hex": ident.pin_hex}
                for seed, ident in ((seed_a, ida), (seed_b, idb))
            ],
        },
    }

    # ------------------------------------------------------ positive frames
    frames = []

    def add(name: str, f: EacpFrame, signed_by: AgentIdentity | None = None,
            expect_compressed: bool = False):
        if signed_by is not None:
            signed_by.sign_frame(f, session_handle=f.envelope.session_handle)
        raw = f.pack()
        entry = {"name": name, "frame_hex": h(raw), "expected": frame_fields(f)}
        if signed_by is not None:
            entry["signature_hex"] = h(f.envelope.signature)
            entry["signer_public_key_hex"] = h(signed_by.public_bytes)
        if expect_compressed:
            entry["expect_flag_compressed"] = True
        frames.append(entry)

    # 1. Minimal MSG_SEND — empty slots, zero pins
    add("msg_send_minimal", EacpFrame(
        msg_type=MsgType.MSG_SEND, sender_pin=0, target_pin=0, transaction_id=0,
    ))

    # 2. Full MSG_SEND — every field populated, signed
    f = EacpFrame(
        msg_type=MsgType.MSG_SEND,
        opcode=0x0100,  # OP_ACTION_INVOKE
        flags=int(FrameFlags.FLAG_URGENT),
        sender_pin=ida.pin, target_pin=idb.pin, transaction_id=0xA1B2C3D4E5F60718,
        capabilities_mask=int(Capability.CAP_DISK_READ | Capability.CAP_TOOL_EXEC),
        verb="query_database",
        data={"query": "SELECT pin, verb FROM agents LIMIT 2", "limit": 2},
        constraints=ExecutionConstraints(token_budget=2048, timeout_ms=3000, max_depth_hops=5),
        envelope=CryptoEnvelope(session_handle=42),
    )
    add("msg_send_full_signed", f, signed_by=ida)

    # 3. MSG_REPLY carrying remaining token budget (cascade accounting)
    reply = f.create_reply(status=EacpError.EACP_SUCCESS,
                           result_data={"rows": [["0xABC", "ping"]], "rows_affected": 1})
    reply.constraints = ExecutionConstraints(token_budget=1749, timeout_ms=3000, max_depth_hops=5)
    add("msg_reply_remaining_budget", reply, signed_by=idb)

    # 4. MSG_PULSE — exactly 8-byte payload (code:u16 + value:u48)
    pulse = EacpFrame.create_pulse(
        sender_pin=idb.pin, target_pin=ida.pin,
        pulse_code=PulseCode.PULSE_CANCEL, pulse_value=0xDEADBEEF, tx_id=7,
    )
    add("msg_pulse_cancel", pulse)

    # 5. MSG_RELAY_CONTROL registration (unsigned, relay-local)
    add("relay_register", EacpFrame(
        msg_type=MsgType.MSG_RELAY_CONTROL,
        opcode=0x0001,  # OP_RELAY_REGISTER
        sender_pin=idb.pin, target_pin=0, transaction_id=1,
        capabilities_mask=int(Capability.CAP_DISK_READ),
        verb="register",
        data={"pub_bytes": h(idb.public_bytes)},
    ))

    # 6. Compression engages above threshold — big repetitive payload
    big = EacpFrame(
        msg_type=MsgType.MSG_SEND,
        sender_pin=ida.pin, target_pin=idb.pin, transaction_id=2,
        verb="large_context",
        data={"text": "A" * 5000, "tokens": list(range(200))},
    )
    add("msg_send_compressed", big, expect_compressed=True)

    # 7. Error-status frame (capability denial reply, unsigned)
    add("msg_reply_capability_denied", EacpFrame(
        msg_type=MsgType.MSG_REPLY,
        sender_pin=idb.pin, target_pin=ida.pin, transaction_id=0xA1B2C3D4E5F60718,
        status=EacpError.EACP_ERR_CAPABILITY_DENIED,
        verb="reboot_node",
        data={"error": "PlatSec capability denied"},
    ))

    # 7b. Additive error statuses (wire-visible codes 12/13)
    add("msg_reply_replay_detected", EacpFrame(
        msg_type=MsgType.MSG_REPLY,
        sender_pin=idb.pin, target_pin=ida.pin, transaction_id=3,
        status=EacpError.EACP_ERR_REPLAY_DETECTED,
        verb="query_database",
        data={"error": "replayed transaction refused"},
    ))
    add("msg_reply_queue_full", EacpFrame(
        msg_type=MsgType.MSG_REPLY,
        sender_pin=idb.pin, target_pin=ida.pin, transaction_id=4,
        status=EacpError.EACP_ERR_QUEUE_FULL,
        verb="offline_delivery",
        data={"error": "offline queue budget exceeded"},
    ))

    vectors["frames_positive"] = frames

    # ------------------------------------------------------------ signatures
    # Signing-domain transparency: verifier recomputes signing bytes and checks
    # the Ed25519 signature; also a tamper case that MUST fail.
    sig_entry = frames[1]  # msg_send_full_signed
    signed_frame = EacpFrame.unpack(bytes.fromhex(sig_entry["frame_hex"]))
    signing_bytes = signed_frame.get_signed_bytes()
    vectors["signatures"] = {
        "algorithm": "Ed25519 (RFC 8032), pure — no prehash",
        "signing_bytes_of_msg_send_full_signed": h(signing_bytes),
        "verify_positive": {
            "public_key_hex": sig_entry["signer_public_key_hex"],
            "signature_hex": sig_entry["signature_hex"],
            "signing_bytes_hex": h(signing_bytes),
            "expect_valid": True,
        },
        "verify_negative_tampered_payload": {
            "note": "same frame with verb changed; signature MUST be invalid",
            "public_key_hex": sig_entry["signer_public_key_hex"],
            "signature_hex": sig_entry["signature_hex"],
            "mutate": {"field": "verb", "from": "query_database", "to": "query_databaseX"},
            "expect_valid": False,
        },
    }

    # -------------------------------------------------------------- negative
    def hdr(payload_len: int, magic: bytes = EACP_MAGIC, version: int = EACP_VERSION,
            msg_type: int = 1, flags: int = 0) -> bytes:
        return HEADER_STRUCT.pack(magic, version, msg_type, 0, flags, 0, 0, 0, 0, 0, payload_len)

    negatives = [
        {"name": "bad_magic",
         "bytes_hex": h(hdr(0, magic=b"\x00\x00")),
         "error": "invalid_magic"},
        {"name": "unsupported_version",
         "bytes_hex": h(hdr(0, version=99)),
         "error": "malformed_frame"},
        {"name": "unknown_msg_type",
         "bytes_hex": h(hdr(0, msg_type=0x7F)),
         "error": "malformed_frame"},
        {"name": "truncated_header",
         "bytes_hex": h(hdr(0)[:-1]),
         "error": "malformed_frame"},
        {"name": "truncated_payload",
         "bytes_hex": h(hdr(64) + b"\x00" * 10),
         "error": "malformed_frame"},
        {"name": "payload_exceeds_max",
         "bytes_hex": h(hdr(MAX_PAYLOAD + 1)),
         "error": "payload_too_large",
         "max_payload_size": MAX_PAYLOAD},
        {"name": "garbage_slot_lengths",
         "bytes_hex": h(hdr(16) + struct.pack(">IIII", 0xFFFF, 0, 0, 0)),
         "error": "malformed_frame"},
        {"name": "invalid_utf8_verb",
         "bytes_hex": h(hdr(14) +
                        struct.pack(">H", 2) + b"\xff\xfe" +
                        struct.pack(">III", 0, 0, 0)),
         "error": "malformed_frame"},
        {"name": "bad_zlib_stream",
         "bytes_hex": h(hdr(8, flags=int(FrameFlags.FLAG_COMPRESSED)) + b"\x00" * 8),
         "error": "malformed_frame"},
    ]
    vectors["frames_negative"] = negatives

    # compression sanity: the compressed positive frame's payload section must
    # be a raw zlib stream that any zlib implementation can decompress
    comp = EacpFrame.unpack(bytes.fromhex(frames[5]["frame_hex"]))
    assert comp.flags & FrameFlags.FLAG_COMPRESSED
    slot_block = zlib.decompress(bytes.fromhex(frames[5]["frame_hex"])[HEADER_SIZE:])
    assert len(slot_block) > COMPRESSION_THRESHOLD and comp.verb == "large_context"
    vectors["compression_check"] = {
        "note": "payload section (after 48-byte header) of msg_send_compressed "
                "is a raw zlib stream; any zlib implementation must decompress it",
    }

    out = os.path.join(HERE, "vectors.json")
    with open(out, "w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=False)
        fp.write("\n")
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
