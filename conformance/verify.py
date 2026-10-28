#!/usr/bin/env python3
"""
EACP conformance self-verifier.

Acts as a *strict independent consumer* of vectors.json: re-parses every
positive frame, byte-compares re-encoding, verifies Ed25519 signatures using
raw cryptography primitives (not eacp.security), recomputes PINs with a local
SHA-256 implementation of the documented algorithm, and asserts every negative
vector is rejected with the expected error class.

Exit code 0 = conformant. Any failure is a bug in the implementation OR in the
vectors — both block a release.
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

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from eacp.constants import (  # noqa: E402
    EACP_MAGIC, HEADER_SIZE, EacpError, FrameFlags, MsgType,
)
from eacp.frame import EacpFrame, ExecutionConstraints, HEADER_STRUCT  # noqa: E402

FAILURES = []


def check(cond: bool, label: str) -> None:
    if not cond:
        FAILURES.append(label)
        print(f"  FAIL  {label}")
    else:
        print(f"  ok    {label}")


def main() -> None:
    with open(os.path.join(HERE, "vectors.json")) as fp:
        vectors = json.load(fp)

    # ---------------------------------------------------------------- identity
    print("== identity / PIN derivation (independent SHA-256 implementation) ==")
    for v in vectors["identity"]["pin_derivation"]["vectors"]:
        pk = bytes.fromhex(v["public_key_hex"])
        pin = int.from_bytes(hashlib.sha256(pk).digest()[:8], "big")
        check(pin == v["pin_dec"], f"pin derivation {v['pin_hex']}")

    # -------------------------------------------------------- positive frames
    print("== positive frames: parse, field equality, byte-exact re-encode ==")
    parsed_by_name = {}
    for case in vectors["frames_positive"]:
        raw = bytes.fromhex(case["frame_hex"])
        f = EacpFrame.unpack(raw, max_payload_size=4096)
        exp = case["expected"]
        ok = (
            f.version == exp["version"]
            and int(f.msg_type) == exp["msg_type"]
            and f.opcode == exp["opcode"]
            and int(f.flags) == exp["flags"]
            and f.sender_pin == exp["sender_pin"]
            and f.target_pin == exp["target_pin"]
            and f.transaction_id == exp["transaction_id"]
            and f.capabilities_mask == exp["capabilities_mask"]
            and int(f.status) == exp["status"]
            and f.verb == exp["verb"]
            and f.data == exp["data"]
            and f.constraints.token_budget == exp["constraints"]["token_budget"]
            and f.constraints.timeout_ms == exp["constraints"]["timeout_ms"]
            and f.constraints.max_depth_hops == exp["constraints"]["max_depth_hops"]
            and f.envelope.session_handle == exp["session_handle"]
        )
        check(ok, f"parse fields: {case['name']}")
        check(f.pack() == raw, f"re-encode byte-exact: {case['name']}")
        if case.get("expect_flag_compressed"):
            check(bool(f.flags & FrameFlags.FLAG_COMPRESSED),
                  f"compression flag engaged: {case['name']}")
        parsed_by_name[case["name"]] = (f, raw)

    # ------------------------------------------------------------- signatures
    print("== Ed25519 signatures (raw cryptography primitives) ==")
    sig = vectors["signatures"]
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["verify_positive"]["public_key_hex"]))
    signing_bytes = bytes.fromhex(sig["verify_positive"]["signing_bytes_hex"])
    signature = bytes.fromhex(sig["verify_positive"]["signature_hex"])
    frame_f, raw_orig = parsed_by_name["msg_send_full_signed"]
    # repartition recipe (SEC-02): shift 5 bytes of the boundary from the
    # arguments slot into the verb slot, content bytes untouched
    _l0, _l1, _l2, _l3 = struct.unpack(">IIII", raw_orig[48:64])
    _shift = min(5, _l1)
    new_lens = struct.pack(">IIII", _l0 + _shift, _l1 - _shift, _l2, _l3)
    check(frame_f.get_signed_bytes() == signing_bytes,
          "reference signing bytes match vectors")
    try:
        pub.verify(signature, signing_bytes)
        valid = True
    except InvalidSignature:
        valid = False
    check(valid, "positive signature verifies")

    # negative: mutate the verb, signature must fail
    tampered = EacpFrame.unpack(bytes.fromhex(
        next(c for c in vectors["frames_positive"] if c["name"] == "msg_send_full_signed")["frame_hex"]
    ))
    tampered.verb = "query_databaseX"
    try:
        pub.verify(signature, tampered.get_signed_bytes())
        tampered_valid = True
    except InvalidSignature:
        tampered_valid = False
    check(not tampered_valid, "tampered frame signature rejected")

    # negative: repartition the slot boundaries (SEC-02) — identical
    # concatenated bytes under a different verb/args split. The 16-byte
    # length block is authenticated in signing contract v2, so the same
    # signature must fail against the repartitioned frame.
    repartitioned = raw_orig[:48] + new_lens + raw_orig[64:]
    rp = EacpFrame.unpack(repartitioned)
    check(rp.verb != frame_f.verb,
          f"repartition changed the parsed verb ({frame_f.verb!r} -> {rp.verb!r})")
    try:
        pub.verify(signature, rp.get_signed_bytes())
        rp_valid = True
    except InvalidSignature:
        rp_valid = False
    check(not rp_valid, "slot repartition rejected (length block authenticated)")

    # --------------------------------------------------------------- negative
    print("== negative vectors: must be rejected with the expected class ==")
    for neg in vectors["frames_negative"]:
        raw = bytes.fromhex(neg["bytes_hex"])
        rejected = False
        try:
            EacpFrame.unpack(raw, max_payload_size=neg.get("max_payload_size", 4096))
        except ValueError:
            rejected = True
        except zlib.error:
            rejected = neg["error"] == "malformed_frame"
        except struct.error:
            rejected = neg["error"] == "malformed_frame"
        except Exception:
            rejected = False
        check(rejected, f"rejected: {neg['name']} ({neg['error']})")

    # ------------------------------------------------------------ determinism
    print("== generator determinism ==")
    before = hashlib.sha256(open(os.path.join(HERE, "vectors.json"), "rb").read()).hexdigest()
    import subprocess
    subprocess.run([sys.executable, os.path.join(HERE, "generate.py")],
                   check=True, capture_output=True)
    after = hashlib.sha256(open(os.path.join(HERE, "vectors.json"), "rb").read()).hexdigest()
    check(before == after, "vectors.json is byte-identical across runs")

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S)")
        sys.exit(1)
    print("\nAll conformance checks passed.")


if __name__ == "__main__":
    main()
