# EACP Conformance Suite

This directory is the **cross-language contract** of the EACP wire protocol.
`vectors.json` contains byte-exact, deterministic test vectors that any
implementation — Python, Scala, Rust, Go, ... — must satisfy to interoperate
with the EACP mesh.

## What implementers must satisfy

Given `vectors.json`:

1. **Identity** — derive the Agent-PIN from a public key:
   `Agent-PIN = first 8 bytes of SHA-256(public_key)` interpreted as a
   big-endian uint64. The vectors contain the expected decimal and `0x____` forms.

2. **Positive frames** (`frames_positive[*].frame_hex`) — parse the hex bytes
   and produce exactly the listed fields (header fields, slots, constraints,
   session handle). Then re-encode your own equivalent frame and compare
   **byte-for-byte**. Any difference — padding, field order, byte order — is a
   non-conformance.

3. **Compression** — frames with `FLAG_COMPRESSED` carry a raw zlib stream of
   the slot block after the 48-byte header. Any conforming zlib decoder must
   decompress it. (The reference encoder uses zlib level 6, but decoders must
   not assume a level.)

4. **Signatures** (`signatures`) — Ed25519 (RFC 8032, pure), signing
   contract **v2** (wire version 2). The signed bytes are the 48-byte
   header (FLAG_SIGNED set, FLAG_COMPRESSED excluded, payload length =
   16 + slots 0..2 + 68) followed by the **16-byte slot length block**,
   slots 0..2, and the 4-byte session-handle prefix of slot 3. The length
   block is authenticated: repartitioning the same concatenated bytes
   across slot boundaries (verb/arguments swap) changes the signature
   input, and `verify.py` checks exactly that case. Verify the positive
   vector; verify that BOTH the tampered and the repartitioned vectors
   FAIL.

5. **Negative vectors** (`frames_negative[*]`) — each byte string MUST be
   rejected. Accepting any of them is a conformance failure (they encode
   real hazards: version confusion, out-of-bounds slot lengths, invalid
   UTF-8 verbs, zlib bombs).

## Versioning & compatibility

The wire `version` byte is `0x02` (EACP v2). v2 authenticates the slot
length block (signing contract v2); v1 peers sign a different byte set and
are refused **at the version check** by both implementations — never by a
misleading signature error. Compatibility policy: additive error codes or
new relay-control opcodes stay within the same wire version (semver minor);
any change to the signed byte set or the header layout bumps the wire
version (semver major). There is no dual acceptance of v1 signatures.

## Layout

```
generate.py   Regenerates vectors.json deterministically (fixed seeds, no RNG)
verify.py     Independent strict consumer: parses, re-encodes, verifies,
              rejects — and asserts generator determinism
vectors.json  The ground truth (committed; do not hand-edit)
```

## Adding a new vector

1. Extend `generate.py`.
2. Run `python3 generate.py` (determinism check will catch accidental RNG).
3. If the new vector exposes an implementation gap, **fix the implementation**,
   not the expectation — the vectors encode the spec in `ARCHITECTURE.md`.
4. Update this file if you introduce a new section.

## Historical note

The initial vectors already caught three real defects in the reference
implementation (missing version-byte check, out-of-bounds slot lengths
silently accepted, invalid UTF-8 verbs silently replaced). That is the point
of the suite: the wire contract is enforced by bytes, not by intentions.
