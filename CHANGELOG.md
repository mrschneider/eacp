# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking
- **Wire version 2 (EACP v2): signing contract v2 authenticates the slot
  length block** — `get_signed_bytes()` now covers
  `header || 16-byte length block || slots 0..2 || envelope prefix`, so
  repartitioning the same bytes across slot boundaries (verb/arguments
  swap) invalidates the signature (SEC-02 repro closed). The header
  `version` byte is `0x02`; v1 peers are refused at the version check on
  both implementations instead of failing signature verification with a
  mystery error. Compatibility policy in CONFORMANCE.md ("Versioning &
  compatibility"): additive codes/opcodes stay same wire version, signed-
  byte or layout changes bump it; no dual acceptance of v1 signatures.
  Conformance vectors regenerated; verify.py gained a slot-repartition
  negative check.

### Security
- **SEC-01 authenticated ingress** — application frames are refused until
  the connection registers (or completes the peer handshake), the frame's
  sender must equal the connection's authenticated PIN (no impersonation),
  no pin switching after registration, and teardown refusals are awaited
  (no fire-and-forget race). The reviewer's exact repro — unsigned
  administrative request carrying a genuine CA-signed public manifest from
  an unregistered connection — is now refused at ingress, and the receiver
  additionally requires the frame itself to be signed by the manifest key
  before caller-manifest grants count (PoP).
- **SEC-03 mesh authentication** — route announcements are admitted only
  from connections that completed a mutual PSK challenge/response with a
  fresh per-connection nonce (opcodes HELLO/CHALLENGE/AUTH); a claimed
  configured peer name is no longer identity. Ownership rules: a local
  pin always wins, a routed pin may not be moved by another peer, only
  the owning peer may release it; forwarded announces ride an
  authenticated peer's assertion within the PSK trust boundary.
- **RUST-01 frame-level parity** — the Rust relay now enforces
  authenticated ingress and connection-bound senders, validates proof of
  possession at registration (presented key stored), verifies Ed25519
  signing-contract-v2 signatures per frame, refuses (tx, target) replays
  (2048-window), and checks the wire version — exercised by the CI
  interop job. Remaining gaps (CA manifests, TLS, mesh, audit, telemetry)
  documented in ARCHITECTURE §8.3.

### Added
- **RUN-01 admission bound** — `max_inflight` (default 4x the handler
  semaphore) refuses over-capacity work with an explicit
  `EACP_ERR_QUEUE_FULL` *before* creating a task; bounded task counts
  under sustained overload with recovery afterwards (tested).
- **Ledger cumulative spend (`spent`)** — consumption is recorded at
  `consume()` time so failure/cancel refunds release only the unused
  reservation, never the spend already incurred (BUD-01).

### Fixed
- **REL-01 bounded decompression** — rejection now happens before any
  unbounded `flush()` (traced peak stays near the 64 KiB limit instead of
  ~7.7 MB for the 8 MB bomb), plus truncated-stream and trailing-bytes
  rejection.
- **REL-02 absolute ledger indices** — recovery of a rotated segment
  continues at `last_index + 1` (was: `len(recovered)` restarted the
  sequence and broke the next restart); `verify_chain()` verifies from the
  segment's own start index with a genesis anchor only at index 0.
  Rotation → restart → append → restart stays monotonic (tested).
- **RUN-02 escrow identity** — dispatcher escrows are keyed
  `(sender_pin, tx)`; two callers using the same transaction id no longer
  collide (tested end-to-end); `spend_tokens(..., sender_pin=frame.sender_pin)`
  matches from inside handlers. Replay identity is `(tx, target)` — a
  server may legitimately answer two callers that chose the same tx.
- **QUE-01 per-target queue overflow is explicit** — the silent
  `deque(maxlen)` eviction is gone; the per-target cap now answers the
  sender with `EACP_ERR_QUEUE_FULL` and releases the deadlock dependency,
  exactly like the global budget path (tested).
- **BUD-01 attenuation on explicit overrides** — `create_downstream_constraints`
  can no longer raise a finite parent's budget nor convert it to
  unlimited via an explicit `0` (min/keep semantics, both branches
  tested). Sibling reservation against one shared parent envelope and
  LLM-provider metering remain tracked as remaining work (the payload
  estimate stays distinct from provider usage by design).
- **DOC-01 claims narrowed** — cancellation documented as cooperative at
  await points (synchronous-blocking or cancellation-suppressing handlers
  excluded); "no races" replaced with the actual single-loop guarantee.
- **REP-01 bytecode untracked** — `src/eacp/__pycache__/*.pyc` removed
  from git; `*.pyc`/`*.pyo` added to .gitignore alongside
  `__pycache__/`.

## [1.3.0] - 2026-10-27

### Security
- **Authorization now follows the caller's authenticated grants** — claimed
  capabilities are checked against the registration grants at the relay AND
  against the caller's CA-attested manifest at the receiver (three layers:
  caller grants, request attenuation, target policy; delegated permissions may
  only decrease). A `Capability.NONE` caller can no longer execute privileged
  handlers by simply claiming `CAP_SYS_ADMIN`.
- **Registration trust chain repaired** — manifests are verified against the
  CONFIGURED trusted CA public key (not the key inside the submitted manifest),
  with manifest-pin/key binding (`compute_pin(public) == pin`) and
  proof-of-possession (the registration frame must be signed by the manifest
  key). The attacker-CA-with-spoofed-pin bypass is closed.
- **Signature enforcement at routing** — senders registered with a public key
  must send signed frames (`EACP_ERR_SIGNATURE_INVALID` otherwise), and
  replayed (sender, tx) transactions are refused with
  `EACP_ERR_REPLAY_DETECTED`.
- **Signing x compression is one contract** — `FLAG_COMPRESSED` (an encoding
  bit, not an authenticated one) is excluded from `get_signed_bytes()`, so
  legitimate signed frames survive compression while payload tampering is
  still rejected; plus a combined sign/compress/verify test.
- **Bounded decompression** — compressed payloads are capped against both the
  wire size and the decompressed size (16:1 ratio), closing the zlib-bomb
  amplification without breaking the conformance vectors.
- **TLS client defaults verify** — `create_client_ssl_context()` requires the
  server certificate unless `verify_server=False` is passed explicitly.

### Added
- **Benchmark harness** — `bench/relay_bench.py` measures Python vs Rust
  relays on identical signed wire workloads: RTT p50/p95/p99, sequential and
  pipelined throughput, RSS per registered connection, and stalled-consumer
  isolation + recovery (fresh relay per scenario). First calibration run and
  honest reading notes (including the observed Rust pipelined regression and
  the Ed25519 verification asymmetry) in `docs/benchmarks.md`.
- **Request registry with real cancellation** — in-flight handlers are tracked
  per (sender, tx); caller timeouts emit `PULSE_CANCEL` that actually cancels
  the handler coroutine, refunds the escrow and answers best-effort; disconnect
  cancels everything; handler concurrency is bounded by a semaphore
  (`max_concurrent_handlers`).
- **Pre-dispatch budget estimate** — `PayloadTokenMeter.estimate_request()`
  refuses a request whose payload alone exceeds the envelope BEFORE the
  handler runs (post-hoc measurement alone cannot prevent the spend).
- **Ledger durability** — startup recovery with full chain verification
  (`LedgerIntegrityError` on corruption instead of silently starting a fresh
  chain), durable appends (flush per record, periodic fsync), size-based
  rotation, `close()` barrier wired into relay stop.
- **Trace propagation** — `send()` puts the W3C `_trace` header on the wire
  (it previously created a context that never travelled), and the relay logs
  routing spans with the trace id.
- **Mesh lifecycle** — origin-bound route announcements (a frame claiming an
  unconfigured `origin_peer` is ignored), peer redial
  (`MeshRoutingTable.ensure_links`), `close_all()`, and a REAL two-relay
  request/reply end-to-end test (the old test never sent a cross-relay frame).
- **CI interop job** — builds the Rust relay, runs the full Python suite with
  the binary present, and FAILS if any test is skipped.
- **Regression battery** — `tests/test_protocol_hardening.py` (28 tests)
  encodes every reproduced finding from the external analysis.
- **Rust relay parity subset** — declared-grants gate on `MsgSend`, per-
  transaction deadlock edges, explicit `EACP_ERR_QUEUE_FULL` refusal (was a
  silent drop), error codes 12/13.

### Fixed
- **Exhausted budget is no longer unlimited** — `create_downstream_constraints`
  raises `BudgetError` when the parent envelope is spent; `token_budget == 0`
  keeps meaning "explicitly unconstrained" only.
- **`create_downstream_constraints(token_budget=...)`** can no longer replace
  an unlimited child with `None`.
- **Relay `stop()` hang** — peer connections are closed before the listener's
  `wait_closed()`; previously a meshed relay blocked forever on shutdown.
- **Offline-queue refusal releases the deadlock dependency** (a refused frame
  no longer leaves the sender stuck waiting).
- **Docs claims narrowed to mechanisms** — non-repudiation/SOC 2/ISO 27001
  wording, "deterministic cancellation", "lock-free", "zero-copy" and
  unbenchmarked p99/RAM figures were replaced with what the code actually
  enforces; mesh/QoS/DTN labeled experimental (README + ARCHITECTURE §8.3).

### Changed
- **Relay forward path: verbatim wire bytes, zero re-encode** - `EacpFrame.unpack()`
  now caches the exact wire bytes the frame was parsed from (`_wire`) and `pack()`
  returns them verbatim for unmodified frames. The Python relay's per-frame cost
  drops from a full JSON re-encode of the payload slots (~158 µs for a 668 B frame)
  to a plain copy (~65 µs, remaining cost is the parse that routing/verification
  needs). `__setattr__` clears the cache on any field mutation, so tampered frames
  re-encode and diverge exactly as before (signature rejection preserved).
  Conformance vectors (including byte-exact re-encode and Ed25519 check) still pass.

## [1.2.1] - 2026-10-26

### Changed
- **Verify path: zero re-encode per signed frame** - `EacpFrame.get_signed_bytes()`
  derives the signed subset by slicing `raw_payload` on parsed frames instead of
  re-serializing slots with JSON on every relay verification. The signed content
  keeps the conformance-locked shape (header + slots WITHOUT the 16-byte length
  block; the block only feeds the header `payload_len`).
- **Tamper detection preserved** - any post-construction field mutation clears the
  parsed-wire cache via `__setattr__`, so mutated frames fall back to re-encoding
  and are rejected (unit test + negative conformance vector stay correct;
  fast path == contract byte-for-byte at 79 bytes).
- **DTN duplicate-suppression ring** evicts with `deque.popleft()` (O(1)) instead
  of `list.pop(0)`, which shifted up to 5001 entries per bundle past capacity.
- **Native relay release profile** - `[profile.release]` with thin LTO and
  `codegen-units = 1` for the standalone `crates/eacp-relay` crate (release
  build ~15.9s; binary smoke-tested).

## [1.2.0] - 2026-10-23

### Added
- **Native Rust Relay Daemon (`crates/eacp-relay`)**:
  - High-performance, multi-core non-blocking microkernel relay built with Tokio.
  - Zero-copy framing for 48-byte headers and 4-slot payloads with zero GC jitter.
  - Native QNX-style circular deadlock cycle detection graph in Rust (`deadlock.rs`).
  - Standalone 2.2 MB release binary (< 15 MB RAM footprint under heavy concurrency).
  - Cross-language integration test `tests/test_rust_relay.py` validating Python agent rendezvous over the Rust daemon.
- **Tactical & Military Resiliency Layer**:
  - **OMG DDS / C4I Quality of Service (`qos.py`)**: Requested vs Offered (RxO) contract compatibility checks, exclusive ownership arbitration with automatic heartbeat liveliness failover (`OwnershipArbitrator`), and deadline violation monitoring (`DeadlineMonitor`).
  - **RFC 9171 / DARPA DTN Bundle Protocol Custody Transfer (`dtn.py`)**: Store-and-forward custody transfer (`CustodyStore`), duplicate suppression rings, hop limit guards, and storage capacity limits across partitioned edge links.
- **Test Suite Expansion**:
  - Suite expanded to 56 unit and end-to-end integration tests.
  - CI updated with native Rust compilation and cargo test job.

## [1.1.0] - 2026-10-23

### Added
- **Token Budget Enforcement (`budget.py`)** — kernel-resource accounting model:
  - Escrow/settle/refund ledger: budget is reserved *before* any handler runs (fail-closed), settled against a pluggable `TokenMeter` after, and refunded in full on failure (CleanupStack discipline).
  - `ledger_capacity` guard makes concurrent budget oversubscription structurally impossible (anti budget-inflation).
  - Hard overflow with `EACP_ERR_TOKEN_OVERFLOW` — no partial overdraw; incremental metering via `RSessionBase.spend_tokens()`.
  - Cascade accounting: replies carry the *remaining* budget in slot 2; `create_downstream_constraints(frame, tokens_used=...)` propagates the shrinking envelope with decremented hops.
- `test_budget.py`: 12 tests (ledger semantics, meter, cascade, 5 end-to-end over the relay).

## [1.0.0] - 2026-10-23

### Added
- **Wire format:** 48-byte big-endian binary header + 4 structured slots (`TIpcArgs`), transparent zlib compression for payloads > 1 KB, 16 MB DoS payload guard.
- **Identity:** Ed25519 keypairs, deterministic 64-bit Agent-PIN (`First8Bytes(SHA-256(PK))`), frame signing/verification.
- **PlatSec:** 64-bit capability bitmask, verification invariant `Granted & Required == Required`, strict fail-closed mode.
- **Enterprise PKI:** `EnterpriseCA` + `SignedManifest` attestation; relay rejects unregistered rogue keys.
- **Concurrency:** Deterministic `ActiveScheduler`/`CActive`/`CleanupStack` with automatic rollback on leave; `AsyncActive` bridge for asyncio.
- **Rendezvous:** QNX `MsgSend`/`MsgReceive`/`MsgReply`/`MsgPulse` semantics with circular-deadlock detection and cleanup-on-timeout via `PULSE_CANCEL`.
- **Relay:** PIN routing table, offline push queues with TTL, heartbeat keepalive + dead-route reaper, TCP and Unix Domain Socket transports, `python3 -m eacp.relay` CLI.
- **Enterprise hardening:**
  - AES-256-GCM payload confidentiality + mTLS/TLS 1.3 contexts.
  - W3C `TraceContext` distributed tracing + Prometheus/OpenMetrics metrics.
  - Multi-relay HA peer mesh (`mesh.py`).
  - Immutable hash-chained audit ledger (SOC2/ISO 27001).
  - `max_depth_hops` enforcement against infinite agent delegation.
- **Tests:** 35-test suite covering wire format, security, scheduler, relay end-to-end, and enterprise pillars.

[1.0.0]: https://github.com/mrschneider/eacp/releases/tag/v1.0.0
