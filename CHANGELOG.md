# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Concurrency:** Symbian `ActiveScheduler`/`CActive`/`CleanupStack` with automatic rollback on leave; `AsyncActive` bridge for asyncio.
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
