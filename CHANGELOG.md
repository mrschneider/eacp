# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
