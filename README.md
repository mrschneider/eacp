# EACP: Enterprise Agentic Communication Protocol

[![CI](https://github.com/mrschneider/eacp/actions/workflows/ci.yml/badge.svg)](https://github.com/mrschneider/eacp/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Code Style](https://img.shields.io/badge/wire%20format-48%20byte%20binary-orange)

**EACP** is a microkernel-grade communication and coordination protocol for enterprise multi-agent systems. It fuses the concurrency and security architectures of **Symbian OS (EKA2)** with the synchronous rendezvous and push-relay architecture of **BlackBerry OS / QNX Neutrino**.

---

## What is EACP and how does it work?

EACP replaces the fragile "agents calling each other over HTTP/JSON" pattern with a battle-tested operating-system discipline: agents do not talk to each other directly — they talk to a **kernel-like relay** through synchronous, permission-checked rendezvous.

![EACP Architecture — how agents communicate](docs/eacp-architecture.png)

The lifecycle of a single call:

1. **`MsgSend`** — Agent A (caller) sends a synchronous request addressed to Agent B's cryptographic **Agent-PIN** (a 64-bit identity derived from its Ed25519 public key — never an IP or DNS name, so agents are migratable across cloud/edge without breaking addressing). The caller blocks (rendezvous) until replied.
2. **Route by PIN** — the **EACP-Relay** looks up the target in its PIN routing table, verifies the frame's Ed25519 signature in transit, and runs deadlock cycle detection (`A→B→C→A` is rejected before it can hang the mesh). Offline targets get their frames queued with TTL.
3. **Permission check (PlatSec)** — before Agent B runs anything, the 64-bit capability bitmask on the frame is validated against B's signed security manifest. Insufficient capability → **denied**, and no LLM inference or tool is ever invoked — this is what makes prompt-injection privilege escalation structurally impossible.
4. **Run handler** — the handler executes under B's cooperative `ActiveScheduler`, with its token budget escrowed upfront (over-budget work is refused before spending compute) and a hop guard against infinite delegation.
5. **`MsgReply`** — the result travels back and unblocks the caller; the reply carries the *remaining* token budget so the delegation tree shares one envelope. Every frame is recorded in a hash-chained audit ledger.

**Pulses** (heartbeat + cancel) are 8-byte out-of-band signals flowing outside the rendezvous: they keep routes alive across flaky edge links and cancel in-flight reasoning steps without blocking.

### The message format

Every message is a fixed **48-byte binary header** (magic, version, message type, opcode, flags, sender/target PIN, transaction ID, capability mask, status) followed by four structured slots: **Verb**, **Arguments**, **Constraints** (token budget, timeout, hop limit) and a cryptographic **Envelope** (Ed25519 signature + session handle). Binary, not JSON — deterministic, compact, and verifiable.

### Enterprise capabilities baked in

CA-signed agent registration · TLS/mTLS transport · AES-256-GCM payload encryption · W3C trace context propagation · peer relay routing (multi-cloud/edge HA) · TTL queues + heartbeats · Prometheus metrics · tamper-evident audit ledger. See the hardening table below for module-by-module details.

---

## Key Pillars

1. **Deterministic Concurrency (Symbian Active Objects):** Single-thread cooperative event loop per agent eliminating thread sprawl, race conditions, and uncontrolled token usage.
2. **Platform Security (Symbian PlatSec):** 64-bit capability bitmask validated at the protocol frame layer before any action or tool executes.
3. **Synchronous Rendezvous (QNX Neutrino IPC):** `MsgSend` / `MsgReceive` / `MsgReply` protocol lifecycle with built-in deadlock cycle detection.
4. **Agent-PIN Cryptographic Addressing (BlackBerry BES):** Global 64-bit cryptographic addressing independent of IP/DNS, routed transparently across cloud and edge topologies via the EACP-Relay.

---

## Enterprise-Grade Hardening (v1.0)

| Capability | Module | Description |
|---|---|---|
| Zero-Trust Encryption | `security.py` | AES-256-GCM payload confidentiality + mTLS/TLS 1.3 transport contexts |
| Observability | `telemetry.py` | W3C TraceContext distributed tracing + Prometheus/OpenMetrics exporter |
| Agent PKI | `security.py` | `EnterpriseCA` signs `SignedManifest`s; relay rejects rogue key registration |
| High Availability | `mesh.py` | Multi-Relay peer mesh routing across clouds/AZs/edges (no SPOF) |
| Audit Compliance | `ledger.py` | Append-only SHA-256 chained WAL ledger (SOC2 / ISO 27001, tamper-evident) |
| DoS Protection | `frame.py` | Strict 16 MB payload guard validated before allocation |
| Wire Compression | `frame.py` | Transparent zlib compression of payloads > 1 KB (`FLAG_COMPRESSED`) |
| Keepalive | `relay.py` | `PULSE_HEARTBEAT` presence + dead-route reaper (3x missed → prune) |
| Hop Guard | `client.py` | `max_depth_hops` decremental enforcement prevents infinite agent delegation |
| Token Budget Escrow | `budget.py` | Kernel-style escrow/settle/refund ledger with pluggable `TokenMeter`, ledger capacity and `EACP_ERR_TOKEN_OVERFLOW` |
| Fail-Closed PlatSec | `security.py` | `strict_mode=True` rejects any action not registered in the manifest |
| DDS C4I QoS Contract | `qos.py` | Requested vs Offered (RxO) contract validation + exclusive ownership arbitration with failover |
| DTN Store-and-Forward | `dtn.py` | RFC 9171 / DARPA Bundle Protocol custody transfer, duplicate suppression & hop limits |

---

## Directory Layout

```
.
├── ARCHITECTURE.md          # Canonical Protocol Reference
├── README.md                # Quickstart & Overview
├── pyproject.toml           # Python packaging
├── conformance/             # Cross-language wire-format contract (vectors + verifier)
│   ├── CONFORMANCE.md       # How to implement EACP in any language
│   ├── generate.py          # Deterministic vector generator
│   ├── verify.py            # Independent strict consumer / self-check
│   └── vectors.json         # Byte-exact ground truth
├── src/
│   └── eacp/
│       ├── __init__.py      # Package export
│       ├── constants.py     # OpCodes, MsgTypes, Capabilities & Error codes
│       ├── frame.py         # 48-byte binary header & slot serializer
│       ├── security.py      # Ed25519 identity, PlatSec gates, Enterprise CA, AES-GCM
│       ├── scheduler.py     # Symbian ActiveScheduler, CActive, CleanupStack, AsyncActive
│       ├── primitives.py    # QNX rendezvous primitives (MsgSend, MsgReceive, MsgReply, MsgPulse)
│       ├── relay.py         # Push relay daemon, deadlock graph, heartbeat reaper, CLI
│       ├── client.py        # Agent RSessionBase client wrapper
│       ├── telemetry.py     # W3C TraceContext + Prometheus metrics
│       ├── ledger.py        # Immutable append-only audit ledger
│       ├── mesh.py          # Multi-relay HA peer mesh routing
│       ├── qos.py           # DDS C4I QoS policies, RxO compatibility & ownership failover
│       ├── dtn.py           # RFC 9171 DTN store-and-forward custody transfer
│       └── __main__.py      # `python3 -m eacp` CLI entry point
└── tests/
    ├── test_frame.py        # Binary wire serialization tests
    ├── test_security.py     # PlatSec & capability verification tests
    ├── test_scheduler.py    # ActiveScheduler & cleanup stack tests
    ├── test_relay.py        # End-to-end multi-agent IPC rendezvous tests
    ├── test_enterprise.py   # Enterprise pillars: encryption, tracing, PKI, mesh, audit
    └── test_tactical.py     # Tactical resiliency: DDS QoS arbitration & DTN custody transfer
```

---

## Quickstart

Run test suite (54 tests):
```bash
python3 -m unittest discover tests -v
```

Run the EACP-Relay daemon:
```bash
# TCP (LAN/VPC/Cloud)
python3 -m eacp.relay --host 0.0.0.0 --port 8990

# Unix Domain Socket (local IPC)
python3 -m eacp.relay --socket /run/eacp.sock

# Tuned for edge devices
python3 -m eacp.relay --max-queue 500 --max-payload-mb 4 --heartbeat-timeout 60
```

Minimal agent example:
```python
import asyncio
from eacp import RSessionBase, MsgSend, Capability

async def main():
    relay_port = 8990

    server = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
    server.register_handler("query", lambda f: {"result": 42},
                            required_caps=Capability.CAP_DISK_READ)
    await server.connect(port=relay_port)

    client = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
    await client.connect(port=relay_port)

    reply = await MsgSend(client, target_pin=server.pin, verb="query",
                          data={"sql": "SELECT 1"})
    print(reply.data)  # {"result": 42}

    await client.close()
    await server.close()

asyncio.run(main())
```

---

## Design Guarantees

- **Prompt injection cannot escalate privileges:** PlatSec validation happens at the L2 protocol layer, before any LLM inference or tool invocation.
- **Circular deadlocks are impossible:** the relay's `DeadlockGraph` rejects `MsgSend` cycles (`A→B→C→A`) with `EACP_ERR_DEADLOCK_DETECTED`.
- **No zombie routes:** offline push queues respect per-message TTL; heartbeat timeouts prune dead transports.
- **Deterministic rollback:** `CleanupStack` guarantees resource recovery when `RunL()` leaves.
- **Non-repudiation:** every routed frame produces a hash-chained audit ledger entry.
- **Language-portable by construction:** the wire contract is pinned by the `conformance/` suite — byte-exact vectors that any Scala/Rust/Go implementation must satisfy to join the mesh (and that CI enforces on every push).
