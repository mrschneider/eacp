# EACP: Enterprise Agentic Communication Protocol

**EACP** is a microkernel-grade communication and coordination protocol for enterprise multi-agent systems. It fuses the concurrency and security architectures of **Symbian OS (EKA2)** with the synchronous rendezvous and push-relay architecture of **BlackBerry OS / QNX Neutrino**.

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
| Fail-Closed PlatSec | `security.py` | `strict_mode=True` rejects any action not registered in the manifest |

---

## Directory Layout

```
.
├── ARCHITECTURE.md          # Canonical Protocol Reference
├── README.md                # Quickstart & Overview
├── pyproject.toml           # Python packaging
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
│       └── __main__.py      # `python3 -m eacp` CLI entry point
└── tests/
    ├── test_frame.py        # Binary wire serialization tests
    ├── test_security.py     # PlatSec & capability verification tests
    ├── test_scheduler.py    # ActiveScheduler & cleanup stack tests
    ├── test_relay.py        # End-to-end multi-agent IPC rendezvous tests
    └── test_enterprise.py   # Enterprise pillars: encryption, tracing, PKI, mesh, audit
```

---

## Quickstart

Run test suite (35 tests):
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
