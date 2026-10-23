# EACP: Enterprise Agentic Communication Protocol

**EACP** is a microkernel-grade communication and coordination protocol for enterprise multi-agent systems. It fuses the concurrency and security architectures of **Symbian OS (EKA2)** with the synchronous rendezvous and push-relay architecture of **BlackBerry OS / QNX Neutrino**.

---

## Key Pillars

1. **Deterministic Concurrency (Symbian Active Objects):** Single-thread cooperative event loop per agent eliminating thread sprawl, race conditions, and uncontrolled token usage.
2. **Platform Security (Symbian PlatSec):** 64-bit capability bitmask validated at the protocol frame layer before any action or tool executes.
3. **Synchronous Rendezvous (QNX Neutrino IPC):** `MsgSend` / `MsgReceive` / `MsgReply` protocol lifecycle with built-in deadlock cycle detection.
4. **Agent-PIN Cryptographic Addressing (BlackBerry BES):** Global 64-bit cryptographic addressing independent of IP/DNS, routed transparently across cloud and edge topologies via the EACP-Relay.

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
│       ├── frame.py         # 32-byte binary header & slot serializer
│       ├── security.py      # Ed25519 key management & PlatSec capability gates
│       ├── scheduler.py     # Symbian ActiveScheduler & CleanupStack
│       ├── primitives.py    # QNX rendezvous primitives (MsgSend, MsgReceive, MsgReply, MsgPulse)
│       ├── relay.py         # Push relay daemon & routing table
│       └── client.py        # Agent RSessionBase client wrapper
└── tests/
    ├── test_frame.py        # Binary wire serialization tests
    ├── test_security.py     # PlatSec & capability verification tests
    ├── test_scheduler.py    # ActiveScheduler & cleanup stack tests
    └── test_relay.py        # End-to-end multi-agent IPC rendezvous tests
```

---

## Quickstart

Run test suite:
```bash
python3 -m unittest discover tests -v
```
