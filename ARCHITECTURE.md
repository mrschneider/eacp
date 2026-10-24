# EACP (Enterprise Agentic Communication Protocol)
## Architectural Specification & Protocol Reference
**Version:** 1.0.0  
**Status:** Canonical Reference Specification  
**Authors:** Architecture Team / Infrastructure Operations  

---

## 1. Executive Summary & Design Rationale

### 1.1 The Multi-Agent Coordination Breakdown
Modern multi-agent architectures (CrewAI, AutoGen, LangGraph, Swarm) suffer from architectural flaws originating from treating agent communication as unstructured conversational turns over plain HTTP/JSON:
1. **Unbounded Concurrency & Thread Sprawl:** Spawning independent asynchronous workers without strict scheduling leads to memory exhaustion and non-deterministic context explosion.
2. **Missing Capability Gates:** Tools and actions are executed with ambient authority; prompt injection can compromise agents laterally without protocol-level permission enforcement.
3. **Absence of Backpressure & Rendezvous:** Asynchronous chat buffers cause hallucination cascades, race conditions, and uncontrolled token consumption.
4. **Fragile Network Addressing:** Agent discovery bound to transient IP addresses or DNS names breaks across hybrid clusters, containers, and edge topologies.

### 1.2 The Microkernel Pedigree
EACP solves multi-agent coordination by importing proven primitives from two battle-tested mobile/embedded microkernel operating systems:
* **Symbian OS (EKA2):**
  * *Active Objects & Active Scheduler:* Non-preemptive, cooperative FSM concurrency within a single thread. Eliminates locking contention and guarantees deterministic cancellation.
  * *Client-Server Architecture (`RMessage2` / `RSessionBase`):* Strict IPC message slots (`TIpcArgs`) separating verb, arguments, constraints, and context.
  * *Platform Security (PlatSec):* Fine-grained, bitmask-enforced capabilities required for any IPC dispatch.
  * *CleanupStack & Two-Phase Construction:* Automatic resource recovery and state rollback upon execution failure.
* **BlackBerry OS & QNX Neutrino:**
  * *Synchronous Rendezvous (`MsgSend / MsgReceive / MsgReply`):* Controlled blocking coordination that eliminates race conditions and enforces strict sequencing.
  * *Pulses:* Ultra-lightweight, non-blocking 8-byte out-of-band signals for cancellations and heartbeats.
  * *PIN-based Routing & Enterprise Push Relay (BES/MDS):* Addressing bound to cryptographic agent identities (Agent-PIN), routing messages transparently across heterogeneous clouds, on-prem nodes, and edge devices.

---

## 2. Layered Protocol Architecture

EACP is divided into five formal layers:

```
+-------------------------------------------------------------------------+
| Layer 4: Application & Agentic Task Ledger                              |
|   - Task decomposition, token budgeting, prompt state, tool registry   |
+-------------------------------------------------------------------------+
| Layer 3: EACP Concurrency Runtime (Symbian ActiveScheduler)             |
|   - CActive objects, TRequestStatus, RunL(), DoCancel(), CleanupStack   |
+-------------------------------------------------------------------------+
| Layer 2: IPC & Platform Security (PlatSec + QNX Rendezvous)             |
|   - RSessionBase, MsgSend, MsgReceive, MsgReply, MsgPulse, Capabilities |
+-------------------------------------------------------------------------+
| Layer 1: Cryptographic Addressing & Push Relay (BlackBerry PIN / BES)   |
|   - Agent-PIN routing table, presence beacons, rendezvous broker        |
+-------------------------------------------------------------------------+
| Layer 0: Abstract Transport                                             |
|   - Unix Domain Sockets (IPC), TCP/mTLS (LAN/VPC), QUIC (WAN/Edge)      |
+-------------------------------------------------------------------------+
```

---

## 3. Identity, Addressing & The Agent-PIN

### 3.1 Cryptographic Identity
Every agent operating under EACP possesses an Ed25519 keypair:
* **Secret Key ($SK_{agent}$):** Used to sign frames and capability claims.
* **Public Key ($PK_{agent}$):** 32-byte public key distributed via the enterprise registry.

### 3.2 Agent-PIN Generation
The **Agent-PIN** is an 8-byte (64-bit) unsigned integer derived deterministically from the public key:
$$\text{Agent-PIN} = \text{First8Bytes}(\text{SHA-256}(PK_{agent}))$$

* Example representation: `0x8F12_A9B4_33C0_11DE`
* Guaranteed collision-resistant within enterprise domain namespaces.
* Independent of physical network location: whether the agent migrates across pods, clouds, or local bare-metal, its PIN remains immutable.

---

## 4. Binary Wire Format Specification

All EACP frames are transmitted in network byte order (big-endian). A frame consists of a fixed **48-byte header** (64-bit aligned) followed by a variable-length **payload** divided into 4 structured slots.

### 4.1 Fixed Header Structure (48 Bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0xEA, 0xCF)   |  Ver (0x01)   |  MsgType (8b) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            OpCode (16b)       |         Flags (16b)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sender PIN (64b)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Target PIN (64b)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Transaction ID / UUID (64b)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Capabilities Mask (64b)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Status / Error Code (32b)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (32b)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Field Definitions:
* **Magic (16 bits):** `0xEA, 0xCF`. Validates protocol frame sync.
* **Version (8 bits):** `0x01` for EACP v1.
* **MsgType (8 bits):**
  * `0x01`: `MSG_SEND` (Synchronous request; sender transitions to `REPLY_BLOCKED`)
  * `0x02`: `MSG_RECEIVE` (Worker poll request)
  * `0x03`: `MSG_REPLY` (Completion of a `MSG_SEND` transaction)
  * `0x04`: `MSG_PULSE` (Non-blocking 8-byte out-of-band notification)
  * `0x05`: `MSG_RELAY_CONTROL` (Heartbeat, route announce, registration)
* **OpCode (16 bits):** Application-level verb or system control code.
* **Flags (16 bits):** Bitwise flags (Urgent, Encrypted, Compressed, Signed).
* **Sender PIN (64 bits):** Originating agent's cryptographic identifier.
* **Target PIN (64 bits):** Destination agent's cryptographic identifier.
* **Transaction ID (64 bits):** Monotonically increasing or random session nonce used for rendezvous pairing.
* **Capabilities Mask (64 bits):** Cryptographically attested capability bitmask attached to this transaction.
* **Status / Error Code (32 bits):** Execution return status code (`EacpError`).
* **Payload Length (32 bits):** Total length in bytes of the variable slot payload following the header.

---

### 4.2 Payload Slot Architecture (Symbian `TIpcArgs`)

The payload following the 32-byte header is structured into four explicit slots:

```
+-------------------------------------------------------------------------+
| Slot 0: Verb / Action Identifier (String / Token ID)                   |
+-------------------------------------------------------------------------+
| Slot 1: Invocation Data (Arguments / Parameters in CBOR)                |
+-------------------------------------------------------------------------+
| Slot 2: Execution Constraints (Budget, Timeouts, Hops)                  |
|   - token_budget: uint32                                                |
|   - timeout_ms: uint32                                                  |
|   - max_depth_hops: uint8                                               |
+-------------------------------------------------------------------------+
| Slot 3: Cryptographic Envelope & Context Metadata                       |
|   - signature: Ed25519(Header + Slots[0..2])                            |
|   - session_handle: uint32                                              |
+-------------------------------------------------------------------------+
```

---

## 5. Platform Security (EACP-PlatSec)

EACP strictly enforces capability boundaries at the protocol decoding layer before any LLM inference or tool invocation can take place.

### 5.1 Capability Bitmask Definitions (64-bit)

| Bit Index | Constant Name | Description |
| :--- | :--- | :--- |
| `0` | `CAP_NET_RAW` | Direct network socket I/O (external APIs, HTTP, raw TCP) |
| `1` | `CAP_DISK_READ` | Read access to host or mounted storage |
| `2` | `CAP_DISK_WRITE` | Write/modification access to host storage |
| `3` | `CAP_TOOL_EXEC` | Spawning local processes, shell commands, or binaries |
| `4` | `CAP_AGENT_SPAWN` | Authorization to bootstrap and register child agents |
| `5` | `CAP_CROSS_CALL` | Calling agents across enterprise security domains |
| `6` | `CAP_SYS_ADMIN` | Modifying system state, systemd units, or containers |
| `7` | `CAP_PII_ACCESS` | Reading or processing data tagged as confidential / PII |
| `8` | `CAP_PERSISTENCE`| Writing to long-term memory or ledger stores |
| `9` | `CAP_CODE_GEN` | Generating and executing arbitrary executable code |
| `10..63` | `RESERVED` | Enterprise-specific capability slots |

### 5.2 Verification Invariant
When an agent receives an EACP frame demanding action $A$, the dispatcher calculates:
```
Granted = Frame.CapabilitiesMask & Manifest.AllowedCapabilities
Required = ToolRegistry[A].RequiredCapabilities

If (Granted & Required) != Required => EACP_ERR_CAPABILITY_DENIED
```

The rejection occurs immediately in the L2 runtime. The underlying LLM is never invoked, completely mitigating prompt-injection-driven privilege escalation.

---

## 6. Concurrency Runtime: The Active Scheduler

To prevent thread bloat and race conditions, EACP agent engines run on a single-thread cooperative event loop modeled on Symbian EKA2.

### 6.1 State Machine & Core Classes

```
+-------------------------------------------------------------------------+
|                             ActiveScheduler                             |
|                                                                         |
|  +---------------------+   +---------------------+   +---------------+  |
|  | CActive (ToolExec)  |   | CActive (Inference) |   | CActive (IPC) |  |
|  +---------------------+   +---------------------+   +---------------+  |
|             \                         |                        /        |
|              +------------------------+-----------------------+         |
|                                       |                                 |
|                           [ Wait for Request Event ]                    |
|                                       |                                 |
|                                 v (Completes)                           |
|                                  RunL()                                 |
+-------------------------------------------------------------------------+
```

* **`TRequestStatus`:** Asynchronous completion status (`KRequestPending`, `KErrNone`, `KErrCancel`, `KErrOverflow`).
* **`CActive`:** Base active object class:
  * `SetActive()`: Marks status as pending and registers with scheduler.
  * `RunL()`: Callback executed when event completes.
  * `Cancel()` / `DoCancel()`: Aborts ongoing asynchronous operation cleanly.
* **`CleanupStack`:** Stack-based guard mechanism. Any allocated resource (open file descriptor, model context slice, network socket) is pushed onto the `CleanupStack`. If `RunL()` leaves (raises an exception), `CleanupStack::PopAndDestroy()` cleans all state without leaking memory.

---

## 7. Messaging Primitives & Rendezvous Semantics

### 7.1 Synchronous Rendezvous (`MsgSend / MsgReceive / MsgReply`)
Emulating QNX Neutrino microkernel IPC:

1. **Client emits `MsgSend`:**
   * Frame sent to Relay target.
   * Client active object enters `STATE_REPLY_BLOCKED`.
   * Client thread halts further generation of tasks.
2. **Server processes via `MsgReceive`:**
   * Server dequeues frame, checks PlatSec capabilities, and invokes `RunL()`.
3. **Server returns `MsgReply`:**
   * Result delivered back to Client.
   * Client unblocks, transitions to `STATE_IDLE`, and receives data.
4. **Deadlock Detection:**
   * The Relay tracks active `Send-Blocked` chains ($A \to B \to C$). If $C$ attempts `MsgSend(A)`, the Relay immediately returns `EACP_ERR_DEADLOCK_DETECTED` to $C$, preventing circular deadlocks.

### 7.2 Non-Blocking Pulses (`MsgPulse`)
For immediate interrupts that cannot wait for rendezvous:
* Structure: Exactly 8 bytes payload (`Code: uint16`, `Value: uint48`).
* Non-blocking: Sender never enters reply-blocked state.
* Primary use case: `PULSE_CANCEL` (aborts current reasoning step) and `PULSE_HEARTBEAT`.

---

## 8. Network Relay & Push Architecture (EACP-Relay)

The **EACP-Relay** functions analogously to the BlackBerry Enterprise Server (BES):

```
[Agent A (AWS Cloud)]       [Agent B (Node .70)]        [Agent C (Edge Node)]
       |                            |                            |
       | QUIC / mTLS                | Unix Socket                | QUIC / mTLS
       v                            v                            v
+-------------------------------------------------------------------------+
|                              EACP-Relay                                 |
|                                                                         |
|  [PIN Routing Table]   [Rendezvous Registry]   [Deadlock Graph Engine]  |
|   0x8F12... -> AWS           0x70A1... -> Local          0x33B9... -> Edge|
+-------------------------------------------------------------------------+
```

### 8.1 Responsibilities
* **Presence & Routing:** Maintains an in-memory lookup table of active Agent-PINs and transport connections.
* **Offline Buffering (Push):** If a target agent temporarily drops connection (e.g. edge pod restart), non-urgent messages are held in a bounded push queue until reconnection or TTL expiration.
* **Transit PlatSec Check:** The Relay validates frame digital signatures before routing, dropping spoofed packets at the boundary.

### 8.2 Native Rust Implementation (`crates/eacp-relay`)
To guarantee sub-millisecond p99 latency without garbage-collection jitter (essential for strict QoS deadlines), the EACP-Relay provides a high-performance native implementation in Rust (`crates/eacp-relay`):
* **Tokio Async Engine:** High-concurrency non-blocking event loop across multi-core systems.
* **Zero-Copy Parsing:** Big-endian 48-byte header and slot boundaries parsed directly off socket buffers without intermediate heap copies.
* **Deadlock Graph in Rust:** Cycle-detection graph with instant lock-free lookups and automatic dependency unwinding on agent disconnect or cancel pulse.
* **Small Footprint:** Single ~2.2 MB binary consuming < 15 MB RAM under tens of thousands of concurrent agent sessions.


---

## 9. Error Codes & Protocol Constants

| Code | Hex | Symbol | Meaning |
| :--- | :--- | :--- | :--- |
| `0` | `0x0000` | `EACP_SUCCESS` | Operation completed successfully |
| `1` | `0x0001` | `EACP_ERR_INVALID_MAGIC` | Frame sync magic bytes mismatch |
| `2` | `0x0002` | `EACP_ERR_UNKNOWN_PIN` | Target Agent-PIN not registered |
| `3` | `0x0003` | `EACP_ERR_CAPABILITY_DENIED` | Sender lacks required PlatSec capability |
| `4` | `0x0004` | `EACP_ERR_DEADLOCK_DETECTED` | Circular `MsgSend` dependency detected |
| `5` | `0x0005` | `EACP_ERR_TIMEOUT` | Rendezvous reply timeout exceeded |
| `6` | `0x0006` | `EACP_ERR_CANCELLED` | Operation cancelled via `MsgPulse` |
| `7` | `0x0007` | `EACP_ERR_TOKEN_OVERFLOW` | Execution exceeded token budget constraint |
| `8` | `0x0008` | `EACP_ERR_SIGNATURE_INVALID` | Ed25519 signature verification failure |

---

## 10. Tactical & Military Resiliency Layer

### 10.1 OMG DDS / C4I Quality of Service (QoS) Contract Model
EACP adopts the contractual Requested vs. Offered (RxO) quality-of-service model from military C4I command systems:
* **RxO Contract Evaluator (`QosContractEvaluator`):** Ensures a consumer agent's requested reliability, durability, deadline, and latency constraints can only bind to a producer offering equal or strictly stronger contractual guarantees.
* **Exclusive Ownership Arbitration (`OwnershipArbitrator`):** Provides deterministic, preemption-capable leadership arbitration for critical execution roles or topics based on assigned ownership strength (0..1000). If the active primary agent misses its liveliness heartbeat lease window, ownership automatically fails over to the next highest-strength live candidate.
* **Deadline Monitoring (`DeadlineMonitor`):** Tracks end-to-end rendezvous and asynchronous processing turnaround against contractual latency budgets, raising actionable alerts upon deadline breach.

### 10.2 RFC 9171 / DARPA DTN Bundle Protocol Custody Transfer
To ensure uninterrupted coordination across partitioned, contested, or intermittent edge links:
* **Custody Transfer Handover (`CustodyStore`):** Uses RFC 9171 store-and-forward semantics with atomic custody transfer (`CUSTODY_ACCEPTED`). An upstream agent retains message custody until downstream explicitly acknowledges custody responsibility.
* **Resiliency Controls:** Bounded buffer memory accounting, duplicate suppression rings, hop limit guards against routing cycles, and proactive TTL expiration pruning prevent message loss and memory starvation across severed WAN/edge mesh topologies.

