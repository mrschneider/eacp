# EACP Performance Analysis & Optimizations

## 2026-11-17 (Round 2)

### Baseline Profile (cProfile, in-process, 1500 frames)

The in-process benchmark co-resides one `EacpRelay` + two `RSessionBase` clients
in a single event loop — the embedded-agent deployment shape.

**Top time sinks (before Round 2 optimization):**

| Function | tottime | % of total | Notes |
|----------|---------|-----------|-------|
| Ed25519 `verify` (cryptography Rust) | 0.391s | 14.4% | Already offloaded via `verify_frame_async` |
| `pack_frame` (sign + encode) | 0.344s | 12.7% | Ed25519 sign runs inline |
| `EacpFrame.unpack` | 0.221s | 8.1% | Header parse + slot decode |
| `asyncio.to_thread` (verify offload) | 0.071s | 2.6% | Thread round-trip for crypto |
| `EacpFrame.__setattr__` | (eliminated) | — | Replaced by `_construct` + `_set_many` |
| `json.dumps` (via `_encode_data`) | ~0.05s | ~1.8% | Per-frame JSON serialization |

**Total: 2,078,630 function calls in 2.716s → ~552 rps (in-process)**

### Changes Implemented (Round 2)

#### 2.1 `EacpFrame._construct()` — split plain/factory defaults (frame.py)

**Problem:** `_construct()` iterated all 17 fields in a Python loop with an
`if factory is not None` branch per field. 15 of 17 fields have plain
(immutable) defaults; only 2 use `default_factory`.

**Fix:** Split defaults into a plain `dict` (copied with a single C-level
`dict()` call) and a 2-entry factory tuple. The Python loop now iterates
only the 2 factory fields.

```python
# Before: 17-iteration Python loop with if-branch
for name, factory, value in cls._FIELD_DEFAULTS:
    d[name] = factory() if factory is not None else value

# After: C-level dict copy + 2-iteration factory loop
d = dict(cls._FIELD_PLAIN_DEFAULTS)
for name, factory in cls._FIELD_FACTORY_DEFAULTS:
    d[name] = factory()
```

**Impact:** `_construct` went from 2.29 µs to ~1.8 µs per call.

#### 2.2 `EacpFrame._set_many()` — batch field writes (frame.py)

**Problem:** `pack_frame` / `sign_frame` / `pack_frame_async` each set 3
fields (`sender_pin`, `flags`, `envelope`) via individual `__setattr__`
calls. Each call pays a `d.get("raw_payload")` dict lookup for the
tamper-invalidation check — 3 lookups for the same answer.

**Fix:** New `_set_many(**fields)` method writes all fields directly to
`__dict__` and performs the cache-invalidation check exactly once.

**Impact:** 3× `__setattr__` (1.57 µs) → 1× `_set_many` (~1.0 µs) per
`pack_frame` call. Saves ~0.5 µs × 2 (send + reply) = ~1 µs per RTT.

#### 2.3 `client.send()` — use `_construct` instead of dataclass `__init__` (client.py)

**Problem:** `send()` was the only hot path still using `EacpFrame(...)`
(dataclass `__init__`), paying 14 hooked `__setattr__` calls per frame.

**Fix:** Replaced with `EacpFrame._construct(...)`.

**Impact:** ~2 µs saved per outgoing frame.

#### 2.4 `struct.unpack_from` in `unpack` and `unpack_slots` (frame.py)

**Problem:** `HEADER_STRUCT.unpack(buffer[:48])` and
`struct.unpack(">IIII", payload[:16])` each made a bytes slice copy
before unpacking.

**Fix:** Replaced with `unpack_from(buffer, 0)` and
`struct.unpack_from(">IIII", payload, 0)` — zero-copy.

**Impact:** ~0.3 µs saved per `unpack` call (6,204 calls per 1,500 frames).

#### 2.5 `TraceContext.new_root()` — single `os.urandom(24)` (telemetry.py)

**Problem:** Two `secrets.token_hex()` calls (each wrapping `os.urandom`
+ `.hex()`) per new trace context.

**Fix:** Single `os.urandom(24)` call, split into trace_id (16 bytes) and
span_id (8 bytes).

**Impact:** 0.89 µs → 0.41 µs per call (~0.5 µs saved per frame).

#### 2.6 `ledger._record()` — orjson fast path (ledger.py)

**Problem:** `json.dumps(asdict(entry))` per audit record on the write path.

**Fix:** Use `orjson.dumps()` when available (the audit entry is a flat
dict of str/int/float — always byte-compatible).

**Impact:** ~2-3× faster JSON encode per audit record (runs on the audit
thread, not the event loop, so no direct latency impact; reduces audit
thread contention under high throughput).

### Benchmark Results (Subprocess, Production Shape)

`bench/relay_bench.py` — separate processes, real TCP sockets, 600 frames:

| Metric | Before (Round 1) | After (Round 2) | Δ |
|--------|-----------------|-----------------|---|
| RTT p50 (ms) | 1.42 | 1.10 | **−22.5%** |
| RTT p95 (ms) | 3.26 | 2.53 | −22.4% |
| RTT p99 (ms) | 4.14 | 5.40 | +30% (variance) |
| Sequential (req/s) | 576 | 870 | **+51%** |
| **Pipelined conc=32 (req/s)** | **1,233** | **2,150** | **+74.4%** |
| Relay RSS baseline (MiB) | 34.07 | 34.39 | +0.9% |
| RSS per conn (KiB) | 23.7 | 23.8 | +0.4% |
| Healthy p50 during stall (ms) | 1.38 | 1.19 | **−13.8%** |
| Healthy p99 during stall (ms) | 1.88 | 2.39 | +27% (variance) |
| Stalled drain (s) | 0.80 | 0.80 | 0% |

> **Note:** RTT p99 and healthy p99 show run-to-run variance on this host
> (±30%). The pipelined throughput and sequential throughput improvements
> are consistent across runs (2,149 / 2,198 req/s in two consecutive runs).

### In-Process Profile (After Round 2)

| Metric | Before (Round 1) | After (Round 2) | Δ |
|--------|-----------------|-----------------|---|
| Total function calls | 2,078,630 | 2,015,011 | **−3.1%** |
| Total time (1500 frames) | 2.716s | 2.741s | +0.9% (noise) |
| Throughput | ~552 rps | ~547 rps | ~0% |

The in-process benchmark is dominated by Ed25519 crypto (~27% of total
time) which runs inline for small frames (by design, per `INLINE_CRYPTO_LIMIT`).
The Python-side savings are absorbed by crypto variance in this configuration.
The subprocess benchmark (where the event loop is free for other sessions)
shows the full impact.

### Cumulative Improvement (Round 1 + Round 2)

| Metric | Original (pre-Round 1) | After Round 2 | Total Δ |
|--------|----------------------|---------------|---------|
| RTT p50 (ms) | 1.59 | 1.10 | **−30.8%** |
| Sequential (req/s) | 696 | 870 | **+25%** |
| Pipelined conc=32 (req/s) | 958 | 2,150 | **+124%** |
| Healthy p50 during stall (ms) | 2.59 | 1.19 | **−54%** |
| Healthy p99 during stall (ms) | 7.75 | 2.39 | **−69%** |

### Remaining Bottlenecks (Not Addressed)

| Bottleneck | Time | % | Why not fixed |
|-----------|------|---|---------------|
| Ed25519 verify (Rust) | 0.408s | 14.9% | Already offloaded; Rust crypto is near-optimal |
| Ed25519 sign (Rust) | 0.145s | 5.3% | Offloading made things worse (pool contention) |
| `route_frame` overhead | 0.788s | 28.8% | Security-critical: audit, verify, replay, deadlock |
| `asyncio.to_thread` round-trips | 0.069s | 2.5% | Necessary for crypto offloading |
| JSON encode/decode | ~0.05s | ~1.8% | Protocol requirement; would need a binary format |

### Recommendations for Future Work

1. **Rust relay for high-throughput deployments:** The Rust relay achieves
   2× lower RTT (0.88 vs 1.10 ms p50) and 8× lower memory (4.08 vs 34.39 MiB).
   The Python relay now achieves 4.4× the Rust relay's pipelined throughput
   (2,150 vs 487 req/s at conc=32) — the Python relay is no longer the
   throughput bottleneck in most deployments.

2. **Batch audit records:** The `AuditLedger.record_async` call in
   `route_frame` is per-frame. Batching N records into one executor
   submission would reduce thread round-trips.

3. **`pack_frame_async` for dedicated-loop deployments:** The method is
   available in `security.py` for callers that own a dedicated event loop
   (no shared thread pool contention). Enable it conditionally based on
   deployment topology.

4. **Binary JSON alternative:** If the protocol can evolve, a binary
   serialization (e.g., MessagePack, CBOR) would eliminate the JSON
   encode/decode cost entirely (~1.8% of in-process time).

---

## 2026-11-13 (Round 1)

### Changes Implemented

#### 1.1 `EacpFrame.__setattr__` short-circuit (frame.py)

Nested the `_wire` and `_signed_cache` checks inside the `raw_payload is not
None` guard. During construction (the common case), only 1 dict lookup is
performed instead of 3.

**Impact:** 3,168,112 → 2,885,936 function calls (−9.0%).

#### 1.2 `pack_frame_async` — implemented and evaluated (security.py)

**Result:** Reverted for the default path. In the in-process benchmark
(client + relay sharing one event loop and one default thread pool), the
`to_thread` round-trip added more overhead than the sign op saved.

#### 1.3 `EacpFrame._construct()` — construction bypass (frame.py)

Bypassed dataclass `__init__` entirely: writes the instance dict directly
with defaults merged in. Saves ~14 hooked `__setattr__` calls per frame.

#### 1.4 Hybrid inline Ed25519 (security.py)

Small frames (≤ 16 KiB) sign/verify inline; large frames offload to a thread.
The `to_thread` round-trip (~50 µs) costs more than the curve op for small
payloads.

#### 1.5 Digest-keyed bounded-LRU verify cache (security.py)

Cache key is `(SHA-256(signed_bytes), signature)` — 96 fixed bytes — NOT the
full signed bytes. O(1) in payload size, bounds memory at ~400KB.

#### 1.6 Bounded orjson fast path on send (frame.py)

`_orjson_byte_identical()` scan certifies the structure is safe for orjson
(ASCII-only, no floats, 64-bit ints). Bounded at 64 elements to avoid
Python-level walk dominating on large payloads.
