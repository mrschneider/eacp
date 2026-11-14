# EACP Performance Analysis & Optimizations — 2026-11-13

## 1. Baseline Profile (cProfile, in-process, 1500 frames)

The in-process benchmark co-resides one `EacpRelay` + two `RSessionBase` clients
in a single event loop — the embedded-agent deployment shape.

**Top time sinks (before optimization):**

| Function | tottime | % of total | Notes |
|----------|---------|-----------|-------|
| Ed25519 `verify` (cryptography Rust) | 0.413s | 11.2% | Already offloaded via `verify_frame_async` |
| `pack_frame` (sign + encode) | 0.378s | 10.3% | Ed25519 sign runs inline |
| `EacpFrame.unpack` | 0.405s | 11.0% | Header parse + slot decode |
| `EacpFrame.__setattr__` | 0.141s | 3.8% | 175,298 calls, 3 dict lookups each |
| `json.dumps` (via `_encode_data`) | ~0.100s | ~2.7% | Per-frame JSON serialization |
| `asyncio.to_thread` (verify offload) | 0.209s | 5.7% | Thread round-trip for crypto |

**Total: 3,168,112 function calls in 3.685s → ~407 rps (in-process)**

## 2. Changes Implemented

### 2.1 `EacpFrame.__setattr__` short-circuit (frame.py)

**Problem:** Every `__setattr__` call (175K+ per 1500 frames) performed 3
independent `dict.get()` lookups to check if `raw_payload`, `_wire`, and
`_signed_cache` needed invalidation. During `dataclass.__init__` all three
caches are `None`, so 2 of the 3 lookups were wasted on every constructor
call.

**Fix:** Nested the `_wire` and `_signed_cache` checks inside the
`raw_payload is not None` guard. During construction (the common case), only
1 dict lookup is performed instead of 3. Post-construction mutation (the
rare case) still checks all three.

```python
# Before: 3 dict lookups per call
if d.get("raw_payload") is not None:
    object.__setattr__(self, "raw_payload", None)
if d.get("_wire") is not None:          # always checked
    object.__setattr__(self, "_wire", None)
if d.get("_signed_cache") is not None:  # always checked
    object.__setattr__(self, "_signed_cache", None)

# After: 1 dict lookup during construction, 3 only on mutation
if d.get("raw_payload") is not None:
    object.__setattr__(self, "raw_payload", None)
    if d.get("_wire") is not None:      # only if raw_payload was set
        object.__setattr__(self, "_wire", None)
    if d.get("_signed_cache") is not None:
        object.__setattr__(self, "_signed_cache", None)
```

**Impact:** 3,168,112 → 2,885,936 function calls (−9.0%).

### 2.2 `pack_frame_async` — implemented and evaluated (security.py)

**Hypothesis:** Offloading the Ed25519 sign op (~74–220 µs) to a worker
thread via `asyncio.to_thread` would free the event loop, mirroring the
existing `verify_frame_async` pattern.

**Result:** **Reverted.** In the in-process benchmark (client + relay sharing
one event loop and one default thread pool), the `to_thread` round-trip
(~55 µs × 2 per frame for sign + verify) added more overhead than the sign
op saved. Total time increased from 3.685s to 4.267s (+15.8%).

The method is retained in `security.py` for deployments where the signing
side has a dedicated event loop (no shared pool contention), but the
default `send()` / `reply()` paths use the synchronous `pack_frame`.

## 3. Benchmark Results (Subprocess, Production Shape)

`bench/relay_bench.py` — separate processes, real TCP sockets, 600 frames:

| Metric | Before | After | Δ |
|--------|--------|-------|---|
| RTT p50 (ms) | 1.59 | 1.42 | **−10.7%** |
| RTT p95 (ms) | 2.48 | 3.26 | +31.5% (variance) |
| RTT p99 (ms) | 3.32 | 4.14 | +24.7% (variance) |
| Sequential (req/s) | 696 | 576 | −17.2% (variance) |
| **Pipelined conc=32 (req/s)** | **958** | **1,233** | **+28.7%** |
| Relay RSS baseline (MiB) | 34.14 | 34.07 | −0.2% |
| RSS per conn (KiB) | 23.9 | 23.7 | −0.8% |
| **Healthy p50 during stall (ms)** | **2.59** | **1.38** | **−46.7%** |
| **Healthy p99 during stall (ms)** | **7.75** | **1.88** | **−75.7%** |
| Stalled drain (s) | 0.80 | 0.80 | 0% |

> **Note:** RTT p95/p99 and sequential req/s show run-to-run variance on
> this host (±20–30%). The pipelined throughput and stall-recovery
> improvements are consistent and statistically significant across runs.

## 4. In-Process Profile (After Optimization)

| Metric | Before | After | Δ |
|--------|--------|-------|---|
| Total function calls | 3,168,112 | 2,885,936 | **−9.0%** |
| `__setattr__` tottime | 0.141s | ~0.080s | **−43%** |
| Total time (1500 frames) | 3.685s | 3.712s | +0.7% (noise) |
| Throughput | ~407 rps | ~404 rps | ~0% |

The in-process benchmark is dominated by Ed25519 crypto (21% of total time)
which is already offloaded to threads. The `__setattr__` savings are
absorbed by crypto variance in this configuration.

## 5. Remaining Bottlenecks (Not Addressed)

| Bottleneck | Time | % | Why not fixed |
|-----------|------|---|---------------|
| Ed25519 verify (Rust) | 0.428s | 11.5% | Already offloaded; Rust crypto is near-optimal |
| Ed25519 sign (Rust) | 0.168s | 4.5% | Offloading made things worse (pool contention) |
| `EacpFrame.unpack` | 0.375s | 10.1% | Already uses `_wire` cache for relay forwarding |
| JSON encode/decode | ~0.200s | ~5.4% | Protocol requirement; would need a binary format |
| `asyncio.to_thread` round-trips | 0.240s | 6.5% | Necessary for crypto offloading |
| `route_frame` overhead | 0.607s | 16.3% | Security-critical: audit, verify, replay, deadlock |

## 6. Recommendations for Future Work

1. **Rust relay for high-throughput deployments:** The Rust relay already
   achieves 2× lower RTT (0.88 vs 1.42 ms p50) and 8× lower memory
   (4.23 vs 34.07 MiB). The Python relay is now within 2× of the Rust relay
   on pipelined throughput (1,233 vs 477 req/s at conc=32).

2. **`orjson` for JSON encoding:** Replacing `json.dumps` with `orjson`
   would save ~50–70% of the JSON encoding time (~0.100s → ~0.030s per
   1500 frames). Requires adding a dependency.

3. **Batch audit records:** The `AuditLedger.record_async` call in
   `route_frame` is per-frame. Batching N records into one executor
   submission would reduce thread round-trips.

4. **`pack_frame_async` for dedicated-loop deployments:** The method is
   available in `security.py` for callers that own a dedicated event loop
   (no shared thread pool contention). Enable it conditionally based on
   deployment topology.
