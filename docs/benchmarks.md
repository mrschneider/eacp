# Relay benchmarks — Python reference vs Rust candidate

**Harness:** `bench/relay_bench.py` · **Date:** 2026-10-27 · **Host:**
Intel N100 (4C), 30 GiB RAM, Linux 7.0.0-34, loopback TCP ·
**Releases:** Python relay from this tree; Rust relay
`cargo build --release` (thin LTO).

## How to run

```bash
cargo build --release --manifest-path crates/eacp-relay/Cargo.toml
python3 bench/relay_bench.py --requests 300 --conns 100 --flood 600
```

Same client stack (Python `RSessionBase`) and byte-identical signed frames
drive both relays. Fresh relay process per scenario group so memory is
attributed to registrations only. Skips: **cross-relay/mesh latency — not
comparable across implementations until the Rust relay has peering
(ARCHITECTURE.md §8.3).**

## Results (single run)

| metric | python relay | rust relay |
|---|---|---|
| RTT p50 (ms) | 1.28 | 0.59 |
| RTT p95 (ms) | 3.20 | 1.13 |
| RTT p99 (ms) | 5.72 | 1.54 |
| RTT mean / max (ms) | 1.52 / 8.58 | 0.68 / 3.05 |
| sequential (req/s) | 936 | 1638 |
| pipelined conc=32 (req/s) | 2288 | 579 |
| relay RSS baseline (MiB) | 33.2 | 4.0 |
| RSS per registered conn (KiB) | 24.7 | 3.8 |
| healthy p50 during stall (ms) | 2.90 | 0.50 |
| healthy p99 during stall (ms) | 5.46 | 1.26 |
| stalled-consumer drain (s) | 0.80 | 0.80 |
| frames sent / drained | 600 / 600 | 600 / 600 |

## Reading the numbers

- **Security asymmetry:** the wire is byte-identical, but the Python relay
  verifies Ed25519 signatures per frame and the Rust relay does not verify
  yet (§8.3). Rust's RTT advantage is the upper bound of that gap —
  qualification must re-measure after signature verification lands.
- **Stalled consumer:** a registered target stops reading; 600 signed
  frames are fired through the relay at it. Both relays keep an unrelated
  client healthy (p99 5.5 ms / 1.3 ms — no contagion) and both deliver
  **all 600 frames** once the target resumes (recovery ≈ drain window).
  The python healthy-p99 tail is its slower burst processing, not a stall
  leak: p50 stays bounded.
- **Open observation:** the Rust relay is *slower* pipelined (conc=32,
  579 req/s) than sequential (1638 req/s), reproducible across runs —
  while Python scales 936 → 2288. This inverts the expected concurrency
  gain and is tracked as an investigation item for the Rust qualification
  cycle; do not cite rust pipelined numbers as a strength.
- **Variance:** single run on a shared host; python RTT p50 observed
  between 0.98–1.67 ms across runs of this session. Treat these as
  order-of-magnitude, not SLA figures. No p99 production claim is made
  until a repeatable multi-run harness exists.
- **Baseline RSS:** python relay ~33 MiB idle (interpreter + imports) vs
  ~4 MiB for the static Rust binary; per-connection cost is the more
  actionable figure (24.7 vs 3.8 KiB/conn).

## Not measured (honest gaps)

- Multi-relay/mesh latency and failover (blocked on Rust peering, §8.3).
- Slow-consumer backpressure beyond 600 frames / 420 KB.
- Sustained-load runs, multi-hour memory drift, and cold-start time —
  single-run methodology only; the harness is the tool, the numbers above
  are a first calibration, not a certification.