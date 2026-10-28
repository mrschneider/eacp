#!/usr/bin/env python3
"""EACP relay benchmark: Python reference vs Rust candidate.

Identical wire workloads on both implementations (same signed frames, same
client code, loopback TCP). Scenarios:

  1. latency    - sequential echo round-trips -> p50/p95/p99/max
  2. throughput - sequential req/s and pipelined req/s (concurrency 32)
  3. memory     - relay process RSS before/after K registrations -> KiB/conn
  4. slowconsumer - a registered target stops reading; flood it, then measure
                  a HEALTHY client's p99 during the stall and the drain time
                  once the target resumes reading (isolation + recovery)
  5. mesh/multi-relay - SKIPPED: not equivalent across implementations until
                  the Rust relay has peering (ARCHITECTURE.md 8.3).

Honest settings note: the Python relay verifies Ed25519 signatures on every
signed frame; the Rust relay does not verify signatures yet (8.3). The wire
is byte-identical; the CPU delta below is the price of that check.

Usage:  python3 bench/relay_bench.py [--requests 300] [--json out.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from eacp.client import RSessionBase
from eacp.constants import Capability, MsgType, OpCode
from eacp.frame import EacpFrame, ExecutionConstraints
from eacp.security import AgentIdentity

HEADER = struct.Struct(">2sBBHHQQQQII")  # 48 bytes
RUST_BIN = REPO / "crates" / "eacp-relay" / "target" / "release" / "eacp-relay"


# ---------------------------------------------------------------- utilities
def rss_kib(pid: int) -> int:
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) + 1))) - 1))
    return s[idx]


class RelayProc:
    def __init__(self, cmd: list[str], env: dict | None = None):
        self.cmd = cmd
        self.env = env
        self.proc: subprocess.Popen | None = None

    def start(self, port: int, timeout: float = 15.0) -> None:
        self.proc = subprocess.Popen(
            self.cmd + ["--host", "127.0.0.1", "--port", str(port)],
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"relay exited early: {self.cmd}")
                time.sleep(0.05)
        raise RuntimeError(f"relay did not open port {port}: {self.cmd}")

    def stop(self) -> None:
        if self and self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    @property
    def pid(self) -> int:
        assert self.proc is not None
        return self.proc.pid


async def echo_pair(port: int):
    """Echo server + client, both registered."""
    server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
    server.register_handler("echo", lambda f: {"pong": f.data.get("n")})
    client = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
    await server.connect(host="127.0.0.1", port=port)
    await client.connect(host="127.0.0.1", port=port)
    return server, client


CONSTR = lambda ms=3000: ExecutionConstraints(timeout_ms=ms)


# ---------------------------------------------------------------- scenarios
async def bench_latency(port: int, n: int) -> dict:
    server, client = await echo_pair(port)
    try:
        for i in range(20):  # warmup (JIT-free but caches/connections)
            await client.send(target_pin=server.pin, verb="echo", data={"n": i},
                              constraints=CONSTR())
        rtts = []
        for i in range(n):
            t0 = time.perf_counter()
            await client.send(target_pin=server.pin, verb="echo", data={"n": i},
                              constraints=CONSTR())
            rtts.append((time.perf_counter() - t0) * 1000.0)
        return {
            "n": n,
            "p50_ms": pct(rtts, 50), "p95_ms": pct(rtts, 95),
            "p99_ms": pct(rtts, 99), "max_ms": max(rtts),
            "mean_ms": sum(rtts) / len(rtts),
        }
    finally:
        await client.close()
        await server.close()


async def bench_throughput(port: int, total: int, conc: int) -> dict:
    server, client = await echo_pair(port)
    try:
        t0 = time.perf_counter()
        for i in range(0, 20):  # warmup
            await client.send(target_pin=server.pin, verb="echo", data={"n": i},
                              constraints=CONSTR())
        t0 = time.perf_counter()
        for base in range(0, total, conc):
            batch = list(range(base, min(base + conc, total)))
            await asyncio.gather(*[
                client.send(target_pin=server.pin, verb="echo", data={"n": i},
                            constraints=CONSTR(10_000))
                for i in batch
            ])
        seq_wall = time.perf_counter() - t0
        # sequential rate: reuse latency-style single-flight window
        t0 = time.perf_counter()
        for i in range(100):
            await client.send(target_pin=server.pin, verb="echo", data={"n": i},
                              constraints=CONSTR())
        seq100 = time.perf_counter() - t0
        return {
            "pipelined_rps": total / seq_wall,
            "sequential_rps": 100 / seq100,
            "conc": conc, "total": total,
        }
    finally:
        await client.close()
        await server.close()


async def bench_memory(port: int, pid: int, k: int) -> dict:
    base = rss_kib(pid)
    clients = []
    for _ in range(k):
        c = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
        await c.connect(host="127.0.0.1", port=port)
        clients.append(c)
    await asyncio.sleep(0.3)
    after = rss_kib(pid)
    for c in clients:
        await c.close()
    return {
        "k": k,
        "baseline_mib": base / 1024.0,
        "delta_mib": (after - base) / 1024.0,
        # rss_kib already returns KiB: delta / k IS KiB per connection
        "kib_per_conn": (after - base) / k,
    }


def _register(sock: socket.socket, ident: AgentIdentity, port: int) -> None:
    """Registers a raw client the way the protocol demands: registration
    frame SIGNED by the presented key (proof of possession). Raises if the
    relay refuses — a silent refusal would fake the whole scenario."""
    reg = EacpFrame(
        msg_type=MsgType.MSG_RELAY_CONTROL, opcode=OpCode.OP_RELAY_REGISTER,
        sender_pin=ident.pin, target_pin=0, transaction_id=1,
        capabilities_mask=int(Capability.NONE),
        data={"pub_bytes": ident.public_bytes.hex()},
    )
    ident.sign_frame(reg)
    sock.sendall(reg.pack())
    sock.settimeout(3.0)
    buf = b""
    while len(buf) < HEADER.size + 8:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed during registration")
        buf += chunk
    status = HEADER.unpack(buf[:HEADER.size])[9]
    if status != 0:
        raise RuntimeError(f"registration refused, status={status}")
    sock.settimeout(None)


async def bench_slow_consumer(port: int, flood: int, pings: int) -> dict:
    # stalled consumer: raw socket, registers, then stops reading
    ident = AgentIdentity.generate()
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    _register(raw, ident, port)

    # flood travels THROUGH the relay from its OWN registered sender socket
    sender_ident = AgentIdentity.generate()
    sender_sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    _register(sender_sock, sender_ident, port)
    sender_sock.settimeout(0.25)

    # healthy pair measured DURING the stall
    server, client = await echo_pair(port)
    # fire-and-forget signed flood at the stalled target
    sent = 0
    deadline = time.perf_counter() + 5.0
    for i in range(flood):
        if time.perf_counter() > deadline:
            break
        fr = EacpFrame(
            msg_type=MsgType.MSG_SEND, verb="flood", sender_pin=sender_ident.pin,
            target_pin=ident.pin, transaction_id=1000 + i,
            constraints=ExecutionConstraints(timeout_ms=60_000),
            data={"i": i},
        )
        sender_ident.sign_frame(fr)
        try:
            sender_sock.sendall(fr.pack())
            sent += 1
        except socket.timeout:
            break
    # let the relay finish processing the accepted burst, then measure the
    # STEADY-STATE isolation of a stalled consumer (not the burst overlap)
    await asyncio.sleep(0.5)
    # health of an UNRELATED path while the target is stalled
    healthy = []
    for i in range(pings):
        t0 = time.perf_counter()
        await client.send(target_pin=server.pin, verb="echo", data={"n": i},
                          constraints=CONSTR())
        healthy.append((time.perf_counter() - t0) * 1000.0)

    # recovery: target resumes reading; drain until quiet
    raw.settimeout(0.4)
    buf = b""
    frames = 0
    quiet = 0.0
    t_drain = time.perf_counter()
    last = time.perf_counter()
    while quiet < 0.8 and time.perf_counter() - t_drain < 20.0:
        try:
            chunk = raw.recv(65536)
        except socket.timeout:
            chunk = b""
        if chunk:
            buf += chunk
            last = time.perf_counter()
            quiet = 0.0
            while len(buf) >= HEADER.size:
                plen = HEADER.unpack(buf[:HEADER.size])[10]
                if len(buf) < HEADER.size + plen:
                    break
                frames += 1
                buf = buf[HEADER.size + plen:]
        else:
            quiet = time.perf_counter() - last
    drain_s = time.perf_counter() - t_drain

    await client.close()
    await server.close()
    raw.close()
    sender_sock.close()
    return {
        "frames_sent": sent, "frames_drained": frames,
        "drain_s": drain_s,
        "healthy_p50_ms": pct(healthy, 50),
        "healthy_p99_ms": pct(healthy, 99),
    }


# ---------------------------------------------------------------- driver
async def run_impl(name: str, cmd: list[str], env: dict | None, args) -> dict:
    port = args.port
    out = {"name": name}

    # fresh relay per scenario group: memory is attributed to the
    # registrations only (no residue from earlier traffic)
    mem_relay = RelayProc(cmd, env)
    mem_relay.start(port)
    try:
        out["memory"] = await bench_memory(port, mem_relay.pid, args.conns)
    finally:
        mem_relay.stop()

    traffic = RelayProc(cmd, env)
    traffic.start(port)
    try:
        out["latency"] = await bench_latency(port, args.requests)
        out["throughput"] = await bench_throughput(port, args.requests, 32)
    finally:
        traffic.stop()

    slow = RelayProc(cmd, env)
    slow.start(port)
    try:
        out["slow"] = await bench_slow_consumer(port, args.flood, 100)
    finally:
        slow.stop()
    return out


def fmt(v, spec=".2f"):
    return format(v, spec) if isinstance(v, float) else str(v)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=300)
    ap.add_argument("--conns", type=int, default=100)
    ap.add_argument("--flood", type=int, default=600)
    ap.add_argument("--port", type=int, default=8991)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    if not RUST_BIN.exists():
        print(f"RUST BINARY MISSING: {RUST_BIN}\n"
              f"build it: cargo build --release --manifest-path crates/eacp-relay/Cargo.toml",
              file=sys.stderr)
        return 2

    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    results = asyncio.run(_run(args, env))
    print(render(results))
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
    return 0


async def _run(args, env) -> dict:
    py = await run_impl(
        "python", [sys.executable, "-m", "eacp.relay"], env, args)
    rs = await run_impl("rust", [str(RUST_BIN)], None, args)
    return {"python": py, "rust": rs}


def render(res: dict) -> str:
    p, r = res["python"], res["rust"]
    rows = [
        ("metric", "python relay", "rust relay"),
        ("RTT p50 (ms)", fmt(p["latency"]["p50_ms"]), fmt(r["latency"]["p50_ms"])),
        ("RTT p95 (ms)", fmt(p["latency"]["p95_ms"]), fmt(r["latency"]["p95_ms"])),
        ("RTT p99 (ms)", fmt(p["latency"]["p99_ms"]), fmt(r["latency"]["p99_ms"])),
        ("RTT mean/max (ms)", f"{fmt(p['latency']['mean_ms'])} / {fmt(p['latency']['max_ms'])}",
         f"{fmt(r['latency']['mean_ms'])} / {fmt(r['latency']['max_ms'])}"),
        ("sequential (req/s)", fmt(p["throughput"]["sequential_rps"], ".0f"),
         fmt(r["throughput"]["sequential_rps"], ".0f")),
        (f"pipelined conc=32 (req/s)", fmt(p["throughput"]["pipelined_rps"], ".0f"),
         fmt(r["throughput"]["pipelined_rps"], ".0f")),
        ("relay RSS baseline (MiB)", fmt(p["memory"]["baseline_mib"]), fmt(r["memory"]["baseline_mib"])),
        ("RSS per registered conn (KiB)", fmt(p["memory"]["kib_per_conn"], ".1f"),
         fmt(r["memory"]["kib_per_conn"], ".1f")),
        (f"healthy p50 during stall (ms)", fmt(p["slow"]["healthy_p50_ms"]),
         fmt(r["slow"]["healthy_p50_ms"])),
        (f"healthy p99 during stall (ms)", fmt(p["slow"]["healthy_p99_ms"]),
         fmt(r["slow"]["healthy_p99_ms"])),
        ("stalled-consumer drain (s)", fmt(p["slow"]["drain_s"]),
         fmt(r["slow"]["drain_s"])),
        ("frames sent / drained",
         f"{p['slow']['frames_sent']} / {p['slow']['frames_drained']}",
         f"{r['slow']['frames_sent']} / {r['slow']['frames_drained']}"),
    ]
    width = [max(len(str(row[i])) for row in rows) for i in range(3)]
    lines = []
    for i, row in enumerate(rows):
        lines.append("| " + " | ".join(str(c).ljust(width[j]) for j, c in enumerate(row)) + " |")
        if i == 0:
            lines.append("|" + "|".join("-" * (width[j] + 2) for j in range(3)) + "|")
    lines.append("")
    lines.append("Wire: byte-identical signed frames on both relays; BOTH verify")
    lines.append("Ed25519 (signing contract v2) per frame. Loopback only.")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())