#!/usr/bin/env python3
"""cProfile the REAL in-process EACP path: one EacpRelay + real RSessionBase
clients co-residing in a single process (the embedded-agent deployment, and the
shape of test_live_relay_audit_survives_concurrent_signed_traffic). This is the
path where relay-side Ed25519 verify, audit, routing and the client dispatch all
share one event loop. Reports the top time sinks per signed frame."""
from __future__ import annotations
import asyncio, cProfile, io, os, pstats, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from eacp.client import RSessionBase
from eacp.constants import Capability, MsgType
from eacp.frame import ExecutionConstraints

CONSTR = lambda ms=3000: ExecutionConstraints(timeout_ms=ms)


async def run(n: int):
    server = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
    server.register_handler("echo", lambda f: {"pong": f.data.get("n")})
    client = RSessionBase(allowed_capabilities=Capability.CAP_TOOL_EXEC)
    # co-resident relay in THIS process
    from eacp.relay import EacpRelay
    relay = EacpRelay()
    await relay.start(host="127.0.0.1", port=0)
    port = relay.server.sockets[0].getsockname()[1]
    try:
        await server.connect(host="127.0.0.1", port=port)
        await client.connect(host="127.0.0.1", port=port)
        for i in range(50):  # warmup
            await client.send(target_pin=server.pin, verb="echo", data={"n": i}, constraints=CONSTR())
        t0 = time.perf_counter()
        for i in range(n):
            await client.send(target_pin=server.pin, verb="echo", data={"n": i}, constraints=CONSTR())
        dt = time.perf_counter() - t0
    finally:
        await client.close(); await server.close(); await relay.stop()
    return n, dt


def main():
    n = 1500
    # warm the interpreter / crypto once, outside the profile
    async def warm():
        from eacp.security import AgentIdentity
        ident = AgentIdentity.generate()
        from eacp.frame import EacpFrame
        for i in range(200):
            f = EacpFrame(verb="echo", data={"n": i}); ident.sign_frame(f); f.pack()
    asyncio.run(warm())

    pr = cProfile.Profile()
    pr.enable()
    asyncio.run(run(n))
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(40)
    out = s.getvalue()
    # filter to eacp + crypto + asyncio-of-interest
    keep = [l for l in out.splitlines() if any(k in l for k in (
        "eacp/", "ed25519", "verify", "to_thread", "run_in_executor",
        "route_frame", "record", "pack", "unpack", "send_frame", "dispatch",
        "json", "sha256", "drain", "write", "ncalls", "function"))]
    print("\n".join(keep[:55]))


if __name__ == "__main__":
    main()
