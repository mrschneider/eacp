"""
End-to-end integration test validating the native Rust EACP Relay against Python agents.
"""

import asyncio
import os
import subprocess
import time
import unittest

from eacp.constants import Capability, EacpError
from eacp.client import RSessionBase
from eacp.frame import ExecutionConstraints
from eacp.primitives import EacpRendezvousException, MsgSend
from eacp.security import AgentIdentity

RELAY_BIN = os.path.join(
    os.path.dirname(__file__), "..", "crates", "eacp-relay", "target", "release", "eacp-relay"
)


@unittest.skipUnless(os.path.exists(RELAY_BIN), "Rust relay binary not built")
class TestRustRelayInteroperability(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = 18995
        # Start Rust Relay in subprocess
        self.proc = subprocess.Popen(
            [RELAY_BIN, "--host", "127.0.0.1", "--port", str(self.port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give relay a moment to bind socket
        await asyncio.sleep(0.3)

    async def asyncTearDown(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()

    async def test_rust_relay_synchronous_rendezvous(self):
        """Validates that Python agents perform synchronous rendezvous via the Rust Relay."""
        server_id = AgentIdentity.generate()
        client_id = AgentIdentity.generate()

        server = RSessionBase(identity=server_id, allowed_capabilities=Capability.CAP_DISK_READ)
        client = RSessionBase(identity=client_id, allowed_capabilities=Capability.CAP_DISK_READ)

        def handle_compute(frame):
            n = frame.data.get("n", 0)
            return {"doubled": n * 2}

        server.register_handler("compute", handle_compute, required_caps=Capability.CAP_DISK_READ)

        await server.connect(host="127.0.0.1", port=self.port)
        await client.connect(host="127.0.0.1", port=self.port)

        # Client sends MsgSend to server via Rust Relay
        reply = await MsgSend(
            client,
            target_pin=server.pin,
            verb="compute",
            data={"n": 21},
            constraints=ExecutionConstraints(timeout_ms=3000),
        )

        self.assertEqual(reply.status, EacpError.EACP_SUCCESS)
        self.assertEqual(reply.data, {"doubled": 42})

        await client.close()
        await server.close()

    async def test_rust_relay_deadlock_prevention(self):
        """Validates that Rust Relay detects circular rendezvous deadlocks."""
        agent_a = RSessionBase(allowed_capabilities=Capability.CAP_NET_RAW)
        agent_b = RSessionBase(allowed_capabilities=Capability.CAP_NET_RAW)

        await agent_a.connect(host="127.0.0.1", port=self.port)
        await agent_b.connect(host="127.0.0.1", port=self.port)

        deadlock_caught = asyncio.Event()

        def handle_a(frame):
            return {"result": "ok"}

        async def slow_b_handler(frame):
            try:
                # B attempts recursive MsgSend back to A while A is waiting for B -> DEADLOCK!
                await MsgSend(agent_b, target_pin=agent_a.pin, verb="call_a", data={})
            except EacpRendezvousException as exc:
                if exc.code == EacpError.EACP_ERR_DEADLOCK_DETECTED:
                    deadlock_caught.set()
            return {"status": "b_done"}

        agent_a.register_handler("call_a", handle_a)
        agent_b.register_handler("call_b", slow_b_handler)

        async def send_a_to_b():
            return await MsgSend(agent_a, target_pin=agent_b.pin, verb="call_b", data={})

        task_a = asyncio.create_task(send_a_to_b())
        await asyncio.wait_for(deadlock_caught.wait(), timeout=3.0)
        self.assertTrue(deadlock_caught.is_set())

        reply_a = await asyncio.wait_for(task_a, timeout=2.0)
        self.assertEqual(reply_a.data, {"status": "b_done"})

        await agent_a.close()
        await agent_b.close()


if __name__ == "__main__":
    unittest.main()
