"""
End-to-end multi-agent IPC rendezvous tests for EACP Relay, PlatSec, and Deadlock Detection.
"""

import asyncio
import sys
import unittest

from eacp.constants import Capability, EacpError, PulseCode
from eacp.client import RSessionBase
from eacp.frame import ExecutionConstraints
from eacp.primitives import EacpRendezvousException, MsgPulse, MsgSend
from eacp.relay import DeadlockGraph, EacpRelay
from eacp.security import AgentIdentity


class TestDeadlockGraph(unittest.TestCase):
    def test_cycle_detection(self):
        graph = DeadlockGraph()
        # A -> B -> C
        self.assertTrue(graph.add_dependency(1, 2))
        self.assertTrue(graph.add_dependency(2, 3))

        # C -> A must be rejected as deadlock
        self.assertTrue(graph.would_deadlock(3, 1))
        self.assertFalse(graph.add_dependency(3, 1))

        # Self-dependency must be rejected
        self.assertTrue(graph.would_deadlock(1, 1))
        self.assertFalse(graph.add_dependency(1, 1))

        # Removing 1 unblocks 1 waiting on 2
        graph.remove_dependency(1)
        # Now 2 -> 1 is allowed
        self.assertTrue(graph.add_dependency(2, 1))


class TestEacpRendezvousEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.port = 18992
        self.relay = EacpRelay()
        await self.relay.start(host="127.0.0.1", port=self.port)

    async def asyncTearDown(self):
        await self.relay.stop()

    async def test_successful_synchronous_rendezvous(self):
        server_id = AgentIdentity.generate()
        client_id = AgentIdentity.generate()

        server = RSessionBase(identity=server_id, allowed_capabilities=Capability.CAP_DISK_READ)
        client = RSessionBase(identity=client_id, allowed_capabilities=Capability.CAP_DISK_READ)

        # Server registers action handler
        def handle_compute(frame):
            n = frame.data.get("n", 0)
            return {"doubled": n * 2}

        server.register_handler("compute", handle_compute, required_caps=Capability.CAP_DISK_READ)

        await server.connect(host="127.0.0.1", port=self.port)
        await client.connect(host="127.0.0.1", port=self.port)

        # Client sends MsgSend to server
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

    async def test_platsec_enforcement_over_wire(self):
        server_id = AgentIdentity.generate()
        client_id = AgentIdentity.generate()

        server = RSessionBase(identity=server_id, allowed_capabilities=Capability.CAP_SYS_ADMIN)
        # Client ONLY has DISK_READ capability, lacks SYS_ADMIN
        client = RSessionBase(identity=client_id, allowed_capabilities=Capability.CAP_DISK_READ)

        executed = []

        def handle_admin(frame):
            executed.append(True)
            return {"status": "ok"}

        # Requires CAP_SYS_ADMIN
        server.register_handler("reboot_node", handle_admin, required_caps=Capability.CAP_SYS_ADMIN)

        await server.connect(host="127.0.0.1", port=self.port)
        await client.connect(host="127.0.0.1", port=self.port)

        # Client attempts invocation without necessary capability
        with self.assertRaises(EacpRendezvousException) as ctx:
            await MsgSend(
                client,
                target_pin=server.pin,
                verb="reboot_node",
                data={},
                constraints=ExecutionConstraints(timeout_ms=3000),
            )

        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_CAPABILITY_DENIED)
        # Handler must never have executed
        self.assertEqual(len(executed), 0)

        await client.close()
        await server.close()

    async def test_deadlock_detection_over_wire(self):
        agent_a = RSessionBase(allowed_capabilities=Capability.CAP_NET_RAW)
        agent_b = RSessionBase(allowed_capabilities=Capability.CAP_NET_RAW)

        await agent_a.connect(host="127.0.0.1", port=self.port)
        await agent_b.connect(host="127.0.0.1", port=self.port)

        deadlock_caught = asyncio.Event()

        # When agent_b receives "call_a", it attempts MsgSend back to agent_a
        async def b_handler(frame):
            try:
                # This should trigger DEADLOCK because agent_a is waiting on agent_b
                await MsgSend(
                    agent_b,
                    target_pin=agent_a.pin,
                    verb="ping",
                    constraints=ExecutionConstraints(timeout_ms=2000),
                )
            except EacpRendezvousException as exc:
                if exc.code == EacpError.EACP_ERR_DEADLOCK_DETECTED:
                    deadlock_caught.set()
            return {"status": "b_done"}

        agent_b.register_handler("call_a", b_handler)

        # Agent A sends to Agent B
        task_a = asyncio.create_task(
            MsgSend(
                agent_a,
                target_pin=agent_b.pin,
                verb="call_a",
                constraints=ExecutionConstraints(timeout_ms=3000),
            )
        )

        # Await deadlock notification
        await asyncio.wait_for(deadlock_caught.wait(), timeout=3.0)
        self.assertTrue(deadlock_caught.is_set())

        # Let the rendezvous transaction complete
        reply_a = await asyncio.wait_for(task_a, timeout=2.0)
        self.assertEqual(reply_a.data, {"status": "b_done"})

        await agent_a.close()
        await agent_b.close()

    async def test_nonblocking_pulse(self):
        server = RSessionBase()
        client = RSessionBase()

        await server.connect(host="127.0.0.1", port=self.port)
        await client.connect(host="127.0.0.1", port=self.port)

        pulse_received = asyncio.Event()
        received_data = []

        def on_pulse(code, val):
            received_data.append((code, val))
            pulse_received.set()

        server.register_pulse_callback(PulseCode.PULSE_CANCEL, on_pulse)

        # Send pulse
        await MsgPulse(client, target_pin=server.pin, pulse_code=PulseCode.PULSE_CANCEL, pulse_value=999)

        await asyncio.wait_for(pulse_received.wait(), timeout=2.0)
        self.assertEqual(received_data, [(int(PulseCode.PULSE_CANCEL), 999)])

        await client.close()
        await server.close()

    @unittest.skipIf(sys.platform == "win32", "Unix domain sockets are not available on Windows")
    async def test_unix_domain_socket_rendezvous(self):
        uds_path = "/tmp/test_eacp_uds.sock"
        uds_relay = EacpRelay()
        await uds_relay.start(unix_path=uds_path)

        server = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)
        client = RSessionBase(allowed_capabilities=Capability.CAP_DISK_READ)

        server.register_handler("uds_ping", lambda f: {"pong": True}, required_caps=Capability.CAP_DISK_READ)

        await server.connect(unix_path=uds_path)
        await client.connect(unix_path=uds_path)

        reply = await MsgSend(client, target_pin=server.pin, verb="uds_ping")
        self.assertEqual(reply.data, {"pong": True})

        await client.close()
        await server.close()
        await uds_relay.stop()

    async def test_max_depth_hops_exceeded(self):
        server = RSessionBase()
        client = RSessionBase()

        server.register_handler("step", lambda f: "ok")

        await server.connect(host="127.0.0.1", port=self.port)
        await client.connect(host="127.0.0.1", port=self.port)

        # Send with max_depth_hops=0 (budget exhausted)
        with self.assertRaises(EacpRendezvousException) as ctx:
            await MsgSend(
                client,
                target_pin=server.pin,
                verb="step",
                constraints=ExecutionConstraints(max_depth_hops=0),
            )
        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_DEPTH_EXCEEDED)

        await client.close()
        await server.close()

    async def test_deadlock_cleanup_on_timeout(self):
        # Verify that when client times out, PULSE_CANCEL frees deadlock graph edge
        agent_a = RSessionBase()
        agent_b = RSessionBase()

        # Agent B handler takes 500ms
        async def slow_handler(frame):
            await asyncio.sleep(0.5)
            return "done"

        agent_b.register_handler("slow", slow_handler)

        await agent_a.connect(host="127.0.0.1", port=self.port)
        await agent_b.connect(host="127.0.0.1", port=self.port)

        # Agent A sends with 50ms timeout -> triggers timeout
        with self.assertRaises(EacpRendezvousException) as ctx:
            await MsgSend(
                agent_a,
                target_pin=agent_b.pin,
                verb="slow",
                constraints=ExecutionConstraints(timeout_ms=50),
            )
        self.assertEqual(ctx.exception.code, EacpError.EACP_ERR_TIMEOUT)

        # Give small tick for pulse to reach relay
        await asyncio.sleep(0.05)

        # Agent A must NO LONGER be blocked in relay's deadlock graph!
        self.assertFalse(self.relay.deadlock_graph.is_blocked(agent_a.pin))

        await agent_a.close()
        await agent_b.close()

    async def test_relay_heartbeat_tracking(self):
        # Configure relay with short heartbeat timeout
        port = 18995
        relay = EacpRelay(heartbeat_timeout_s=0.2)
        await relay.start(port=port)

        client = RSessionBase(heartbeat_interval_s=0.05)
        await client.connect(port=port)

        self.assertIn(client.pin, relay.routes)
        session = relay.routes[client.pin]

        # Let heartbeats exchange
        t0 = session.last_seen
        await asyncio.sleep(0.12)
        # last_seen must be updated by heartbeats
        self.assertGreater(session.last_seen, t0)

        await client.close()
        await relay.stop()


if __name__ == "__main__":
    unittest.main()
