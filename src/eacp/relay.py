"""
EACP-Relay: BlackBerry BES/QNX rendezvous router, PIN routing table,
offline push buffering, and cycle deadlock detection.
"""

from __future__ import annotations
import asyncio
import os
import time
from collections import deque
import logging
import struct
from typing import Deque, Dict, Optional, Set, Tuple

from .constants import (
    DEFAULT_HEARTBEAT_TIMEOUT_S,
    DEFAULT_MAX_PAYLOAD_SIZE,
    EACP_MAGIC,
    HEADER_SIZE,
    EacpError,
    FrameFlags,
    MsgType,
    OpCode,
    PulseCode,
)
from .frame import EacpFrame, HEADER_STRUCT
from .security import AgentVerifier, format_pin

logger = logging.getLogger("eacp.relay")


class DeadlockGraph:
    """
    Tracks synchronous MsgSend dependency chains to detect circular deadlocks.
    Emulates QNX Neutrino kernel rendezvous graph.
    """

    def __init__(self):
        # Maps sender_pin -> target_pin (sender is blocked waiting for reply from target)
        self._edges: Dict[int, int] = {}

    def would_deadlock(self, sender_pin: int, target_pin: int) -> bool:
        """
        Determines whether adding an edge sender_pin -> target_pin causes a cycle.
        Traverses path starting from target_pin: if it reaches sender_pin, deadlock!
        """
        if sender_pin == target_pin:
            return True

        curr = target_pin
        visited: Set[int] = {sender_pin}
        while curr in self._edges:
            curr = self._edges[curr]
            if curr in visited:
                return True
            visited.add(curr)
        return False

    def add_dependency(self, sender_pin: int, target_pin: int) -> bool:
        """
        Attempts to add sender_pin -> target_pin edge.
        Returns False if a cycle was detected (and does not add the edge), True otherwise.
        """
        if self.would_deadlock(sender_pin, target_pin):
            return False
        self._edges[sender_pin] = target_pin
        return True

    def remove_dependency(self, sender_pin: int) -> None:
        self._edges.pop(sender_pin, None)

    def remove_agent(self, pin: int) -> None:
        self._edges.pop(pin, None)
        # Also remove any edges pointing to this pin
        to_del = [s for s, t in self._edges.items() if t == pin]
        for s in to_del:
            self._edges.pop(s, None)

    def is_blocked(self, pin: int) -> bool:
        return pin in self._edges


class RelayClientSession:
    """Represents a connected agent's transport session at the Relay."""

    def __init__(
        self,
        pin: int,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        verifier: Optional[AgentVerifier] = None,
    ):
        self.pin = pin
        self.reader = reader
        self.writer = writer
        self.verifier = verifier
        self.state: int = 0  # 0: IDLE, 1: SEND_BLOCKED, 2: REPLY_BLOCKED
        self.closed: bool = False
        self.last_seen: float = time.monotonic()

    async def send_frame(self, frame: EacpFrame) -> None:
        if self.writer and not self.closed:
            data = frame.pack()
            self.writer.write(data)
            await self.writer.drain()

    def close(self) -> None:
        self.closed = True
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


class EacpRelay:
    """
    EACP Push Relay Server.
    - Manages Agent-PIN registration and routing table.
    - Enforces QNX synchronous rendezvous & deadlock detection.
    - Buffers offline messages (BlackBerry BES push architecture).
    """

    RELAY_PIN: int = 0x0000_0000_0000_0001

    def __init__(
        self,
        max_push_queue: int = 1000,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        heartbeat_timeout_s: float = DEFAULT_HEARTBEAT_TIMEOUT_S,
    ):
        self.max_push_queue = max_push_queue
        self.max_payload_size = max_payload_size
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.routes: Dict[int, RelayClientSession] = {}
        self.verifiers: Dict[int, AgentVerifier] = {}
        self.deadlock_graph: DeadlockGraph = DeadlockGraph()
        self.push_queues: Dict[int, Deque[Tuple[float, EacpFrame]]] = {}
        self.server: Optional[asyncio.Server] = None
        self.unix_path: Optional[str] = None
        self._reaper_task: Optional[asyncio.Task[None]] = None
        self._running: bool = False

    def register_agent(
        self,
        pin: int,
        session: RelayClientSession,
        verifier: Optional[AgentVerifier] = None,
    ) -> None:
        self.routes[pin] = session
        if verifier:
            self.verifiers[pin] = verifier
            session.verifier = verifier

        # Drain queued offline push messages for this agent respecting TTL
        if pin in self.push_queues and self.push_queues[pin]:
            queue = self.push_queues[pin]
            now = time.monotonic()
            while queue:
                enqueued_at, msg = queue.popleft()
                timeout_sec = (msg.constraints.timeout_ms / 1000.0) if (msg.constraints and msg.constraints.timeout_ms > 0) else 5.0
                if (now - enqueued_at) > timeout_sec:
                    # Message expired while offline in queue
                    if msg.msg_type == MsgType.MSG_SEND:
                        self.deadlock_graph.remove_dependency(msg.sender_pin)
                        sender_sess = self.routes.get(msg.sender_pin)
                        if sender_sess and not sender_sess.closed:
                            err_reply = msg.create_reply(status=EacpError.EACP_ERR_TIMEOUT)
                            asyncio.create_task(sender_sess.send_frame(err_reply))
                    continue

                asyncio.create_task(session.send_frame(msg))

    def unregister_agent(self, pin: int) -> None:
        self.routes.pop(pin, None)
        self.deadlock_graph.remove_agent(pin)

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session: Optional[RelayClientSession] = None
        registered_pin: Optional[int] = None
        try:
            while self._running:
                # Read 48-byte header
                hdr_bytes = await reader.readexactly(HEADER_SIZE)
                if not hdr_bytes:
                    break

                magic, ver, msg_type_raw, opcode, flags_raw, sender_pin, target_pin, tx_id, cap_mask, status_raw, payload_len = HEADER_STRUCT.unpack(hdr_bytes)

                if magic != EACP_MAGIC:
                    # Sync violation
                    break

                if payload_len > self.max_payload_size:
                    logger.warning(
                        f"Payload length {payload_len} exceeds max payload size {self.max_payload_size}. Dropping connection."
                    )
                    break

                # Read payload
                payload = b""
                if payload_len > 0:
                    payload = await reader.readexactly(payload_len)

                frame = EacpFrame.unpack(hdr_bytes + payload, max_payload_size=self.max_payload_size)

                # Check registration / relay control
                if frame.msg_type == MsgType.MSG_RELAY_CONTROL and frame.opcode == OpCode.OP_RELAY_REGISTER:
                    registered_pin = frame.sender_pin
                    verifier = None
                    # If public key attached in frame.data or slot 1
                    if isinstance(frame.data, dict) and "pub_bytes" in frame.data:
                        try:
                            pub_raw = bytes.fromhex(frame.data["pub_bytes"])
                            verifier = AgentVerifier.from_public_bytes(pub_raw)
                        except Exception as e:
                            logger.warning(f"Invalid verifier in registration: {e}")

                    session = RelayClientSession(
                        pin=registered_pin,
                        reader=reader,
                        writer=writer,
                        verifier=verifier,
                    )
                    self.register_agent(registered_pin, session, verifier)
                    
                    # Send ACK reply
                    ack = frame.create_reply(status=EacpError.EACP_SUCCESS, result_data={"registered": True, "pin": registered_pin})
                    await session.send_frame(ack)
                    continue

                # Ensure sender session is established
                if not session and registered_pin:
                    session = self.routes.get(registered_pin)

                if session:
                    session.last_seen = time.monotonic()

                # If frame is a heartbeat pulse, update presence and acknowledge if requested
                if frame.msg_type == MsgType.MSG_PULSE:
                    code, _ = frame.get_pulse_data()
                    if code == PulseCode.PULSE_HEARTBEAT and frame.target_pin in (0, self.RELAY_PIN):
                        # Relay presence ping handled
                        continue

                await self.route_frame(frame, session, writer)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error(f"Relay connection handler error: {e}", exc_info=True)
        finally:
            if registered_pin:
                self.unregister_agent(registered_pin)
            if session:
                session.close()
            else:
                try:
                    writer.close()
                except Exception:
                    pass

    async def route_frame(
        self,
        frame: EacpFrame,
        sender_session: Optional[RelayClientSession],
        writer: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        sender_pin = frame.sender_pin
        target_pin = frame.target_pin

        # 1. Verification: if verifier exists for sender, check signature
        if (frame.flags & FrameFlags.FLAG_SIGNED) and sender_pin in self.verifiers:
            verifier = self.verifiers[sender_pin]
            if not verifier.verify_frame(frame):
                # Signature invalid, drop or reply with error
                if frame.msg_type == MsgType.MSG_SEND and sender_session:
                    err_reply = frame.create_reply(status=EacpError.EACP_ERR_SIGNATURE_INVALID)
                    await sender_session.send_frame(err_reply)
                return

        # 2. QNX Synchronous Rendezvous & Deadlock Detection
        if frame.msg_type == MsgType.MSG_SEND:
            # Check deadlock cycle before routing
            if not self.deadlock_graph.add_dependency(sender_pin, target_pin):
                # Deadlock detected! Reply immediately with error
                err_reply = frame.create_reply(status=EacpError.EACP_ERR_DEADLOCK_DETECTED)
                if sender_session:
                    await sender_session.send_frame(err_reply)
                return

        elif frame.msg_type == MsgType.MSG_REPLY:
            # Reply releases the dependency (target_pin was waiting for sender_pin's reply)
            self.deadlock_graph.remove_dependency(target_pin)

        elif frame.msg_type == MsgType.MSG_PULSE:
            code, _ = frame.get_pulse_data()
            if code == PulseCode.PULSE_CANCEL:
                # Cancel frees sender's in-flight dependency
                self.deadlock_graph.remove_dependency(sender_pin)

        # 3. Route to target
        target_session = self.routes.get(target_pin)
        if target_session and not target_session.closed:
            await target_session.send_frame(frame)
        else:
            # Target is offline
            now = time.monotonic()
            if frame.msg_type == MsgType.MSG_SEND:
                # If urgent or no buffering allowed, return unknown PIN immediately
                if frame.flags & FrameFlags.FLAG_URGENT:
                    self.deadlock_graph.remove_dependency(sender_pin)
                    if sender_session:
                        err_reply = frame.create_reply(status=EacpError.EACP_ERR_UNKNOWN_PIN)
                        await sender_session.send_frame(err_reply)
                else:
                    # Buffer message in push queue
                    if target_pin not in self.push_queues:
                        self.push_queues[target_pin] = deque(maxlen=self.max_push_queue)
                    self.push_queues[target_pin].append((now, frame))
            elif frame.msg_type in (MsgType.MSG_PULSE, MsgType.MSG_REPLY):
                # For replies where target is lost, clear deadlock edge
                if frame.msg_type == MsgType.MSG_REPLY:
                    self.deadlock_graph.remove_dependency(target_pin)
                # Store pulse or drop
                if target_pin not in self.push_queues:
                    self.push_queues[target_pin] = deque(maxlen=self.max_push_queue)
                self.push_queues[target_pin].append((now, frame))

    async def _heartbeat_reaper(self) -> None:
        """Periodically prunes dead agent connections that failed heartbeat timeout."""
        try:
            while self._running:
                await asyncio.sleep(min(15.0, self.heartbeat_timeout_s / 2.0))
                now = time.monotonic()
                for pin, session in list(self.routes.items()):
                    if (now - session.last_seen) > self.heartbeat_timeout_s:
                        logger.warning(
                            f"Agent-PIN {format_pin(pin)} heartbeat timed out ({now - session.last_seen:.1f}s), closing dead route"
                        )
                        self.unregister_agent(pin)
                        session.close()
        except asyncio.CancelledError:
            pass

    async def start(
        self,
        host: Optional[str] = "127.0.0.1",
        port: Optional[int] = 8990,
        unix_path: Optional[str] = None,
    ) -> None:
        self._running = True
        self.unix_path = unix_path
        if unix_path:
            if os.path.exists(unix_path):
                os.unlink(unix_path)
            self.server = await asyncio.start_unix_server(self.handle_connection, path=unix_path)
            logger.info(f"EACP Relay started on unix socket {unix_path}")
        elif host is not None and port is not None:
            self.server = await asyncio.start_server(self.handle_connection, host, port)
            logger.info(f"EACP Relay started on {host}:{port}")

        self._reaper_task = asyncio.create_task(self._heartbeat_reaper())

    async def stop(self) -> None:
        self._running = False
        if self._reaper_task and not self._reaper_task.done():
            self._reaper_task.cancel()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.unix_path and os.path.exists(self.unix_path):
            try:
                os.unlink(self.unix_path)
            except Exception:
                pass
        for session in list(self.routes.values()):
            session.close()
        self.routes.clear()
        self.push_queues.clear()


def main() -> None:
    """Portable CLI entry point to run the EACP Push Relay Daemon."""
    import argparse
    parser = argparse.ArgumentParser(description="EACP Push Relay Daemon (Microkernel Enterprise Mesh)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8990, help="Listen port (default: 8990)")
    parser.add_argument("--socket", default=None, help="Listen on Unix domain socket path")
    parser.add_argument("--max-queue", type=int, default=1000, help="Max offline push queue per agent")
    parser.add_argument("--max-payload-mb", type=int, default=16, help="Max frame payload size in MB")
    parser.add_argument("--heartbeat-timeout", type=float, default=90.0, help="Heartbeat timeout in seconds")
    args = parser.parse_args()

    async def _run() -> None:
        relay = EacpRelay(
            max_push_queue=args.max_queue,
            max_payload_size=args.max_payload_mb * 1024 * 1024,
            heartbeat_timeout_s=args.heartbeat_timeout,
        )
        await relay.start(host=args.host, port=args.port, unix_path=args.socket)
        print(f"EACP Relay listening on {args.socket if args.socket else f'{args.host}:{args.port}'}...")
        try:
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await relay.stop()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    asyncio.run(_run())


if __name__ == "__main__":
    main()
