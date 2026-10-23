"""
EACP-Relay: BlackBerry BES/QNX rendezvous router, PIN routing table,
offline push buffering, and cycle deadlock detection.
"""

from __future__ import annotations
import asyncio
from collections import deque
import logging
import struct
from typing import Dict, Optional, Set, Tuple

from .constants import (
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

    def __init__(self, max_push_queue: int = 1000):
        self.max_push_queue = max_push_queue
        self.routes: Dict[int, RelayClientSession] = {}
        self.verifiers: Dict[int, AgentVerifier] = {}
        self.deadlock_graph: DeadlockGraph = DeadlockGraph()
        self.push_queues: Dict[int, deque[EacpFrame]] = {}
        self.server: Optional[asyncio.Server] = None
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

        # Drain queued offline push messages for this agent
        if pin in self.push_queues and self.push_queues[pin]:
            queue = self.push_queues[pin]
            while queue:
                msg = queue.popleft()
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

                # Read payload
                payload = b""
                if payload_len > 0:
                    payload = await reader.readexactly(payload_len)

                frame = EacpFrame.unpack(hdr_bytes + payload)

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

        # 3. Route to target
        target_session = self.routes.get(target_pin)
        if target_session and not target_session.closed:
            await target_session.send_frame(frame)
        else:
            # Target is offline
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
                    self.push_queues[target_pin].append(frame)
            elif frame.msg_type in (MsgType.MSG_PULSE, MsgType.MSG_REPLY):
                # For replies where target is lost, clear deadlock edge
                if frame.msg_type == MsgType.MSG_REPLY:
                    self.deadlock_graph.remove_dependency(target_pin)
                # Store pulse or drop
                if target_pin not in self.push_queues:
                    self.push_queues[target_pin] = deque(maxlen=self.max_push_queue)
                self.push_queues[target_pin].append(frame)

    async def start(self, host: str = "127.0.0.1", port: int = 8990) -> None:
        self._running = True
        self.server = await asyncio.start_server(self.handle_connection, host, port)
        logger.info(f"EACP Relay started on {host}:{port}")

    async def stop(self) -> None:
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for session in list(self.routes.values()):
            session.close()
        self.routes.clear()
        self.push_queues.clear()
