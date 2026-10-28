"""
EACP-Relay: Microkernel rendezvous router, cryptographic PIN routing table,
offline push buffering, and cycle deadlock detection.

Security model (fail-closed, anchored at registration):
- Registration proves possession: the register frame must be signed by the
  manifest's key (CA mode) or the presented ``pub_bytes`` key (plain mode).
- CA mode verifies the signed manifest against the CONFIGURED trusted CA
  key — never against the CA key carried inside the manifest itself — and
  binds manifest pin / derived pin / frame sender together.
- The registered grants (declared mask, or the CA-attested manifest caps)
  are enforced on every routed MSG_SEND: a claim beyond grants is refused.
- Signed senders must send SIGNED frames (verified); (sender, tx) is
  remembered per session so a replayed frame is refused explicitly.
- Deadlock dependencies are tracked per TRANSACTION, so concurrent calls
  from one sender cannot overwrite each other's edges.
- Offline queues have global entry/byte budgets with explicit overflow
  errors, and queued frames expire on a timer, not only on re-registration.
"""

from __future__ import annotations
import asyncio
import hmac
import os
import secrets
import time
from collections import deque
import logging
import struct
import ssl
from typing import Deque, Dict, List, Optional, Set, Tuple

from .constants import (
    DEFAULT_HEARTBEAT_TIMEOUT_S,
    DEFAULT_MAX_PAYLOAD_SIZE,
    EACP_MAGIC,
    HEADER_SIZE,
    Capability,
    EacpError,
    FrameFlags,
    MsgType,
    OpCode,
    PulseCode,
)
from .frame import EacpFrame, HEADER_STRUCT
from .ledger import AuditLedger
from .mesh import MeshRoutingTable, RelayPeer, peer_tag
from .security import (
    AgentVerifier,
    EnterpriseCA,
    SignedManifest,
    compute_pin,
    format_pin,
)
from .telemetry import EacpMetrics, TraceContext

logger = logging.getLogger("eacp.relay")


class DeadlockGraph:
    """
    Tracks synchronous MsgSend dependency chains to detect circular deadlocks.
    Emulates QNX Neutrino kernel rendezvous graph.

    Dependencies are keyed per TRANSACTION: one sender may have several
    outstanding calls, and each edge must survive until ITS reply/cancel —
    storing a single target per sender silently overwrites edges and misses
    cycles (the classic A→B / A→C overwrite).
    """

    def __init__(self):
        # sender -> {tx_id -> target} (sender is blocked waiting on targets)
        self._edges: Dict[int, Dict[int, int]] = {}

    def would_deadlock(self, sender_pin: int, target_pin: int, tx_id: int = 0) -> bool:
        """Adding sender->target (for tx) causes a cycle? BFS over ALL of
        the sender's outstanding edges from target forward."""
        if sender_pin == target_pin:
            return True
        visited: Set[int] = {sender_pin}
        frontier = [target_pin]
        while frontier:
            curr = frontier.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for nxt in self._edges.get(curr, {}).values():
                if nxt == sender_pin:
                    return True
                frontier.append(nxt)
        return False

    def add_dependency(self, sender_pin: int, target_pin: int, tx_id: int = 0) -> bool:
        """Adds sender->target for tx_id. Returns False (and adds nothing)
        if a cycle was detected."""
        if self.would_deadlock(sender_pin, target_pin, tx_id):
            return False
        self._edges.setdefault(sender_pin, {})[tx_id] = target_pin
        return True

    def remove_dependency(self, sender_pin: int, tx_id: Optional[int] = None) -> None:
        """tx_id given: drop only that transaction's edge. None: drop every
        outstanding edge of the sender (legacy/agent-gone semantics)."""
        if tx_id is None:
            self._edges.pop(sender_pin, None)
            return
        edges = self._edges.get(sender_pin)
        if edges is None:
            return
        edges.pop(tx_id, None)
        if not edges:
            self._edges.pop(sender_pin, None)

    def remove_agent(self, pin: int) -> None:
        self._edges.pop(pin, None)
        for s in list(self._edges):
            self._edges[s] = {t: tg for t, tg in self._edges[s].items() if tg != pin}
            if not self._edges[s]:
                del self._edges[s]

    def is_blocked(self, pin: int) -> bool:
        return bool(self._edges.get(pin))


class RelayClientSession:
    """Represents a connected agent's transport session at the Relay."""

    REPLAY_WINDOW = 2048

    def __init__(
        self,
        pin: int,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        verifier: Optional[AgentVerifier] = None,
        grants: int = int(Capability.NONE),
    ):
        self.pin = pin
        self.reader = reader
        self.writer = writer
        self.verifier = verifier
        self.grants = grants  # authenticated registration grants
        self.state: int = 0  # 0: IDLE, 1: SEND_BLOCKED, 2: REPLY_BLOCKED
        self.closed: bool = False
        self.last_seen: float = time.monotonic()
        # replay defense: bounded (sender, tx) window per session
        self._seen_tx: Set[int] = set()
        self._seen_order: Deque[int] = deque(maxlen=self.REPLAY_WINDOW)

    def seen_tx(self, tx_id: int) -> bool:
        return tx_id in self._seen_tx

    def remember_tx(self, tx_id: int) -> None:
        if tx_id in self._seen_tx:
            return
        if len(self._seen_order) == self.REPLAY_WINDOW:
            old = self._seen_order[0]
            self._seen_tx.discard(old)
        self._seen_order.append(tx_id)
        self._seen_tx.add(tx_id)

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
    - Buffers offline messages (push architecture).
    """

    RELAY_PIN: int = 0x0000_0000_0000_0001

    def __init__(
        self,
        relay_id: str = "relay-1",
        max_push_queue: int = 1000,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        heartbeat_timeout_s: float = DEFAULT_HEARTBEAT_TIMEOUT_S,
        enterprise_ca: Optional[EnterpriseCA] = None,
        audit_file_path: Optional[str] = None,
        max_queue_total: int = 10_000,
        max_queue_bytes: int = 64 * 1024 * 1024,
    ):
        self.relay_id = relay_id
        self.max_push_queue = max_push_queue
        self.max_payload_size = max_payload_size
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.enterprise_ca = enterprise_ca
        self.routes: Dict[int, RelayClientSession] = {}
        self.verifiers: Dict[int, AgentVerifier] = {}
        self.grants: Dict[int, int] = {}  # authenticated caps per registered pin
        self.deadlock_graph: DeadlockGraph = DeadlockGraph()
        self.push_queues: Dict[int, Deque[Tuple[float, EacpFrame]]] = {}
        # global offline-queue budgets (per-target limits alone leave the
        # target count — and therefore memory — unbounded)
        self.max_queue_total = max_queue_total
        self.max_queue_bytes = max_queue_bytes
        self._queued_total = 0
        self._queued_bytes = 0
        self.server: Optional[asyncio.Server] = None
        self.unix_path: Optional[str] = None
        self._reaper_task: Optional[asyncio.Task[None]] = None
        self._running: bool = False

        # Enterprise extensions
        self.metrics: EacpMetrics = EacpMetrics()
        self.ledger: AuditLedger = AuditLedger(file_path=audit_file_path)
        self.mesh: MeshRoutingTable = MeshRoutingTable(local_relay_id=relay_id)

    # ------------------------------------------------------------------
    # registration

    def register_agent(
        self,
        pin: int,
        session: RelayClientSession,
        verifier: Optional[AgentVerifier] = None,
    ) -> None:
        self.routes[pin] = session
        self.mesh.register_local(pin)
        self.metrics.registered_agents.set(len(self.routes))
        if verifier:
            self.verifiers[pin] = verifier
            session.verifier = verifier

        # Drain queued offline push messages for this agent respecting TTL
        if pin in self.push_queues and self.push_queues[pin]:
            queue = self.push_queues[pin]
            now = time.monotonic()
            while queue:
                enqueued_at, msg = queue.popleft()
                self._queued_total -= 1
                self._queued_bytes -= self._frame_size(msg)
                timeout_sec = (msg.constraints.timeout_ms / 1000.0) if (msg.constraints and msg.constraints.timeout_ms > 0) else 5.0
                if (now - enqueued_at) > timeout_sec:
                    # Message expired while offline in queue
                    if msg.msg_type == MsgType.MSG_SEND:
                        self.deadlock_graph.remove_dependency(msg.sender_pin, msg.transaction_id)
                        sender_sess = self.routes.get(msg.sender_pin)
                        if sender_sess and not sender_sess.closed:
                            err_reply = msg.create_reply(status=EacpError.EACP_ERR_TIMEOUT)
                            asyncio.create_task(sender_sess.send_frame(err_reply))
                    continue

                asyncio.create_task(session.send_frame(msg))
            if not queue:
                self.push_queues.pop(pin, None)

        # announce the new local route to the mesh (configured peers)
        self._announce(pin, "add")

    def unregister_agent(self, pin: int) -> None:
        self.routes.pop(pin, None)
        self.verifiers.pop(pin, None)
        self.grants.pop(pin, None)
        self.mesh.unregister(pin)
        self.deadlock_graph.remove_agent(pin)
        self.metrics.registered_agents.set(len(self.routes))
        self._announce(pin, "remove")

    def _announce(self, pin: int, action: str) -> None:
        """Announce a LOCAL route change to mesh peers (best effort)."""
        if not self.mesh.peers:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.mesh.broadcast_route(pin, action=action))

    # ------------------------------------------------------------------
    # queue accounting (global budgets + explicit overflow)

    @staticmethod
    def _frame_size(frame: EacpFrame) -> int:
        if frame._wire is not None:
            return len(frame._wire)
        return len(frame.pack())

    def _buffer_frame(self, target_pin: int, frame: EacpFrame, now: float) -> bool:
        """Queues a frame under global entry/byte budgets. False = overflow
        (the caller must surface an explicit error, never a silent drop)."""
        size = self._frame_size(frame)
        if self._queued_total + 1 > self.max_queue_total or self._queued_bytes + size > self.max_queue_bytes:
            return False
        queue = self.push_queues.get(target_pin)
        if queue is None:
            queue = deque(maxlen=self.max_push_queue)
            self.push_queues[target_pin] = queue
        if len(queue) == queue.maxlen:
            # per-target cap reached: count the evicted frame out first so
            # global accounting stays exact (deque evicts silently)
            _ts, evicted = queue[0]
            self._queued_total -= 1
            self._queued_bytes -= self._frame_size(evicted)
        queue.append((now, frame))
        self._queued_total += 1
        self._queued_bytes += size
        return True

    def _unbuffer_frame(self, target_pin: int, frame: EacpFrame) -> None:
        """Account a frame leaving a queue without delivery."""
        self._queued_total -= 1
        self._queued_bytes -= self._frame_size(frame)
        queue = self.push_queues.get(target_pin)
        if queue is not None and not queue:
            self.push_queues.pop(target_pin, None)

    async def expire_queued(self) -> List[EacpFrame]:
        """Drops expired offline frames, answering senders with TIMEOUT.
        Called from the reaper and directly by tests."""
        now = time.monotonic()
        expired: List[EacpFrame] = []
        for target_pin in list(self.push_queues):
            queue = self.push_queues[target_pin]
            keep: Deque[Tuple[float, EacpFrame]] = deque(maxlen=self.max_push_queue)
            for enqueued_at, msg in queue:
                timeout_sec = (msg.constraints.timeout_ms / 1000.0) if (msg.constraints and msg.constraints.timeout_ms > 0) else 5.0
                if (now - enqueued_at) > timeout_sec:
                    self._unbuffer_frame(target_pin, msg)
                    expired.append(msg)
                else:
                    keep.append((enqueued_at, msg))
            if keep:
                self.push_queues[target_pin] = keep
            else:
                self.push_queues.pop(target_pin, None)
        for msg in expired:
            if msg.msg_type == MsgType.MSG_SEND:
                self.deadlock_graph.remove_dependency(msg.sender_pin, msg.transaction_id)
                sender_sess = self.routes.get(msg.sender_pin)
                if sender_sess and not sender_sess.closed:
                    await sender_sess.send_frame(msg.create_reply(status=EacpError.EACP_ERR_TIMEOUT))
        return expired

    # ------------------------------------------------------------------
    # connection handling

    def _refuse(self, writer: asyncio.StreamWriter, request: EacpFrame, status: EacpError, detail: str) -> None:
        """Registration-time refusal (session not established yet)."""
        err = request.create_reply(
            status=status,
            result_data={"error": detail},
        )

        async def _send() -> None:
            try:
                writer.write(err.pack())
                await writer.drain()
            except Exception:
                pass

        try:
            asyncio.get_running_loop().create_task(_send())
        except RuntimeError:
            pass

    async def _refuse_now(
        self, writer: asyncio.StreamWriter, request: EacpFrame, status: EacpError, detail: str
    ) -> None:
        """Inline refusal for teardown paths: unlike _refuse (fire-and-
        forget task), this AWAITS the flush — the caller breaks and closes
        the connection right after, and a pending task would lose the race."""
        err = request.create_reply(status=status, result_data={"error": detail})
        try:
            writer.write(err.pack())
            await writer.drain()
        except Exception:
            pass

    def _validate_registration(self, frame: EacpFrame) -> Tuple[Optional[AgentVerifier], int, Optional[str]]:
        """Registration trust chain. Returns (verifier, grants, error_detail).

        CA mode: verify the manifest against the CONFIGURED trusted CA key,
        bind pins, and require proof of possession (the register frame must
        be signed by the manifest key). Plain mode: the presented pub_bytes
        key must also prove possession via the frame signature.
        """
        pin = frame.sender_pin
        data = frame.data if isinstance(frame.data, dict) else {}

        if self.enterprise_ca is not None:
            if "signed_manifest" not in data:
                return None, 0, "missing signed manifest (Enterprise CA required)"
            try:
                sm = SignedManifest.from_dict(data["signed_manifest"])
            except Exception as e:
                return None, 0, f"malformed signed manifest: {e}"
            # the FIX: signature is verified against the CONFIGURED CA key;
            # the submitted ca_public_bytes is never trusted for verification
            if not sm.is_valid(trusted_ca_public_bytes=self.enterprise_ca.public_bytes):
                return None, 0, "manifest signature invalid under the configured Enterprise CA"
            if sm.ca_pin != self.enterprise_ca.ca_pin:
                return None, 0, "manifest ca_pin does not match the configured Enterprise CA"
            if sm.manifest.pin != pin:
                return None, 0, "manifest pin does not match the registration frame sender"
            pub = sm.manifest.public_bytes
            if not pub or compute_pin(pub) != pin:
                return None, 0, "manifest public key does not derive the registered PIN"
            declared_pub = data.get("pub_bytes")
            if declared_pub and bytes.fromhex(declared_pub) != pub:
                return None, 0, "registration pub_bytes does not match the CA-attested manifest key"
            try:
                verifier = AgentVerifier.from_public_bytes(pub)
            except Exception as e:
                return None, 0, f"invalid manifest public key: {e}"
            # proof of possession: the frame must be signed by that key
            if not (frame.flags & FrameFlags.FLAG_SIGNED) or not verifier.verify_frame(frame):
                return None, 0, "no proof of possession: registration frame not signed by the manifest key"
            return verifier, int(sm.manifest.allowed_capabilities), None

        # plain mode: if a key is presented, possession must be proven
        pub_hex = data.get("pub_bytes")
        if not pub_hex:
            return None, int(frame.capabilities_mask), "registration must present pub_bytes"
        try:
            pub = bytes.fromhex(pub_hex)
            verifier = AgentVerifier.from_public_bytes(pub)
        except Exception as e:
            return None, 0, f"invalid registration public key: {e}"
        if compute_pin(pub) != pin:
            return None, 0, "registration pub_bytes does not derive the claimed PIN"
        if not (frame.flags & FrameFlags.FLAG_SIGNED) or not verifier.verify_frame(frame):
            return None, 0, "no proof of possession: registration frame not signed by the presented key"
        return verifier, int(frame.capabilities_mask), None

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session: Optional[RelayClientSession] = None
        registered_pin: Optional[int] = None
        # SEC-03: peer identity lives on the CONNECTION (PSK handshake),
        # never inside a claimed name in a later frame
        peer_state: Dict[str, Optional[str]] = {"authed": None, "pending": None, "nonce": None}
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
                    if registered_pin is not None and frame.sender_pin != registered_pin:
                        # SEC-01: one connection = one authenticated identity;
                        # no pin switching after registration
                        self.metrics.platsec_denials.inc(action="ingress_pin_switch")
                        await self._refuse_now(
                            writer,
                            frame,
                            EacpError.EACP_ERR_SIGNATURE_INVALID,
                            "connection already authenticated for another PIN",
                        )
                        break
                    registered_pin = frame.sender_pin
                    verifier, grants, err_detail = self._validate_registration(frame)
                    if err_detail is not None:
                        self.metrics.platsec_denials.inc(action="register")
                        self._refuse(
                            writer,
                            frame,
                            EacpError.EACP_ERR_SIGNATURE_INVALID
                            if "possession" in err_detail or "signature" in err_detail or "key" in err_detail
                            else EacpError.EACP_ERR_CAPABILITY_DENIED,
                            f"Registration refused: {err_detail}",
                        )
                        registered_pin = None
                        continue

                    session = RelayClientSession(
                        pin=registered_pin,
                        reader=reader,
                        writer=writer,
                        verifier=verifier,
                        grants=grants,
                    )
                    self.grants[registered_pin] = grants
                    self.register_agent(registered_pin, session, verifier)

                    # Send ACK reply
                    ack = frame.create_reply(status=EacpError.EACP_SUCCESS, result_data={"registered": True, "pin": registered_pin})
                    await session.send_frame(ack)
                    continue

                # Mesh peer handshake (SEC-03): peer identity is established
                # on THIS connection via PSK challenge/response, never taken
                # from a claimed name inside a later frame
                if (
                    frame.msg_type == MsgType.MSG_RELAY_CONTROL
                    and frame.opcode in (OpCode.OP_RELAY_PEER_HELLO, OpCode.OP_RELAY_PEER_AUTH)
                ):
                    await self._peer_handshake_step(frame, writer, peer_state)
                    continue

                # Mesh route announcements: admitted only from a connection
                # that completed the peer handshake (and, for originated
                # frames, AS that origin). Forwarded announces ride an
                # authenticated peer's word that the origin told them so —
                # within the PSK trust boundary (ARCHITECTURE, mesh section).
                if frame.msg_type == MsgType.MSG_RELAY_CONTROL and frame.opcode == OpCode.OP_RELAY_ROUTE_ANNOUNCE:
                    data = frame.data if isinstance(frame.data, dict) else {}
                    origin = data.get("origin_peer")
                    pin = data.get("pin")
                    action = data.get("action")
                    authed_as = peer_state["authed"]
                    forwarded = bool(data.get("forwarded"))
                    admitted = authed_as is not None and (
                        origin == authed_as or (forwarded and origin in self.mesh.peers)
                    )
                    if not admitted:
                        self.metrics.platsec_denials.inc(action="announce_unauthed")
                        logger.warning(
                            f"Ignoring route announce: connection authenticated as {authed_as!r} "
                            f"may not announce for {origin!r} (peer handshake required)"
                        )
                        continue
                    if isinstance(pin, int):
                        if not data.get("forwarded"):
                            if action == "remove":
                                applied = self.mesh.release_remote(pin, authed_as)
                            else:
                                applied = self.mesh.register_remote(pin, authed_as)
                            if not applied:
                                logger.warning(
                                    f"Announce ownership refused: peer {authed_as!r} may not "
                                    f"modify the route of {format_pin(pin)}"
                                )
                                continue
                            # rebroadcast to the other peers (loop-safe:
                            # forwarded frames are never forwarded again)
                            await self.mesh.broadcast_route(
                                pin, action=action or "add", forwarded=True, exclude_peer=authed_as
                            )
                        # duplicates/forwarded frames already applied upstream
                    continue

                # SEC-01: authenticated ingress — application frames are
                # refused until THIS connection registers (or completes the
                # peer handshake), and a registered connection may only send
                # as its own authenticated PIN. Peer connections forward
                # remote agents' frames under the PSK trust established
                # above (their own agents authenticated them at their hop).
                if registered_pin is None and peer_state["authed"] is None:
                    self.metrics.platsec_denials.inc(action="ingress_unregistered")
                    logger.warning("Refusing application frame from an unregistered connection")
                    await self._refuse_now(
                        writer,
                        frame,
                        EacpError.EACP_ERR_SIGNATURE_INVALID,
                        "unauthenticated ingress: register before sending application frames",
                    )
                    break
                if registered_pin is not None and frame.sender_pin != registered_pin:
                    self.metrics.platsec_denials.inc(action="ingress_sender_mismatch")
                    logger.warning(
                        f"Sender mismatch: frame claims {format_pin(frame.sender_pin)} "
                        f"on a connection authenticated as {format_pin(registered_pin)}"
                    )
                    await self._refuse_now(
                        writer,
                        frame,
                        EacpError.EACP_ERR_SIGNATURE_INVALID,
                        "sender identity is not bound to this connection",
                    )
                    break

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

    # ------------------------------------------------------------------
    # mesh peer handshake (SEC-03)

    async def _peer_handshake_step(
        self, frame: EacpFrame, writer: asyncio.StreamWriter, peer_state: Dict[str, Optional[str]]
    ) -> None:
        """PSK challenge/response bound to THIS connection.

        The responder generates a fresh nonce per HELLO and must see an AUTH
        tagged with it: a captured exchange cannot authenticate a new
        connection. The challenge carries the responder's own tag so the
        initiator verifies the remote knows the PSK too (mutual auth).
        """
        data = frame.data if isinstance(frame.data, dict) else {}
        if frame.opcode == OpCode.OP_RELAY_PEER_HELLO:
            pid = data.get("peer_id")
            peer = self.mesh.peers.get(pid) if isinstance(pid, str) else None
            if peer is None or not peer.psk:
                logger.warning(f"Peer HELLO for {pid!r} refused: not a configured peer with a PSK")
                return
            nonce = secrets.token_hex(16)
            tag = peer_tag(peer.psk, "challenge", pid, nonce)
            peer_state["pending"] = pid
            peer_state["nonce"] = nonce
            chal = EacpFrame(
                msg_type=MsgType.MSG_RELAY_CONTROL,
                opcode=OpCode.OP_RELAY_PEER_CHALLENGE,
                sender_pin=0,
                target_pin=0,
                transaction_id=frame.transaction_id,
                data={"peer_id": pid, "nonce": nonce, "tag": tag},
            )
            writer.write(chal.pack())
            await writer.drain()
        elif frame.opcode == OpCode.OP_RELAY_PEER_AUTH:
            pid = data.get("peer_id")
            nonce = peer_state.get("nonce")
            if peer_state.get("pending") is None or pid != peer_state["pending"] or not isinstance(nonce, str):
                logger.warning("Peer AUTH refused: no matching outstanding challenge")
                return
            peer = self.mesh.peers.get(pid) if isinstance(pid, str) else None
            tag = str(data.get("tag", ""))
            if peer is None or not peer.psk or not hmac.compare_digest(
                tag, peer_tag(peer.psk, "auth", pid, nonce)
            ):
                logger.warning(f"Peer AUTH for {pid!r} failed PSK verification")
                peer_state["pending"] = None
                peer_state["nonce"] = None
                return
            peer_state["authed"] = pid
            peer_state["pending"] = None
            peer_state["nonce"] = None
            logger.info(f"Mesh peer authenticated on this connection: {pid}")

    # ------------------------------------------------------------------
    # routing

    async def route_frame(
        self,
        frame: EacpFrame,
        sender_session: Optional[RelayClientSession],
        writer: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        sender_pin = frame.sender_pin
        target_pin = frame.target_pin
        span_start = time.perf_counter()
        trace_id = None
        if isinstance(frame.data, dict) and isinstance(frame.data.get("_trace"), str):
            tc = TraceContext.parse(frame.data["_trace"])
            trace_id = tc.trace_id if tc else None

        # Audit ledger record & metrics tracking
        self.ledger.record(
            tx_id=frame.transaction_id,
            sender_pin=sender_pin,
            target_pin=target_pin,
            verb=frame.verb,
            capabilities_mask=frame.capabilities_mask,
            status=int(frame.status),
            data_payload=frame.raw_payload,
        )
        self.metrics.frames_total.inc(type=frame.msg_type.name, status=str(int(frame.status)))

        # 1. Authentication: a registered sender with a known key MUST be
        # signed (verification happens whenever the flag claims it; an
        # unsigned frame from a keyed sender is refused outright — the old
        # "only if the frame says so" check let unsigned privileged traffic
        # through). Pulses and relay-control are exempt (no signature room /
        # own handshake); remote senders were authenticated at ingress.
        verifier = self.verifiers.get(sender_pin)
        if verifier is not None and frame.msg_type in (MsgType.MSG_SEND, MsgType.MSG_REPLY):
            if not (frame.flags & FrameFlags.FLAG_SIGNED):
                self.metrics.platsec_denials.inc(action="route_unsigned")
                if frame.msg_type == MsgType.MSG_SEND and sender_session:
                    err_reply = frame.create_reply(status=EacpError.EACP_ERR_SIGNATURE_INVALID)
                    await sender_session.send_frame(err_reply)
                return
            if not verifier.verify_frame(frame):
                # Signature invalid, drop or reply with error
                self.metrics.platsec_denials.inc(action="route_signature")
                if frame.msg_type == MsgType.MSG_SEND and sender_session:
                    err_reply = frame.create_reply(status=EacpError.EACP_ERR_SIGNATURE_INVALID)
                    await sender_session.send_frame(err_reply)
                return
            # replay defense per session: (sender, tx) remembered only after
            # a valid signature, bounded window
            if sender_session is not None:
                if sender_session.seen_tx(frame.transaction_id):
                    self.metrics.platsec_denials.inc(action="route_replay")
                    logger.warning(
                        f"Replay refused: tx {frame.transaction_id} from {format_pin(sender_pin)}"
                    )
                    if frame.msg_type == MsgType.MSG_SEND:
                        await sender_session.send_frame(
                            frame.create_reply(status=EacpError.EACP_ERR_REPLAY_DETECTED)
                        )
                    return
                sender_session.remember_tx(frame.transaction_id)

        # 1b. Authorization: claimed capabilities must fit the authenticated
        # registration grants (defense at the trust anchor; the receiver
        # additionally applies caller-manifest + its own policy)
        if frame.msg_type == MsgType.MSG_SEND:
            claimed = frame.capabilities_mask
            allowed = self.grants.get(sender_pin)
            if allowed is not None and (claimed & ~allowed):
                self.metrics.platsec_denials.inc(action="route_claims")
                if sender_session:
                    await sender_session.send_frame(
                        frame.create_reply(
                            status=EacpError.EACP_ERR_CAPABILITY_DENIED,
                            result_data={
                                "error": "claimed capabilities exceed registration grants",
                                "claimed": claimed,
                                "granted": allowed,
                            },
                        )
                    )
                return

        # 2. QNX Synchronous Rendezvous & Deadlock Detection (per transaction)
        if frame.msg_type == MsgType.MSG_SEND:
            # Check deadlock cycle before routing
            if not self.deadlock_graph.add_dependency(sender_pin, target_pin, frame.transaction_id):
                # Deadlock detected! Reply immediately with error
                self.metrics.deadlocks_prevented.inc()
                err_reply = frame.create_reply(status=EacpError.EACP_ERR_DEADLOCK_DETECTED)
                if sender_session:
                    await sender_session.send_frame(err_reply)
                return

        elif frame.msg_type == MsgType.MSG_REPLY:
            # Reply releases THE transaction's dependency
            self.deadlock_graph.remove_dependency(target_pin, frame.transaction_id)

        elif frame.msg_type == MsgType.MSG_PULSE:
            code, _ = frame.get_pulse_data()
            if code == PulseCode.PULSE_CANCEL:
                # Cancel frees exactly that transaction's dependency
                self.deadlock_graph.remove_dependency(sender_pin, frame.transaction_id)

        # 3. Route to target (Local session or Remote Peer in Mesh)
        target_session = self.routes.get(target_pin)
        if target_session and not target_session.closed:
            await target_session.send_frame(frame)
            self._trace_span("route.local", frame, trace_id, span_start)
            return

        # Check peer mesh routing
        peer = self.mesh.get_peer_for_pin(target_pin)
        if peer and peer.connected:
            try:
                await peer.send_frame(frame)
                self._trace_span("route.peer", frame, trace_id, span_start)
                return
            except Exception as exc:
                logger.warning(f"Peer route failed ({peer.peer_id}): {exc}; falling back to offline queue")
                peer.close()

        # Target is offline
        now = time.monotonic()
        if frame.msg_type == MsgType.MSG_SEND:
            # If urgent or no buffering allowed, return unknown PIN immediately
            if frame.flags & FrameFlags.FLAG_URGENT:
                self.deadlock_graph.remove_dependency(sender_pin, frame.transaction_id)
                if sender_session:
                    err_reply = frame.create_reply(status=EacpError.EACP_ERR_UNKNOWN_PIN)
                    await sender_session.send_frame(err_reply)
            else:
                # Buffer message in push queue (global budgets; explicit error)
                if not self._buffer_frame(target_pin, frame, now):
                    self.deadlock_graph.remove_dependency(sender_pin, frame.transaction_id)
                    logger.warning(
                        f"Offline queue budget exceeded ({self._queued_total} frames / {self._queued_bytes} bytes); "
                        f"refusing tx {frame.transaction_id}"
                    )
                    if sender_session:
                        await sender_session.send_frame(
                            frame.create_reply(
                                status=EacpError.EACP_ERR_QUEUE_FULL,
                                result_data={"error": "offline queue budget exceeded"},
                            )
                        )
        elif frame.msg_type in (MsgType.MSG_PULSE, MsgType.MSG_REPLY):
            # For replies where target is lost, clear deadlock edge
            if frame.msg_type == MsgType.MSG_REPLY:
                self.deadlock_graph.remove_dependency(target_pin, frame.transaction_id)
            # Store pulse or drop — overflow here is logged, never silent
            if not self._buffer_frame(target_pin, frame, now):
                logger.warning(
                    f"Offline queue budget exceeded; dropping {frame.msg_type.name} for {format_pin(target_pin)}"
                )

        self._trace_span("route.offline", frame, trace_id, span_start)

    def _trace_span(self, span: str, frame: EacpFrame, trace_id: Optional[str], start: float) -> None:
        """Span around routing: structured log line with the propagated
        trace id and the routing duration (wire carries `_trace`)."""
        ms = (time.perf_counter() - start) * 1000.0
        logger.debug(
            "span=%s tx=%d trace=%s ms=%.3f",
            span,
            frame.transaction_id,
            trace_id or "-",
            ms,
        )

    # ------------------------------------------------------------------
    # maintenance loops

    async def _heartbeat_reaper(self) -> None:
        """Periodically prunes dead agent connections, expires offline
        queues, redials mesh peers, and refreshes local route announces."""
        try:
            while self._running:
                await asyncio.sleep(min(15.0, max(0.05, self.heartbeat_timeout_s / 2.0)))
                now = time.monotonic()
                for pin, session in list(self.routes.items()):
                    if (now - session.last_seen) > self.heartbeat_timeout_s:
                        logger.warning(
                            f"Agent-PIN {format_pin(pin)} heartbeat timed out ({now - session.last_seen:.1f}s), closing dead route"
                        )
                        self.unregister_agent(pin)
                        session.close()
                # offline queue expiry (a message must not wait forever just
                # because its target never re-registers)
                await self.expire_queued()
                # mesh peer recovery: redial configured peers that dropped
                await self.mesh.ensure_links()
                # refresh local routes periodically (announce-loss resilience)
                for pin in self.mesh.local_pins():
                    self._announce(pin, "add")
        except asyncio.CancelledError:
            pass

    async def start(
        self,
        host: Optional[str] = "127.0.0.1",
        port: Optional[int] = 8990,
        unix_path: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self._running = True
        self.unix_path = unix_path
        if unix_path:
            if os.path.exists(unix_path):
                os.unlink(unix_path)
            self.server = await asyncio.start_unix_server(self.handle_connection, path=unix_path)
            logger.info(f"EACP Relay started on unix socket {unix_path}")
        elif host is not None and port is not None:
            self.server = await asyncio.start_server(self.handle_connection, host, port, ssl=ssl_context)
            proto = "mTLS/TLS" if ssl_context else "TCP"
            logger.info(f"EACP Relay started on {host}:{port} ({proto})")

        self._reaper_task = asyncio.create_task(self._heartbeat_reaper())

    async def stop(self) -> None:
        self._running = False
        if self._reaper_task and not self._reaper_task.done():
            self._reaper_task.cancel()
        # peers FIRST (see MeshRoutingTable.close_all): an open peer
        # transport keeps its connection handler alive and wait_closed()
        # would block forever
        self.mesh.close_all()
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
        closer = getattr(self.ledger, "close", None)
        if closer is not None:
            try:
                closer()
            except Exception:
                pass


def main() -> None:
    """Portable CLI entry point to run the EACP Push Relay Daemon."""
    import argparse
    parser = argparse.ArgumentParser(description="EACP Push Relay Daemon (Microkernel Enterprise Mesh)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8990, help="Listen port (default: 8990)")
    parser.add_argument("--socket", default=None, help="Listen on Unix domain socket path")
    parser.add_argument("--max-queue", type=int, default=1000, help="Max offline push queue per agent")
    parser.add_argument("--max-queue-total", type=int, default=10_000, help="Global offline queue frame budget")
    parser.add_argument("--max-queue-mb", type=int, default=64, help="Global offline queue byte budget (MB)")
    parser.add_argument("--max-payload-mb", type=int, default=16, help="Max frame payload size in MB")
    parser.add_argument("--heartbeat-timeout", type=float, default=90.0, help="Heartbeat timeout in seconds")
    args = parser.parse_args()

    async def _run() -> None:
        relay = EacpRelay(
            max_push_queue=args.max_queue,
            max_queue_total=args.max_queue_total,
            max_queue_bytes=args.max_queue_mb * 1024 * 1024,
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