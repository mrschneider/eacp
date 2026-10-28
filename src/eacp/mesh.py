"""
EACP Multi-Relay Mesh Subsystem:
Cross-Relay peer routing and distributed Agent-PIN presence across multi-cloud/multi-AZ deployments.
Eliminates Single Point of Failure (SPOF).

Peering model (honest scope): peers are configured explicitly; route
announcements are origin-bound (only a configured peer id may announce, and
only for its own routes) and are rebroadcast at most once (forwarded frames
are never forwarded again — no loops). Confidentiality/authenticity of the
peering transport is the operator's TLS/mTLS context
(`RelayPeer.ssl_context`); frame-level relay signatures are not part of the
protocol yet (documented gap).
"""

from __future__ import annotations
import asyncio
import logging
import ssl
from typing import Dict, List, Optional

from .constants import MsgType, OpCode
from .frame import EacpFrame

logger = logging.getLogger("eacp.mesh")


class RelayPeer:
    """Represents a connection to a peer EACP Relay instance in the mesh."""

    CONNECT_TIMEOUT_S = 5.0

    def __init__(self, peer_id: str, host: str, port: int, ssl_context: Optional[ssl.SSLContext] = None):
        self.peer_id = peer_id
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected: bool = False

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self.ssl_context),
                timeout=self.CONNECT_TIMEOUT_S,
            )
            self.connected = True
            return True
        except Exception as e:
            logger.warning(f"Could not connect to peer {self.peer_id} ({self.host}:{self.port}): {e}")
            self.connected = False
            return False

    async def ensure_connected(self) -> bool:
        """Idempotent connect: the recovery path for dropped peer links."""
        if self.connected:
            return True
        return await self.connect()

    async def send_frame(self, frame: EacpFrame) -> None:
        if not (self.writer and self.connected):
            raise ConnectionError(f"peer {self.peer_id} not connected")
        self.writer.write(frame.pack())
        await self.writer.drain()

    def close(self) -> None:
        self.connected = False
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


class MeshRoutingTable:
    """Tracks which Agent-PINs are hosted locally vs on remote Relay peers."""

    def __init__(self, local_relay_id: str):
        self.local_relay_id = local_relay_id
        # Maps pin -> peer_id (None means locally hosted on this relay)
        self._routes: Dict[int, Optional[str]] = {}
        self.peers: Dict[str, RelayPeer] = {}

    def register_local(self, pin: int) -> None:
        self._routes[pin] = None

    def register_remote(self, pin: int, peer_id: str) -> None:
        if self.is_local(pin):
            # a local mapping always wins: an announce must never clobber
            # an agent this relay actually hosts (an UNKNOWN pin is fine)
            return
        self._routes[pin] = peer_id

    def unregister(self, pin: int) -> None:
        self._routes.pop(pin, None)

    def is_local(self, pin: int) -> bool:
        return pin in self._routes and self._routes[pin] is None

    def local_pins(self) -> List[int]:
        return [pin for pin, dest in self._routes.items() if dest is None]

    def get_peer_for_pin(self, pin: int) -> Optional[RelayPeer]:
        peer_id = self._routes.get(pin)
        if peer_id:
            return self.peers.get(peer_id)
        return None

    def add_peer(self, peer: RelayPeer) -> None:
        self.peers[peer.peer_id] = peer

    def close_all(self) -> None:
        """Closes every peer connection. Must run BEFORE the relay closes
        its listener: start_server().wait_closed() blocks until every
        inbound handle_connection task returns, and those tasks only end
        when their transport drops."""
        for peer in self.peers.values():
            peer.close()

    async def ensure_links(self) -> None:
        """Redial configured peers that dropped (failure recovery)."""
        for peer in self.peers.values():
            if not peer.connected:
                await peer.ensure_connected()

    async def broadcast_route(
        self,
        pin: int,
        action: str = "add",
        forwarded: bool = False,
        exclude_peer: Optional[str] = None,
    ) -> None:
        """Announces agent presence to all active peers in the mesh.

        `forwarded=True` marks a rebroadcast of a received announce: the
        receiver applies it but never forwards it again (one rebroadcast
        hop — no loops, and `origin_peer` stays the true origin).
        """
        data = {"pin": pin, "action": action, "origin_peer": self.local_relay_id}
        if forwarded:
            data["forwarded"] = True
        announce_frame = EacpFrame(
            msg_type=MsgType.MSG_RELAY_CONTROL,
            opcode=OpCode.OP_RELAY_ROUTE_ANNOUNCE,
            sender_pin=0,
            target_pin=0,
            verb="route_announce",
            data=data,
        )
        for peer in self.peers.values():
            if exclude_peer is not None and peer.peer_id == exclude_peer:
                continue
            if peer.connected:
                try:
                    await peer.send_frame(announce_frame)
                except Exception as exc:
                    logger.warning(f"Failed to announce route to peer {peer.peer_id}: {exc}")
                    peer.close()