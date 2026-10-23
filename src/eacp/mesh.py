"""
EACP Multi-Relay Mesh Subsystem:
Cross-Relay peer routing and distributed Agent-PIN presence across multi-cloud/multi-AZ deployments.
Eliminates Single Point of Failure (SPOF).
"""

from __future__ import annotations
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple

from .constants import EacpError, MsgType, OpCode
from .frame import EacpFrame
from .security import format_pin

logger = logging.getLogger("eacp.mesh")


class RelayPeer:
    """Represents a connection to a peer EACP Relay instance in the mesh."""

    def __init__(self, peer_id: str, host: str, port: int):
        self.peer_id = peer_id
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected: bool = False

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.connected = True
            return True
        except Exception as e:
            logger.warning(f"Could not connect to peer {self.peer_id} ({self.host}:{self.port}): {e}")
            self.connected = False
            return False

    async def send_frame(self, frame: EacpFrame) -> None:
        if self.writer and self.connected:
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
    """
    Tracks which Agent-PINs are hosted locally vs on remote Relay peers.
    """

    def __init__(self, local_relay_id: str):
        self.local_relay_id = local_relay_id
        # Maps pin -> peer_id (None means locally hosted on this relay)
        self._routes: Dict[int, Optional[str]] = {}
        self.peers: Dict[str, RelayPeer] = {}

    def register_local(self, pin: int) -> None:
        self._routes[pin] = None

    def register_remote(self, pin: int, peer_id: str) -> None:
        self._routes[pin] = peer_id

    def unregister(self, pin: int) -> None:
        self._routes.pop(pin, None)

    def is_local(self, pin: int) -> bool:
        return pin in self._routes and self._routes[pin] is None

    def get_peer_for_pin(self, pin: int) -> Optional[RelayPeer]:
        peer_id = self._routes.get(pin)
        if peer_id:
            return self.peers.get(peer_id)
        return None

    def add_peer(self, peer: RelayPeer) -> None:
        self.peers[peer.peer_id] = peer

    async def broadcast_route(self, pin: int, action: str = "add") -> None:
        """Announces agent presence to all active peers in the mesh."""
        announce_frame = EacpFrame(
            msg_type=MsgType.MSG_RELAY_CONTROL,
            opcode=OpCode.OP_RELAY_ROUTE_ANNOUNCE,
            sender_pin=0,
            target_pin=0,
            verb="route_announce",
            data={"pin": pin, "action": action, "origin_peer": self.local_relay_id},
        )
        for peer in self.peers.values():
            if peer.connected:
                try:
                    await peer.send_frame(announce_frame)
                except Exception as exc:
                    logger.warning(f"Failed to announce route to peer {peer.peer_id}: {exc}")
