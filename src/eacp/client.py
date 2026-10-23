"""
EACP Agent Client Subsystem: Symbian-style RSessionBase client handle,
PlatSec gate integration, and asynchronous frame pump.
"""

from __future__ import annotations
import asyncio
import inspect
import itertools
import logging
from typing import Any, Callable, Coroutine, Dict, Optional

from .constants import (
    EACP_MAGIC,
    HEADER_SIZE,
    Capability,
    EacpError,
    FrameFlags,
    MsgType,
    OpCode,
    PulseCode,
)
from .frame import CryptoEnvelope, EacpFrame, ExecutionConstraints, HEADER_STRUCT
from .primitives import EacpRendezvousException
from .security import AgentIdentity, PlatSecGate, SecurityManifest, format_pin

logger = logging.getLogger("eacp.client")


class RSessionBase:
    """
    Symbian RSessionBase client handle connecting an agent to the EACP-Relay.
    Provides synchronous rendezvous primitives and PlatSec gate enforcement.
    """

    _tx_counter = itertools.count(1)

    def __init__(
        self,
        identity: Optional[AgentIdentity] = None,
        allowed_capabilities: Capability = Capability.NONE,
        strict_mode: bool = False,
    ):
        self.identity: AgentIdentity = identity or AgentIdentity.generate()
        self.manifest: SecurityManifest = SecurityManifest(
            pin=self.identity.pin,
            allowed_capabilities=allowed_capabilities,
            public_bytes=self.identity.public_bytes,
        )
        self.gate: PlatSecGate = PlatSecGate(self.manifest, strict_mode=strict_mode)
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._pump_task: Optional[asyncio.Task] = None
        
        self._pending_replies: Dict[int, asyncio.Future[EacpFrame]] = {}
        self._incoming_requests: asyncio.Queue[EacpFrame] = asyncio.Queue()
        self._action_handlers: Dict[str, Callable[..., Any]] = {}
        self._pulse_callbacks: Dict[int, Callable[[int, int], Any]] = {}
        self._connected: bool = False

    @property
    def pin(self) -> int:
        return self.identity.pin

    @property
    def pin_hex(self) -> str:
        return self.identity.pin_hex

    def register_tool(self, action: str, required_caps: Capability) -> None:
        """Registers a tool with PlatSec capability requirements."""
        self.gate.register_tool(action, required_caps)

    def register_handler(
        self,
        action: str,
        handler: Callable[[EacpFrame], Any],
        required_caps: Capability = Capability.NONE,
    ) -> None:
        """Registers an action handler callback with PlatSec protection."""
        self.register_tool(action, required_caps)
        self._action_handlers[action] = handler

    def register_pulse_callback(self, code: int | PulseCode, callback: Callable[[int, int], Any]) -> None:
        self._pulse_callbacks[int(code)] = callback

    async def connect(
        self,
        host: Optional[str] = "127.0.0.1",
        port: Optional[int] = 8990,
        unix_path: Optional[str] = None,
    ) -> None:
        """Connects to EACP Relay via TCP or Unix Domain Socket and performs registration."""
        if unix_path:
            self.reader, self.writer = await asyncio.open_unix_connection(unix_path)
        else:
            self.reader, self.writer = await asyncio.open_connection(host or "127.0.0.1", port or 8990)
        self._connected = True
        self._pump_task = asyncio.create_task(self._frame_pump())

        # Send registration frame
        reg_frame = EacpFrame(
            msg_type=MsgType.MSG_RELAY_CONTROL,
            opcode=OpCode.OP_RELAY_REGISTER,
            sender_pin=self.identity.pin,
            target_pin=0,
            transaction_id=next(self._tx_counter),
            capabilities_mask=int(self.manifest.allowed_capabilities),
            data={"pub_bytes": self.identity.public_bytes.hex()},
        )
        self.identity.sign_frame(reg_frame)

        reply = await self._send_and_await_reply(reg_frame, timeout_ms=5000)
        if reply.status != EacpError.EACP_SUCCESS:
            await self.close()
            raise RuntimeError(f"Failed to register with EACP Relay: status={reply.status}")

    async def _send_and_await_reply(self, frame: EacpFrame, timeout_ms: int = 5000) -> EacpFrame:
        if not self._connected or not self.writer:
            raise ConnectionError("RSessionBase is not connected")

        fut: asyncio.Future[EacpFrame] = asyncio.get_running_loop().create_future()
        self._pending_replies[frame.transaction_id] = fut

        try:
            data = frame.pack()
            self.writer.write(data)
            await self.writer.drain()

            timeout_sec = timeout_ms / 1000.0 if timeout_ms > 0 else None
            return await asyncio.wait_for(fut, timeout=timeout_sec)
        except asyncio.TimeoutError:
            # Inform relay via PULSE_CANCEL to unblock deadlock dependency immediately
            try:
                cancel_pulse = EacpFrame.create_pulse(
                    sender_pin=self.identity.pin,
                    target_pin=frame.target_pin,
                    pulse_code=PulseCode.PULSE_CANCEL,
                    tx_id=frame.transaction_id,
                )
                self.writer.write(cancel_pulse.pack())
                await self.writer.drain()
            except Exception:
                pass

            raise EacpRendezvousException(
                EacpError.EACP_ERR_TIMEOUT,
                f"Rendezvous timeout ({timeout_ms}ms) awaiting reply for tx {frame.transaction_id}",
                frame,
            )
        finally:
            self._pending_replies.pop(frame.transaction_id, None)

    async def send(
        self,
        target_pin: int,
        verb: str,
        data: Any = None,
        constraints: Optional[ExecutionConstraints] = None,
        opcode: int = OpCode.OP_ACTION_INVOKE,
        capabilities_mask: Optional[int] = None,
    ) -> EacpFrame:
        """
        Emits synchronous MsgSend rendezvous request.
        Caller enters REPLY_BLOCKED until MsgReply arrives or timeout.
        """
        constr = constraints or ExecutionConstraints()
        cap_mask = capabilities_mask if capabilities_mask is not None else int(self.manifest.allowed_capabilities)

        frame = EacpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=opcode,
            sender_pin=self.identity.pin,
            target_pin=target_pin,
            transaction_id=next(self._tx_counter),
            capabilities_mask=cap_mask,
            verb=verb,
            data=data,
            constraints=constr,
        )
        self.identity.sign_frame(frame)

        reply = await self._send_and_await_reply(frame, timeout_ms=constr.timeout_ms)
        if reply.status != EacpError.EACP_SUCCESS:
            raise EacpRendezvousException(
                reply.status,
                f"EACP MsgSend failed with status {reply.status!r}",
                reply,
            )
        return reply

    async def reply(
        self,
        request_frame: EacpFrame,
        status: int | EacpError = EacpError.EACP_SUCCESS,
        result_data: Any = None,
    ) -> None:
        """Sends MsgReply completing rendezvous transaction."""
        if not self._connected or not self.writer:
            raise ConnectionError("RSessionBase is not connected")

        reply_frame = request_frame.create_reply(status=int(status), result_data=result_data)
        self.identity.sign_frame(reply_frame)
        self.writer.write(reply_frame.pack())
        await self.writer.drain()

    async def pulse(
        self,
        target_pin: int,
        pulse_code: int | PulseCode,
        pulse_value: int = 0,
    ) -> None:
        """Emits non-blocking 8-byte pulse."""
        if not self._connected or not self.writer:
            raise ConnectionError("RSessionBase is not connected")

        pulse_frame = EacpFrame.create_pulse(
            sender_pin=self.identity.pin,
            target_pin=target_pin,
            pulse_code=pulse_code,
            pulse_value=pulse_value,
            tx_id=next(self._tx_counter),
        )
        self.writer.write(pulse_frame.pack())
        await self.writer.drain()

    async def receive(self, timeout_ms: Optional[int] = None) -> EacpFrame:
        """Awaits next incoming request frame from Relay queue."""
        timeout_sec = timeout_ms / 1000.0 if timeout_ms is not None else None
        try:
            return await asyncio.wait_for(self._incoming_requests.get(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            raise EacpRendezvousException(
                EacpError.EACP_ERR_TIMEOUT,
                "Timed out waiting for MsgReceive",
            )

    async def _frame_pump(self) -> None:
        """Background pump reading frames from Relay transport."""
        assert self.reader is not None
        try:
            while self._connected:
                hdr_bytes = await self.reader.readexactly(HEADER_SIZE)
                if not hdr_bytes:
                    break

                magic, ver, msg_type_raw, opcode, flags_raw, sender_pin, target_pin, tx_id, cap_mask, status_raw, payload_len = HEADER_STRUCT.unpack(hdr_bytes)

                if magic != EACP_MAGIC:
                    logger.error("Invalid magic in client stream")
                    break

                payload = b""
                if payload_len > 0:
                    payload = await self.reader.readexactly(payload_len)

                frame = EacpFrame.unpack(hdr_bytes + payload)

                # Route frame
                if frame.msg_type == MsgType.MSG_REPLY or (frame.msg_type == MsgType.MSG_RELAY_CONTROL and frame.transaction_id in self._pending_replies):
                    fut = self._pending_replies.get(frame.transaction_id)
                    if fut and not fut.done():
                        fut.set_result(frame)

                elif frame.msg_type == MsgType.MSG_PULSE:
                    code, val = frame.get_pulse_data()
                    # Check registered callback
                    cb = self._pulse_callbacks.get(code)
                    if cb:
                        res = cb(code, val)
                        if inspect.iscoroutine(res):
                            asyncio.create_task(res)
                    else:
                        await self._incoming_requests.put(frame)

                elif frame.msg_type == MsgType.MSG_SEND:
                    # If registered handler exists, execute through PlatSec gate
                    if frame.verb in self._action_handlers:
                        asyncio.create_task(self._dispatch_handler(frame))
                    else:
                        await self._incoming_requests.put(frame)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error(f"Client frame pump exception: {e}", exc_info=True)
        finally:
            self._connected = False
            for fut in list(self._pending_replies.values()):
                if not fut.done():
                    fut.set_exception(ConnectionError("Connection closed"))
            self._pending_replies.clear()

    @staticmethod
    def create_downstream_constraints(
        frame: EacpFrame,
        token_budget: Optional[int] = None,
        timeout_ms: Optional[int] = None,
    ) -> ExecutionConstraints:
        """
        Creates child execution constraints with decremented max_depth_hops
        to prevent infinite agentic delegation cycles.
        """
        parent_hops = frame.constraints.max_depth_hops if frame.constraints else 10
        budget = token_budget if token_budget is not None else (frame.constraints.token_budget if frame.constraints else 0)
        timeout = timeout_ms if timeout_ms is not None else (frame.constraints.timeout_ms if frame.constraints else 5000)
        return ExecutionConstraints(
            token_budget=budget,
            timeout_ms=timeout,
            max_depth_hops=max(0, parent_hops - 1),
        )

    async def _dispatch_handler(self, frame: EacpFrame) -> None:
        """Invokes handler with PlatSec capability enforcement and hop limit check."""
        handler = self._action_handlers.get(frame.verb)
        if not handler:
            await self.reply(frame, status=EacpError.EACP_ERR_MALFORMED_FRAME)
            return

        # Execution constraints check (max_depth_hops)
        if frame.constraints and frame.constraints.max_depth_hops <= 0:
            await self.reply(
                frame,
                status=EacpError.EACP_ERR_DEPTH_EXCEEDED,
                result_data={"error": "EACP execution depth exceeded (max_depth_hops reached 0)"},
            )
            return

        # PlatSec capability check
        allowed, err_code = self.gate.evaluate(frame.capabilities_mask, frame.verb)
        if not allowed:
            await self.reply(frame, status=err_code, result_data={"error": "PlatSec capability denied"})
            return

        try:
            res = handler(frame)
            if inspect.iscoroutine(res):
                res = await res
            await self.reply(frame, status=EacpError.EACP_SUCCESS, result_data=res)
        except Exception as exc:
            logger.error(f"Error executing action {frame.verb}: {exc}", exc_info=True)
            await self.reply(frame, status=EacpError.EACP_ERR_CANCELLED, result_data={"error": str(exc)})

    async def close(self) -> None:
        """Closes client session."""
        self._connected = False
        if self._pump_task and not self._pump_task.done():
            self._pump_task.cancel()
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        self.writer = None
        self.reader = None
