"""
EACP Agent Client Subsystem: RSessionBase client handle,
out-of-band pulse emission, and active dispatch loop.
"""

from __future__ import annotations
import asyncio
import inspect
import itertools
import logging
import ssl
import time
from typing import Any, Callable, Coroutine, Dict, Optional, Tuple

from .constants import (
    DEFAULT_HEARTBEAT_INTERVAL_S,
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
from .frame import CryptoEnvelope, EacpFrame, ExecutionConstraints, HEADER_STRUCT
from .primitives import EacpRendezvousException
from .security import (
    AgentIdentity,
    EnterpriseCA,
    PlatSecGate,
    SecurityManifest,
    SignedManifest,
    compute_pin,
    format_pin,
)
from .telemetry import TraceContext
from .budget import (
    BudgetError,
    PayloadTokenMeter,
    TokenBudgetLedger,
    TokenMeter,
)

logger = logging.getLogger("eacp.client")


class RSessionBase:
    """
    RSessionBase client handle connecting an agent to the EACP-Relay.
    Provides synchronous rendezvous primitives and PlatSec gate enforcement.
    """

    _tx_counter = itertools.count(1)

    def __init__(
        self,
        identity: Optional[AgentIdentity] = None,
        allowed_capabilities: Capability = Capability.NONE,
        strict_mode: bool = False,
        signed_manifest: Optional[SignedManifest] = None,
        heartbeat_interval_s: float = DEFAULT_HEARTBEAT_INTERVAL_S,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        token_meter: Optional[TokenMeter] = None,
        token_ledger_capacity: int = 1_000_000,
        enterprise_ca: Optional[EnterpriseCA] = None,
        max_concurrent_handlers: int = 64,
    ):
        self.identity: AgentIdentity = identity or AgentIdentity.generate()
        self.signed_manifest = signed_manifest
        self.manifest: SecurityManifest = (
            signed_manifest.manifest
            if signed_manifest
            else SecurityManifest(
                pin=self.identity.pin,
                allowed_capabilities=allowed_capabilities,
                public_bytes=self.identity.public_bytes,
            )
        )
        self.gate: PlatSecGate = PlatSecGate(self.manifest, strict_mode=strict_mode)
        self.heartbeat_interval_s = heartbeat_interval_s
        self.max_payload_size = max_payload_size
        self.token_meter: TokenMeter = token_meter or PayloadTokenMeter()
        self.ledger: TokenBudgetLedger = TokenBudgetLedger(ledger_capacity=token_ledger_capacity)
        # CA mode: incoming callers must prove CA-attested grants
        self.enterprise_ca = enterprise_ca
        self._max_concurrent_handlers = max_concurrent_handlers
        self._handler_gate: Optional[asyncio.Semaphore] = None
        # request registry: (sender_pin, tx_id) -> in-flight handler task
        self._inflight: Dict[Tuple[int, int], asyncio.Task] = {}
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._pump_task: Optional[asyncio.Task[None]] = None
        self._heartbeat_task: Optional[asyncio.Task[None]] = None
        
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
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        """Connects to EACP Relay via TCP/mTLS or Unix Domain Socket and performs registration."""
        if unix_path:
            self.reader, self.writer = await asyncio.open_unix_connection(unix_path)
        else:
            self.reader, self.writer = await asyncio.open_connection(
                host or "127.0.0.1", port or 8990, ssl=ssl_context
            )
        self._connected = True
        self._pump_task = asyncio.create_task(self._frame_pump())

        reg_data: Dict[str, Any] = {"pub_bytes": self.identity.public_bytes.hex()}
        if self.signed_manifest:
            reg_data["signed_manifest"] = {
                "pin": self.signed_manifest.manifest.pin,
                "allowed_capabilities": int(self.signed_manifest.manifest.allowed_capabilities),
                "public_bytes": self.signed_manifest.manifest.public_bytes.hex() if self.signed_manifest.manifest.public_bytes else "",
                "ca_pin": self.signed_manifest.ca_pin,
                "ca_public_bytes": self.signed_manifest.ca_public_bytes.hex(),
                "signature": self.signed_manifest.signature.hex(),
                "expires_at": self.signed_manifest.expires_at,
            }

        # Send registration frame
        reg_frame = EacpFrame(
            msg_type=MsgType.MSG_RELAY_CONTROL,
            opcode=OpCode.OP_RELAY_REGISTER,
            sender_pin=self.identity.pin,
            target_pin=0,
            transaction_id=next(self._tx_counter),
            capabilities_mask=int(self.manifest.allowed_capabilities),
            data=reg_data,
        )
        self.identity.sign_frame(reg_frame)

        reply = await self._send_and_await_reply(reg_frame, timeout_ms=5000)
        if reply.status != EacpError.EACP_SUCCESS:
            await self.close()
            raise RuntimeError(f"Failed to register with EACP Relay: status={reply.status}")

        # Start periodic keepalive heartbeat if configured
        if self.heartbeat_interval_s > 0:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self) -> None:
        """Periodically emits heartbeat pulse to maintain presence across edge/cloud networks."""
        try:
            while self._connected:
                await asyncio.sleep(self.heartbeat_interval_s)
                if not self._connected or not self.writer:
                    break
                try:
                    await self.pulse(target_pin=0, pulse_code=PulseCode.PULSE_HEARTBEAT, pulse_value=0)
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass

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
        trace_context: Optional[TraceContext] = None,
    ) -> EacpFrame:
        """
        Emits synchronous MsgSend rendezvous request.
        Caller enters REPLY_BLOCKED until MsgReply arrives or timeout.
        """
        constr = constraints or ExecutionConstraints()
        cap_mask = capabilities_mask if capabilities_mask is not None else int(self.manifest.allowed_capabilities)
        tc = trace_context or TraceContext.new_root()
        # Wire propagation (additive JSON keys, authenticated by the frame
        # signature that is applied below): the trace context travels with
        # the request, and in CA mode the caller's CA-attested manifest
        # travels too so the receiver can authorize against GRANTS rather
        # than against a self-made claim.
        if isinstance(data, dict):
            data = dict(data)  # never mutate the caller's dict
            data.setdefault("_trace", tc.to_header())
            if self.signed_manifest is not None:
                data["_caller_manifest"] = self.signed_manifest.to_dict()

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
        remaining_budget: Optional[int] = None,
    ) -> None:
        """Sends MsgReply completing rendezvous transaction."""
        if not self._connected or not self.writer:
            raise ConnectionError("RSessionBase is not connected")

        reply_frame = request_frame.create_reply(status=int(status), result_data=result_data)
        if remaining_budget is not None:
            # Slot 2 on the reply carries the budget REMAINING after settlement,
            # letting the caller cascade the unused envelope downstream.
            reply_frame.constraints = ExecutionConstraints(
                token_budget=remaining_budget,
                timeout_ms=request_frame.constraints.timeout_ms if request_frame.constraints else 5000,
                max_depth_hops=request_frame.constraints.max_depth_hops if request_frame.constraints else 10,
            )
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

                if payload_len > self.max_payload_size:
                    logger.error(
                        f"Incoming payload {payload_len} exceeds max payload limit {self.max_payload_size}. Disconnecting."
                    )
                    break

                payload = b""
                if payload_len > 0:
                    payload = await self.reader.readexactly(payload_len)

                frame = EacpFrame.unpack(hdr_bytes + payload, max_payload_size=self.max_payload_size)

                # Route frame
                if frame.msg_type == MsgType.MSG_REPLY or (frame.msg_type == MsgType.MSG_RELAY_CONTROL and frame.transaction_id in self._pending_replies):
                    fut = self._pending_replies.get(frame.transaction_id)
                    if fut and not fut.done():
                        fut.set_result(frame)
                    elif frame.msg_type == MsgType.MSG_REPLY:
                        # reply correlation: a reply nobody is waiting for is
                        # logged, never silently swallowed
                        logger.debug("unexpected reply for tx %s (no waiter)", frame.transaction_id)

                elif frame.msg_type == MsgType.MSG_PULSE:
                    code, val = frame.get_pulse_data()
                    if code == PulseCode.PULSE_CANCEL:
                        # cancellation is real: the in-flight handler task is
                        # cancelled at its await point (escrow refunded in
                        # the handler's cleanup), not merely noted
                        task = self._inflight.get((frame.sender_pin, frame.transaction_id))
                        if task is not None and not task.done():
                            logger.debug(
                                "PULSE_CANCEL for tx %s from %s: cancelling handler",
                                frame.transaction_id,
                                frame.sender_pin,
                            )
                            task.cancel()
                    # Check registered callback
                    cb = self._pulse_callbacks.get(code)
                    if cb:
                        res = cb(code, val)
                        if inspect.iscoroutine(res):
                            asyncio.create_task(res)
                    else:
                        await self._incoming_requests.put(frame)

                elif frame.msg_type == MsgType.MSG_SEND:
                    # If registered handler exists, execute through PlatSec
                    # gate inside the request registry (bounded concurrency,
                    # cancellation, disconnect cleanup)
                    if frame.verb in self._action_handlers:
                        task = asyncio.create_task(self._dispatch_handler(frame))
                        self._inflight[(frame.sender_pin, frame.transaction_id)] = task
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
        tokens_used: int = 0,
    ) -> ExecutionConstraints:
        """
        Creates child execution constraints with decremented max_depth_hops.
        When `tokens_used` is given, the child budget is the parent's
        remaining envelope after the parent's own consumption (cascade
        accounting): parent_budget - tokens_used.
        """
        from .budget import create_downstream_constraints as cascade_constraints

        if tokens_used:
            child = cascade_constraints(frame, tokens_used, timeout_ms=timeout_ms)
            if token_budget is not None:
                # explicit cap: never replace an unlimited child with None,
                # and take the tighter of the two when both constrain
                child.token_budget = (
                    token_budget if child.token_budget == 0 else min(child.token_budget, token_budget)
                )
            return child

        parent_hops = frame.constraints.max_depth_hops if frame.constraints else 10
        budget = token_budget if token_budget is not None else (frame.constraints.token_budget if frame.constraints else 0)
        timeout = timeout_ms if timeout_ms is not None else (frame.constraints.timeout_ms if frame.constraints else 5000)
        return ExecutionConstraints(
            token_budget=budget,
            timeout_ms=timeout,
            max_depth_hops=max(0, parent_hops - 1),
        )

    def spend_tokens(self, txn_id: int, tokens: int) -> int:
        """
        Incremental metering hook for handlers: spends `tokens` mid-transaction
        against the active escrow. Raises BudgetError on overflow (the handler
        should stop work immediately; the dispatcher settles/refunds on return).
        """
        return self.ledger.consume(txn_id, tokens)

    def _semaphore(self) -> asyncio.Semaphore:
        if self._handler_gate is None:
            self._handler_gate = asyncio.Semaphore(self._max_concurrent_handlers)
        return self._handler_gate

    def _safe_refund(self, txn_id: int) -> None:
        """Refund if an escrow is still open (no-op after commit)."""
        try:
            if self.ledger.remaining(txn_id) is not None:
                self.ledger.refund(txn_id)
        except Exception:  # pragma: no cover - defensive
            pass

    def _caller_grants(self, frame: EacpFrame) -> Optional[int]:
        """Authenticated caller grants (CA mode only).

        Returns the CA-attested allowed capabilities of the caller — verified
        against the CONFIGURED CA key with pin/key binding — or 0 when CA
        mode is on and no valid manifest travelled with the request (a
        missing attestation is NOT a wildcard). Returns None when no CA is
        configured, meaning no attestation layer exists (relay-side
        registration grants still bound claims in that deployment).
        """
        if self.enterprise_ca is None:
            return None
        if not isinstance(frame.data, dict) or "_caller_manifest" not in frame.data:
            return 0
        try:
            sm = SignedManifest.from_dict(frame.data["_caller_manifest"])
        except Exception as e:
            logger.warning(f"malformed caller manifest from {frame.sender_pin}: {e}")
            return 0
        if not sm.is_valid(trusted_ca_public_bytes=self.enterprise_ca.public_bytes):
            return 0
        if sm.manifest.pin != frame.sender_pin:
            return 0
        pub = sm.manifest.public_bytes
        if not pub or compute_pin(pub) != frame.sender_pin:
            return 0
        return int(sm.manifest.allowed_capabilities)

    async def _dispatch_handler(self, frame: EacpFrame) -> None:
        """Request registry entry point: bounded concurrency (semaphore),
        PlatSec three-layer authorization, hop limit, token escrow with a
        PRE-dispatch estimate, cancellation, and guaranteed cleanup."""
        key = (frame.sender_pin, frame.transaction_id)
        escrowed = False
        span_start = time.perf_counter()
        trace = None
        if isinstance(frame.data, dict) and isinstance(frame.data.get("_trace"), str):
            trace = TraceContext.parse(frame.data["_trace"])
        try:
            async with self._semaphore():
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

                # PlatSec capability check — three layers: authenticated
                # caller grants (CA mode), the request's attenuation, and
                # this agent's own policy
                caller_grants = self._caller_grants(frame)
                if caller_grants is not None and (frame.capabilities_mask & ~caller_grants):
                    await self.reply(
                        frame,
                        status=EacpError.EACP_ERR_CAPABILITY_DENIED,
                        result_data={
                            "error": "claimed capabilities exceed the caller's CA-attested grants "
                            "(delegated permissions may only decrease)"
                        },
                    )
                    return
                allowed, err_code = self.gate.evaluate(
                    frame.capabilities_mask, frame.verb, caller_grants=caller_grants
                )
                if not allowed:
                    await self.reply(frame, status=err_code, result_data={"error": "PlatSec capability denied"})
                    return

                # --- Token budget lifecycle (kernel escrow discipline) -------------
                # Escrow happens BEFORE any work: an over-budget request is refused
                # without spending a single unit of compute (fail-closed).
                budget = frame.constraints.token_budget if frame.constraints else 0
                try:
                    self.ledger.escrow(frame.transaction_id, budget)
                    escrowed = True
                except BudgetError as esc_err:
                    await self.reply(
                        frame,
                        status=EacpError.EACP_ERR_TOKEN_OVERFLOW,
                        result_data={"error": "budget escrow refused", "detail": esc_err.detail},
                    )
                    return

                # Pre-dispatch estimate: refuse a request whose OWN payload
                # already exceeds the envelope, before the handler runs
                # (a post-hoc measure alone cannot prevent the spend).
                pre = 0
                est_fn = getattr(self.token_meter, "estimate_request", None)
                if est_fn is not None and budget != 0:
                    pre = int(est_fn(frame))
                    if pre:
                        try:
                            self.ledger.consume(frame.transaction_id, pre)
                        except BudgetError as pre_err:
                            self.ledger.refund(frame.transaction_id)
                            escrowed = False
                            await self.reply(
                                frame,
                                status=EacpError.EACP_ERR_TOKEN_OVERFLOW,
                                result_data={
                                    "error": "request payload alone exceeds the token envelope "
                                    "(refused before handler execution)",
                                    "detail": pre_err.detail,
                                },
                            )
                            return

                try:
                    res = handler(frame)
                    if inspect.iscoroutine(res):
                        res = await res
                    total = int(self.token_meter.measure(frame, res))
                    usage = total - pre if pre else total
                    if usage > 0:
                        try:
                            self.ledger.consume(frame.transaction_id, usage)
                        except BudgetError as over_err:
                            self.ledger.refund(frame.transaction_id)
                            escrowed = False
                            await self.reply(
                                frame,
                                status=EacpError.EACP_ERR_TOKEN_OVERFLOW,
                                result_data={"error": "token budget overflow", "detail": over_err.detail},
                            )
                            return
                    remaining = self.ledger.commit(frame.transaction_id)
                    escrowed = False
                    logger.debug(
                        "span=handler verb=%s tx=%d trace=%s ms=%.3f",
                        frame.verb,
                        frame.transaction_id,
                        trace.trace_id if trace else "-",
                        (time.perf_counter() - span_start) * 1000.0,
                    )
                    await self.reply(frame, status=EacpError.EACP_SUCCESS, result_data=res, remaining_budget=remaining)
                except BudgetError as bud_err:
                    # Handler itself hit the envelope (e.g. via spend_tokens): refund + overflow reply
                    self.ledger.refund(frame.transaction_id)
                    escrowed = False
                    await self.reply(
                        frame,
                        status=EacpError.EACP_ERR_TOKEN_OVERFLOW,
                        result_data={"error": "token budget overflow", "detail": bud_err.detail},
                    )
                except Exception as exc:
                    self.ledger.refund(frame.transaction_id)
                    escrowed = False
                    logger.error(f"Error executing action {frame.verb}: {exc}", exc_info=True)
                    await self.reply(frame, status=EacpError.EACP_ERR_CANCELLED, result_data={"error": str(exc)})
        except asyncio.CancelledError:
            # Cancellation (caller timeout -> PULSE_CANCEL): refund the
            # escrow deterministically and answer best-effort. The HANDLER
            # coroutine is cancelled at its await point — work does not
            # continue after the timeout. External side effects already
            # performed need their own compensation (cleanup != rollback of
            # the outside world; see ARCHITECTURE).
            if escrowed:
                self._safe_refund(frame.transaction_id)
                escrowed = False
            logger.debug(
                "handler cancelled verb=%s tx=%d ms=%.3f",
                frame.verb,
                frame.transaction_id,
                (time.perf_counter() - span_start) * 1000.0,
            )
            try:
                await self.reply(
                    frame,
                    status=EacpError.EACP_ERR_CANCELLED,
                    result_data={"error": "handler cancelled after caller timeout"},
                )
            except Exception:
                pass
            raise
        finally:
            self._inflight.pop(key, None)
            if escrowed:
                self._safe_refund(frame.transaction_id)

    async def close(self) -> None:
        """Closes client session (and cancels every in-flight handler —
        disconnect cleanup: no handler outlives its connection)."""
        self._connected = False
        for task in list(self._inflight.values()):
            task.cancel()
        self._inflight.clear()
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
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
