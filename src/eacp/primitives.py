"""
QNX Neutrino-style rendezvous IPC primitives: MsgSend, MsgReceive, MsgReply, MsgPulse.
"""

from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING, Any, Optional

from .constants import EacpError, MsgType, OpCode, PulseCode
from .frame import EacpFrame, ExecutionConstraints

if TYPE_CHECKING:
    from .client import RSessionBase


class EacpRendezvousException(Exception):
    def __init__(self, code: int | EacpError, message: str, frame: Optional[EacpFrame] = None):
        super().__init__(message)
        self.code = EacpError(code)
        self.frame = frame


async def MsgSend(
    session: RSessionBase,
    target_pin: int,
    verb: str,
    data: Any = None,
    constraints: Optional[ExecutionConstraints] = None,
    opcode: int = OpCode.OP_ACTION_INVOKE,
    capabilities_mask: Optional[int] = None,
) -> EacpFrame:
    """
    Synchronous rendezvous request:
    Sends frame to target_pin and puts calling agent into STATE_REPLY_BLOCKED
    until MsgReply is received or timeout expires.
    """
    return await session.send(
        target_pin=target_pin,
        verb=verb,
        data=data,
        constraints=constraints,
        opcode=opcode,
        capabilities_mask=capabilities_mask,
    )


async def MsgReceive(
    session: RSessionBase,
    timeout_ms: Optional[int] = None,
) -> EacpFrame:
    """
    Server rendezvous primitive:
    Blocks until an incoming MSG_SEND or MSG_PULSE arrives.
    """
    return await session.receive(timeout_ms=timeout_ms)


async def MsgReply(
    session: RSessionBase,
    request_frame: EacpFrame,
    status: int | EacpError = EacpError.EACP_SUCCESS,
    result_data: Any = None,
) -> None:
    """
    Rendezvous completion primitive:
    Returns reply to sender, unblocking the sender's MsgSend.
    """
    await session.reply(request_frame, status=status, result_data=result_data)


async def MsgPulse(
    session: RSessionBase,
    target_pin: int,
    pulse_code: int | PulseCode,
    pulse_value: int = 0,
) -> None:
    """
    Non-blocking 8-byte out-of-band notification primitive:
    Sender never blocks waiting for a reply.
    """
    await session.pulse(target_pin=target_pin, pulse_code=pulse_code, pulse_value=pulse_value)
