"""
EACP: Enterprise Agentic Communication Protocol
Microkernel-grade communication and coordination protocol for enterprise multi-agent systems.
"""

from .constants import (
    EACP_MAGIC,
    EACP_VERSION,
    HEADER_SIZE,
    ActivePriority,
    Capability,
    EacpError,
    FrameFlags,
    MsgType,
    OpCode,
    PulseCode,
    RequestStatus,
)
from .frame import (
    CryptoEnvelope,
    EacpFrame,
    ExecutionConstraints,
)
from .security import (
    AgentIdentity,
    AgentVerifier,
    PlatSecException,
    PlatSecGate,
    SecurityManifest,
    compute_pin,
    format_pin,
)
from .scheduler import (
    ActiveScheduler,
    CActive,
    CleanupItem,
    CleanupStack,
    TRequestStatus,
)
from .primitives import (
    EacpRendezvousException,
    MsgPulse,
    MsgReceive,
    MsgReply,
    MsgSend,
)
from .relay import (
    DeadlockGraph,
    EacpRelay,
    RelayClientSession,
)
from .client import (
    RSessionBase,
)

__all__ = [
    # Constants
    "EACP_MAGIC",
    "EACP_VERSION",
    "HEADER_SIZE",
    "ActivePriority",
    "Capability",
    "EacpError",
    "FrameFlags",
    "MsgType",
    "OpCode",
    "PulseCode",
    "RequestStatus",
    # Frame
    "CryptoEnvelope",
    "EacpFrame",
    "ExecutionConstraints",
    # Security
    "AgentIdentity",
    "AgentVerifier",
    "PlatSecException",
    "PlatSecGate",
    "SecurityManifest",
    "compute_pin",
    "format_pin",
    # Scheduler
    "ActiveScheduler",
    "CActive",
    "CleanupItem",
    "CleanupStack",
    "TRequestStatus",
    # Primitives
    "EacpRendezvousException",
    "MsgPulse",
    "MsgReceive",
    "MsgReply",
    "MsgSend",
    # Relay
    "DeadlockGraph",
    "EacpRelay",
    "RelayClientSession",
    # Client
    "RSessionBase",
]
