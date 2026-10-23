"""
EACP: Enterprise Agentic Communication Protocol
Microkernel-grade communication and coordination protocol for enterprise multi-agent systems.
"""

from .constants import (
    COMPRESSION_THRESHOLD_BYTES,
    DEFAULT_HEARTBEAT_INTERVAL_S,
    DEFAULT_HEARTBEAT_TIMEOUT_S,
    DEFAULT_MAX_PAYLOAD_SIZE,
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
    EnterpriseCA,
    PlatSecException,
    PlatSecGate,
    SecurityManifest,
    SignedManifest,
    compute_pin,
    create_client_ssl_context,
    create_server_ssl_context,
    decrypt_payload_aes_gcm,
    encrypt_payload_aes_gcm,
    format_pin,
)
from .scheduler import (
    ActiveScheduler,
    AsyncActive,
    AsyncActiveScheduler,
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
from .budget import (
    BudgetError,
    PayloadTokenMeter,
    TokenBudgetLedger,
    TokenMeter,
)
from .client import (
    RSessionBase,
)
from .telemetry import (
    EacpMetrics,
    TraceContext,
)
from .ledger import (
    AuditEntry,
    AuditLedger,
)
from .mesh import (
    MeshRoutingTable,
    RelayPeer,
)

__all__ = [
    # Constants
    "EACP_MAGIC",
    "EACP_VERSION",
    "HEADER_SIZE",
    "DEFAULT_MAX_PAYLOAD_SIZE",
    "DEFAULT_HEARTBEAT_INTERVAL_S",
    "DEFAULT_HEARTBEAT_TIMEOUT_S",
    "COMPRESSION_THRESHOLD_BYTES",
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
    # Security & Enterprise PKI
    "AgentIdentity",
    "AgentVerifier",
    "EnterpriseCA",
    "PlatSecException",
    "PlatSecGate",
    "SecurityManifest",
    "SignedManifest",
    "compute_pin",
    "create_client_ssl_context",
    "create_server_ssl_context",
    "decrypt_payload_aes_gcm",
    "encrypt_payload_aes_gcm",
    "format_pin",
    # Scheduler
    "ActiveScheduler",
    "AsyncActive",
    "AsyncActiveScheduler",
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
    # Token Budget
    "BudgetError",
    "PayloadTokenMeter",
    "TokenBudgetLedger",
    "TokenMeter",
    # Client
    "RSessionBase",
    # Enterprise Telemetry
    "EacpMetrics",
    "TraceContext",
    # Enterprise Audit Ledger
    "AuditEntry",
    "AuditLedger",
    # Enterprise HA Mesh
    "MeshRoutingTable",
    "RelayPeer",
]
