"""
EACP Protocol Constants, OpCodes, Capabilities, and Error Codes.
"""

from enum import IntEnum, IntFlag

# 16-bit Protocol Magic: 0xEACF
EACP_MAGIC = b"\xEA\xCF"
EACP_MAGIC_INT = 0xEACF
EACP_VERSION = 1

# Header fixed length: 48 bytes (64-bit aligned)
HEADER_SIZE = 48

# Operational defaults (cloud/edge/local agnostic)
DEFAULT_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024  # 16 MB maximum payload guard
DEFAULT_HEARTBEAT_INTERVAL_S = 30.0          # Periodic keepalive ping interval
DEFAULT_HEARTBEAT_TIMEOUT_S = 90.0           # 3x missed heartbeat dead-route pruning
COMPRESSION_THRESHOLD_BYTES = 1024           # Compress payloads exceeding 1KB if enabled


class MsgType(IntEnum):
    MSG_SEND = 1          # Synchronous rendezvous request
    MSG_RECEIVE = 2       # Worker dequeue / polling request
    MSG_REPLY = 3         # Completion of MSG_SEND transaction
    MSG_PULSE = 4         # Non-blocking 8-byte out-of-band notification
    MSG_RELAY_CONTROL = 5 # Presence, registration, routing update


class FrameFlags(IntFlag):
    FLAG_NONE = 0
    FLAG_URGENT = 1 << 0
    FLAG_ENCRYPTED = 1 << 1
    FLAG_COMPRESSED = 1 << 2
    FLAG_SIGNED = 1 << 3


class Capability(IntFlag):
    NONE = 0
    CAP_NET_RAW = 1 << 0        # Direct network socket I/O
    CAP_DISK_READ = 1 << 1      # Read access to storage
    CAP_DISK_WRITE = 1 << 2     # Write access to storage
    CAP_TOOL_EXEC = 1 << 3      # Spawning local tools/shell commands
    CAP_AGENT_SPAWN = 1 << 4    # Registering/creating child agents
    CAP_CROSS_CALL = 1 << 5     # Invoking agents across security domains
    CAP_SYS_ADMIN = 1 << 6      # Modifying system/infra state
    CAP_PII_ACCESS = 1 << 7     # Accessing confidential/PII data
    CAP_PERSISTENCE = 1 << 8    # Writing to long-term memory/ledger
    CAP_CODE_GEN = 1 << 9       # Executing dynamically generated code


class PulseCode(IntEnum):
    PULSE_HEARTBEAT = 0x0001
    PULSE_CANCEL = 0x0002
    PULSE_PAUSE = 0x0003
    PULSE_RESUME = 0x0004
    PULSE_CONTEXT_TRUNCATED = 0x0005


class OpCode(IntEnum):
    OP_ACTION_INVOKE = 0x0100
    OP_ACTION_REPLY = 0x0101
    OP_RELAY_REGISTER = 0x0001
    OP_RELAY_UNREGISTER = 0x0002
    OP_RELAY_PING = 0x0003
    OP_RELAY_ROUTE_ANNOUNCE = 0x0004


class EacpError(IntEnum):
    EACP_SUCCESS = 0
    EACP_ERR_INVALID_MAGIC = 1
    EACP_ERR_UNKNOWN_PIN = 2
    EACP_ERR_CAPABILITY_DENIED = 3
    EACP_ERR_DEADLOCK_DETECTED = 4
    EACP_ERR_TIMEOUT = 5
    EACP_ERR_CANCELLED = 6
    EACP_ERR_TOKEN_OVERFLOW = 7
    EACP_ERR_SIGNATURE_INVALID = 8
    EACP_ERR_MALFORMED_FRAME = 9
    EACP_ERR_DISCONNECTED = 10
    EACP_ERR_DEPTH_EXCEEDED = 11
    EACP_ERR_REPLAY_DETECTED = 12
    EACP_ERR_QUEUE_FULL = 13


class RequestStatus(IntEnum):
    KRequestPending = -1
    KErrNone = 0
    KErrNotFound = -2
    KErrGeneral = -3
    KErrCancel = -4
    KErrNoMemory = -5
    KErrNotSupported = -6
    KErrArgument = -7
    KErrOverflow = -8
    KErrUnderflow = -9
    KErrAlreadyExists = -10
    KErrPathNotFound = -11
    KErrDied = -12
    KErrInUse = -13
    KErrServerTerminated = -14
    KErrServerBusy = -15
    KErrCompletion = -16
    KErrNotReady = -17
    KErrUnknown = -18
    KErrCorrupt = -19
    KErrAccessDenied = -20


class ActivePriority(IntEnum):
    EPriorityIdle = -20
    EPriorityLow = -10
    EPriorityStandard = 0
    EPriorityHigh = 10
    EPriorityRealtime = 20
