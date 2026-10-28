#![allow(dead_code)]
//! Protocol constants and opcodes for EACP Relay.

pub const EACP_MAGIC: [u8; 2] = [0xEA, 0xCF];
pub const EACP_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 48;

pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16 MB
pub const DEFAULT_HEARTBEAT_TIMEOUT_S: f64 = 90.0;
pub const RELAY_PIN: u64 = 0x0000_0000_0000_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    MsgSend = 1,
    MsgReceive = 2,
    MsgReply = 3,
    MsgPulse = 4,
    MsgRelayControl = 5,
    Unknown = 255,
}

impl From<u8> for MsgType {
    fn from(v: u8) -> Self {
        match v {
            1 => MsgType::MsgSend,
            2 => MsgType::MsgReceive,
            3 => MsgType::MsgReply,
            4 => MsgType::MsgPulse,
            5 => MsgType::MsgRelayControl,
            _ => MsgType::Unknown,
        }
    }
}

pub mod flags {
    pub const FLAG_NONE: u16 = 0;
    pub const FLAG_URGENT: u16 = 1 << 0;
    pub const FLAG_ENCRYPTED: u16 = 1 << 1;
    pub const FLAG_COMPRESSED: u16 = 1 << 2;
    pub const FLAG_SIGNED: u16 = 1 << 3;
}

pub mod opcode {
    pub const OP_ACTION_INVOKE: u16 = 0x0100;
    pub const OP_ACTION_REPLY: u16 = 0x0101;
    pub const OP_RELAY_REGISTER: u16 = 0x0001;
    pub const OP_RELAY_UNREGISTER: u16 = 0x0002;
    pub const OP_RELAY_PING: u16 = 0x0003;
    pub const OP_RELAY_ROUTE_ANNOUNCE: u16 = 0x0004;
}

pub mod pulse_code {
    pub const PULSE_HEARTBEAT: u16 = 0x0001;
    pub const PULSE_CANCEL: u16 = 0x0002;
    pub const PULSE_PAUSE: u16 = 0x0003;
    pub const PULSE_RESUME: u16 = 0x0004;
    pub const PULSE_CONTEXT_TRUNCATED: u16 = 0x0005;
}

pub mod error_code {
    pub const EACP_SUCCESS: u32 = 0;
    pub const EACP_ERR_INVALID_MAGIC: u32 = 1;
    pub const EACP_ERR_UNKNOWN_PIN: u32 = 2;
    pub const EACP_ERR_CAPABILITY_DENIED: u32 = 3;
    pub const EACP_ERR_DEADLOCK_DETECTED: u32 = 4;
    pub const EACP_ERR_TIMEOUT: u32 = 5;
    pub const EACP_ERR_CANCELLED: u32 = 6;
    pub const EACP_ERR_TOKEN_OVERFLOW: u32 = 7;
    pub const EACP_ERR_SIGNATURE_INVALID: u32 = 8;
    pub const EACP_ERR_MALFORMED_FRAME: u32 = 9;
    pub const EACP_ERR_DISCONNECTED: u32 = 10;
    pub const EACP_ERR_DEPTH_EXCEEDED: u32 = 11;
    pub const EACP_ERR_REPLAY_DETECTED: u32 = 12;
    pub const EACP_ERR_QUEUE_FULL: u32 = 13;
}
