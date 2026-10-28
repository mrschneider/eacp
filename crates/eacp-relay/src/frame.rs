//! EACP 48-byte binary frame parser and serializer.

use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use crate::constants::{
    error_code, flags, opcode, MsgType, EACP_MAGIC, EACP_VERSION, HEADER_SIZE, RELAY_PIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EacpHeader {
    pub magic: [u8; 2],
    pub version: u8,
    pub msg_type: u8,
    pub opcode: u16,
    pub flags: u16,
    pub sender_pin: u64,
    pub target_pin: u64,
    pub transaction_id: u64,
    pub capabilities_mask: u64,
    pub status: u32,
    pub payload_len: u32,
}

impl EacpHeader {
    pub fn from_bytes(raw: &[u8; HEADER_SIZE]) -> Result<Self, u32> {
        let magic = [raw[0], raw[1]];
        if magic != EACP_MAGIC {
            return Err(error_code::EACP_ERR_INVALID_MAGIC);
        }

        let version = raw[2];
        // wire version demarcation: v1 peers used the old signing contract
        // (slot length block not authenticated) — refuse them explicitly
        // instead of failing signature verification with a mystery error
        if version != EACP_VERSION {
            return Err(error_code::EACP_ERR_MALFORMED_FRAME);
        }
        let msg_type = raw[3];
        let opcode = u16::from_be_bytes([raw[4], raw[5]]);
        let flags = u16::from_be_bytes([raw[6], raw[7]]);
        let sender_pin = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        let target_pin = u64::from_be_bytes(raw[16..24].try_into().unwrap());
        let transaction_id = u64::from_be_bytes(raw[24..32].try_into().unwrap());
        let capabilities_mask = u64::from_be_bytes(raw[32..40].try_into().unwrap());
        let status = u32::from_be_bytes(raw[40..44].try_into().unwrap());
        let payload_len = u32::from_be_bytes(raw[44..48].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            msg_type,
            opcode,
            flags,
            sender_pin,
            target_pin,
            transaction_id,
            capabilities_mask,
            status,
            payload_len,
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.magic);
        buf[2] = self.version;
        buf[3] = self.msg_type;
        buf[4..6].copy_from_slice(&self.opcode.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..16].copy_from_slice(&self.sender_pin.to_be_bytes());
        buf[16..24].copy_from_slice(&self.target_pin.to_be_bytes());
        buf[24..32].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[32..40].copy_from_slice(&self.capabilities_mask.to_be_bytes());
        buf[40..44].copy_from_slice(&self.status.to_be_bytes());
        buf[44..48].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn is_pulse(&self) -> bool {
        self.msg_type == MsgType::MsgPulse as u8
    }

    pub fn is_urgent(&self) -> bool {
        (self.flags & flags::FLAG_URGENT) != 0
    }
}

#[derive(Debug, Clone)]
pub struct EacpFrame {
    pub header: EacpHeader,
    pub payload: Bytes,
}

impl EacpFrame {
    pub fn new(header: EacpHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Extracts (pulse_code, pulse_value) if this is a pulse frame.
    pub fn get_pulse_data(&self) -> Option<(u16, u64)> {
        if !self.header.is_pulse() || self.payload.len() < 8 {
            return None;
        }
        let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let mut val_bytes = [0u8; 8];
        val_bytes[2..8].copy_from_slice(&self.payload[2..8]);
        let val = u64::from_be_bytes(val_bytes);
        Some((code, val))
    }

    /// Extracts timeout_ms from slot 2 if present.
    pub fn get_timeout_ms(&self) -> u32 {
        if self.header.is_pulse() || self.payload.len() < 16 {
            return 5000;
        }
        let l0 = u32::from_be_bytes(self.payload[0..4].try_into().unwrap()) as usize;
        let l1 = u32::from_be_bytes(self.payload[4..8].try_into().unwrap()) as usize;
        let l2 = u32::from_be_bytes(self.payload[8..12].try_into().unwrap()) as usize;

        let slot2_offset = 16 + l0 + l1;
        if self.payload.len() >= slot2_offset + l2 && l2 >= 8 {
            let timeout_bytes = &self.payload[slot2_offset + 4..slot2_offset + 8];
            let t = u32::from_be_bytes(timeout_bytes.try_into().unwrap());
            if t > 0 {
                return t;
            }
        }
        5000
    }

    /// Creates a standard MsgReply for this frame with status and optional JSON payload.
    pub fn create_reply(&self, status: u32, json_data: Option<&serde_json::Value>) -> Self {
        let slot0 = b"reply";
        let slot1_bytes = match json_data {
            Some(v) => serde_json::to_vec(v).unwrap_or_default(),
            None => Vec::new(),
        };

        // Slot 2: constraints (token_budget: 0, timeout_ms: 5000, max_depth_hops: 10) -> 9 bytes
        let mut slot2 = Vec::with_capacity(9);
        slot2.extend_from_slice(&0u32.to_be_bytes());
        slot2.extend_from_slice(&5000u32.to_be_bytes());
        slot2.push(10u8);

        // Slot 3: crypto envelope (session_handle: 0) -> 4 bytes
        let slot3 = 0u32.to_be_bytes();

        let l0 = slot0.len() as u32;
        let l1 = slot1_bytes.len() as u32;
        let l2 = slot2.len() as u32;
        let l3 = slot3.len() as u32;

        let mut payload_buf = BytesMut::with_capacity(16 + l0 as usize + l1 as usize + l2 as usize + l3 as usize);
        payload_buf.put_u32(l0);
        payload_buf.put_u32(l1);
        payload_buf.put_u32(l2);
        payload_buf.put_u32(l3);
        payload_buf.extend_from_slice(slot0);
        payload_buf.extend_from_slice(&slot1_bytes);
        payload_buf.extend_from_slice(&slot2);
        payload_buf.extend_from_slice(&slot3);

        let reply_payload = payload_buf.freeze();

        let header = EacpHeader {
            magic: EACP_MAGIC,
            version: EACP_VERSION,
            msg_type: MsgType::MsgReply as u8,
            opcode: if self.header.opcode != 0 { self.header.opcode } else { opcode::OP_ACTION_REPLY },
            flags: flags::FLAG_NONE,
            sender_pin: RELAY_PIN,
            target_pin: self.header.sender_pin,
            transaction_id: self.header.transaction_id,
            capabilities_mask: self.header.capabilities_mask,
            status,
            payload_len: reply_payload.len() as u32,
        };

        Self::new(header, reply_payload)
    }

    /// Signing contract v2 (SEC-02), byte-identical to the Python
    /// reference `get_signed_bytes()`: header (FLAG_COMPRESSED excluded,
    /// FLAG_SIGNED forced, payload_len = 16 + slots0..2 + 68) followed by
    /// the 16-byte slot length block, slots 0..2 and the 4-byte
    /// session-handle prefix of slot 3. The length block IS authenticated,
    /// so a boundary repartition changes the signature input.
    pub fn signed_bytes_v2(&self) -> Option<Bytes> {
        let p = &self.payload;
        if p.len() < 24 {
            return None;
        }
        let l0 = u32::from_be_bytes(p[0..4].try_into().ok()?) as usize;
        let l1 = u32::from_be_bytes(p[4..8].try_into().ok()?) as usize;
        let l2 = u32::from_be_bytes(p[8..12].try_into().ok()?) as usize;
        let l3 = u32::from_be_bytes(p[12..16].try_into().ok()?) as usize;
        if 16usize + l0 + l1 + l2 + l3 != p.len() {
            return None;
        }
        if l3 < 68 {
            return None; // session handle (4) + signature (64)
        }
        let covered = 20 + l0 + l1 + l2; // through the session-handle prefix
        if p.len() < covered + 64 {
            return None;
        }
        let mut h = self.header;
        h.flags = (h.flags & !flags::FLAG_COMPRESSED) | flags::FLAG_SIGNED;
        h.payload_len = (16 + l0 + l1 + l2 + 68) as u32;
        let mut buf = BytesMut::with_capacity(48 + covered);
        buf.extend_from_slice(&h.to_bytes());
        buf.extend_from_slice(&p[..covered]);
        Some(buf.freeze())
    }

    /// Verifies the frame's Ed25519 signature against a known sender key
    /// (RFC 8032 pure — same acceptance domain as the Python verifier).
    pub fn verify_sender_signature(&self, pub_bytes: &[u8; 32]) -> bool {
        if self.header.flags & flags::FLAG_SIGNED == 0 {
            return false;
        }
        let p = &self.payload;
        if p.len() < 24 {
            return false;
        }
        let l0 = u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize;
        let l1 = u32::from_be_bytes(p[4..8].try_into().unwrap()) as usize;
        let l2 = u32::from_be_bytes(p[8..12].try_into().unwrap()) as usize;
        let sig_start = 16 + l0 + l1 + l2 + 4;
        if p.len() < sig_start + 64 {
            return false;
        }
        let sig_bytes: [u8; 64] = match p[sig_start..sig_start + 64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let vk = match VerifyingKey::from_bytes(pub_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let msg = match self.signed_bytes_v2() {
            Some(m) => m,
            None => return false,
        };
        vk.verify(&msg, &sig).is_ok()
    }
}
