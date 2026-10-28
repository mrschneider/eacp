//! EACP High-Performance Relay Server Core.

use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::constants::{
    error_code, opcode, pulse_code, MsgType, DEFAULT_HEARTBEAT_TIMEOUT_S,
    DEFAULT_MAX_PAYLOAD_SIZE, HEADER_SIZE, RELAY_PIN,
};
use crate::deadlock::DeadlockGraph;
use crate::frame::{EacpFrame, EacpHeader};

pub struct RelayConfig {
    pub max_push_queue: usize,
    pub max_payload_size: usize,
    pub heartbeat_timeout_s: f64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_push_queue: 1000,
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            heartbeat_timeout_s: DEFAULT_HEARTBEAT_TIMEOUT_S,
        }
    }
}

pub struct RelayState {
    pub config: RelayConfig,
    /// Maps Agent-PIN -> transmission channel to its active socket task
    routes: RwLock<HashMap<u64, mpsc::Sender<Bytes>>>,
    /// Authenticated DECLARED capability mask per registered Agent-PIN:
    /// claimed capabilities on MsgSend must fit inside it (mirrors the
    /// Python relay's registration-grants gate; full CA-signed-manifest
    /// verification remains a documented Rust qualification gap)
    grants: RwLock<HashMap<u64, u64>>,
    /// Sender public keys proven at registration (proof of possession).
    /// Frames from keyed senders MUST verify against these (RUST-01:
    /// signature verification + identity binding parity with Python).
    verifier_keys: RwLock<HashMap<u64, [u8; 32]>>,
    /// Last activity timestamp per Agent-PIN
    last_seen: RwLock<HashMap<u64, Instant>>,
    /// QNX Neutrino-style rendezvous deadlock graph
    deadlock: Mutex<DeadlockGraph>,
    /// Offline push buffers: target_pin -> [(enqueued_at, timeout_ms, raw_frame_bytes)]
    push_queues: Mutex<HashMap<u64, VecDeque<(Instant, u32, Bytes)>>>,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            routes: RwLock::new(HashMap::new()),
            grants: RwLock::new(HashMap::new()),
            verifier_keys: RwLock::new(HashMap::new()),
            last_seen: RwLock::new(HashMap::new()),
            deadlock: Mutex::new(DeadlockGraph::new()),
            push_queues: Mutex::new(HashMap::new()),
        }
    }

    pub async fn register_agent(
        &self,
        pin: u64,
        sender: mpsc::Sender<Bytes>,
        declared_capabilities: u64,
    ) {
        {
            let mut routes = self.routes.write().await;
            routes.insert(pin, sender.clone());
        }
        {
            let mut grants = self.grants.write().await;
            grants.insert(pin, declared_capabilities);
        }
        {
            let mut ls = self.last_seen.write().await;
            ls.insert(pin, Instant::now());
        }
        info!(pin = format!("0x{:016X}", pin), capabilities = declared_capabilities, "Agent registered");

        // Drain offline push queue for this agent respecting TTL
        let queued_frames = {
            let mut queues = self.push_queues.lock().await;
            queues.remove(&pin)
        };

        if let Some(mut queue) = queued_frames {
            let now = Instant::now();
            while let Some((enqueued_at, timeout_ms, raw_bytes)) = queue.pop_front() {
                let elapsed = now.duration_since(enqueued_at);
                if elapsed > Duration::from_millis(timeout_ms as u64) {
                    // Frame expired while target was offline
                    continue;
                }
                let _ = sender.send(raw_bytes).await;
            }
        }
    }

    pub async fn unregister_agent(&self, pin: u64) {
        {
            let mut routes = self.routes.write().await;
            routes.remove(&pin);
        }
        {
            let mut grants = self.grants.write().await;
            grants.remove(&pin);
        }
        {
            let mut keys = self.verifier_keys.write().await;
            keys.remove(&pin);
        }
        {
            let mut ls = self.last_seen.write().await;
            ls.remove(&pin);
        }
        {
            let mut dl = self.deadlock.lock().await;
            dl.remove_agent(pin);
        }
        info!(pin = format!("0x{:016X}", pin), "Agent unregistered");
    }

    pub async fn update_last_seen(&self, pin: u64) {
        let mut ls = self.last_seen.write().await;
        ls.insert(pin, Instant::now());
    }

    pub async fn prune_timed_out_agents(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs_f64(self.config.heartbeat_timeout_s);
        let mut timed_out = Vec::new();

        {
            let ls = self.last_seen.read().await;
            for (&pin, &last) in ls.iter() {
                if now.duration_since(last) > timeout {
                    timed_out.push(pin);
                }
            }
        }

        for pin in timed_out {
            warn!(pin = format!("0x{:016X}", pin), "Agent heartbeat timed out, removing dead route");
            self.unregister_agent(pin).await;
        }
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Extracts the sender's presented public key from slot 1 (`pub_bytes`).
fn sender_pub_key(frame: &EacpFrame) -> Option<[u8; 32]> {
    let p = &frame.payload;
    if p.len() < 16 {
        return None;
    }
    let l0 = u32::from_be_bytes(p[0..4].try_into().ok()?) as usize;
    let l1 = u32::from_be_bytes(p[4..8].try_into().ok()?) as usize;
    if 16 + l0 + l1 > p.len() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&p[16 + l0..16 + l0 + l1]).ok()?;
    hex32(v.get("pub_bytes")?.as_str()?)
}

/// Runs connection handler for an established client stream.
pub async fn handle_connection<S>(
    stream: S,
    state: Arc<RelayState>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);

    // Writer task: forward outgoing frames from channel to socket
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if let Err(e) = writer.write_all(&bytes).await {
                debug!("Failed to write frame to socket: {}", e);
                break;
            }
            if let Err(e) = writer.flush().await {
                debug!("Failed to flush socket: {}", e);
                break;
            }
        }
    });

    let mut registered_pin: Option<u64> = None;
    // replay identity (tx, target) — windowed like the Python session
    const REPLAY_WINDOW: usize = 2048;
    let mut seen_tx: HashSet<(u64, u64)> = HashSet::new();
    let mut seen_order: VecDeque<(u64, u64)> = VecDeque::new();
    let mut header_buf = [0u8; HEADER_SIZE];

    loop {
        // Read 48-byte header
        if let Err(_) = reader.read_exact(&mut header_buf).await {
            break;
        }

        let header = match EacpHeader::from_bytes(&header_buf) {
            Ok(h) => h,
            Err(e) => {
                warn!("Invalid header magic or structure: error code {}", e);
                break;
            }
        };

        if header.payload_len as usize > state.config.max_payload_size {
            warn!(
                "Payload size {} exceeds limit {}",
                header.payload_len, state.config.max_payload_size
            );
            break;
        }

        // Read payload
        let mut payload_buf = vec![0u8; header.payload_len as usize];
        if header.payload_len > 0 {
            if let Err(e) = reader.read_exact(&mut payload_buf).await {
                warn!("Failed to read frame payload: {}", e);
                break;
            }
        }

        let frame = EacpFrame::new(header, Bytes::from(payload_buf));

        // 1. Registration: present a key AND prove possession of it
        //    (RUST-01 parity with the Python relay — no keyless or
        //    unproven registrations, no pin switching on one connection)
        if frame.header.msg_type == MsgType::MsgRelayControl as u8
            && frame.header.opcode == opcode::OP_RELAY_REGISTER
        {
            let pin = frame.header.sender_pin;
            let reject: Option<&str> = if registered_pin.is_some() && registered_pin != Some(pin) {
                Some("connection already authenticated for another PIN")
            } else {
                match sender_pub_key(&frame) {
                    None => Some("registration must present a 32-byte pub_bytes key"),
                    Some(pk) if !frame.verify_sender_signature(&pk) => Some(
                        "no proof of possession: registration frame not signed by the presented key",
                    ),
                    Some(_) => None,
                }
            };
            if let Some(reason) = reject {
                warn!(pin = format!("0x{:016X}", pin), reason = reason, "Registration refused");
                let err = frame.create_reply(
                    error_code::EACP_ERR_SIGNATURE_INVALID,
                    Some(&serde_json::json!({ "error": reason })),
                );
                let _ = tx.send(err.to_bytes()).await;
                break;
            }
            let pk = sender_pub_key(&frame).expect("validated above");
            state.verifier_keys.write().await.insert(pin, pk);
            registered_pin = Some(pin);
            state.register_agent(pin, tx.clone(), frame.header.capabilities_mask).await;

            // Send registration ACK reply
            let ack = frame.create_reply(
                error_code::EACP_SUCCESS,
                Some(&serde_json::json!({
                    "registered": true,
                    "pin": pin
                })),
            );
            let _ = tx.send(ack.to_bytes()).await;
            continue;
        }

        if let Some(pin) = registered_pin {
            state.update_last_seen(pin).await;
        }

        // SEC-01 parity: application frames only from THIS connection's
        // authenticated PIN (the Rust relay has no mesh — every connection
        // is an agent connection)
        if frame.header.msg_type != MsgType::MsgRelayControl as u8 {
            let bad = match registered_pin {
                None => Some("unauthenticated ingress: register before sending application frames"),
                Some(p) if p != frame.header.sender_pin => {
                    Some("sender identity is not bound to this connection")
                }
                _ => None,
            };
            if let Some(reason) = bad {
                warn!(reason = reason, "Refusing application frame at ingress");
                let err = frame.create_reply(
                    error_code::EACP_ERR_SIGNATURE_INVALID,
                    Some(&serde_json::json!({ "error": reason })),
                );
                let _ = tx.send(err.to_bytes()).await;
                break;
            }
        }

        // Signature verification + replay for authenticated traffic
        // (signing contract v2 — byte-identical to the Python verifier)
        if frame.header.msg_type == MsgType::MsgSend as u8
            || frame.header.msg_type == MsgType::MsgReply as u8
        {
            let key = {
                let keys = state.verifier_keys.read().await;
                keys.get(&frame.header.sender_pin).copied()
            };
            let mut refused: Option<u32> = None;
            match key {
                Some(pk) if frame.verify_sender_signature(&pk) => {
                    let k = (frame.header.transaction_id, frame.header.target_pin);
                    if seen_tx.contains(&k) {
                        refused = Some(error_code::EACP_ERR_REPLAY_DETECTED);
                    } else {
                        if seen_order.len() >= REPLAY_WINDOW {
                            if let Some(old) = seen_order.pop_front() {
                                seen_tx.remove(&old);
                            }
                        }
                        seen_order.push_back(k);
                        seen_tx.insert(k);
                    }
                }
                _ => refused = Some(error_code::EACP_ERR_SIGNATURE_INVALID),
            }
            if let Some(code) = refused {
                warn!(
                    sender = format!("0x{:016X}", frame.header.sender_pin),
                    code = code,
                    "Refusing frame (signature/replay)"
                );
                if frame.header.msg_type == MsgType::MsgSend as u8 {
                    let err = frame.create_reply(
                        code,
                        Some(&serde_json::json!({ "error": "frame authentication refused" })),
                    );
                    let _ = tx.send(err.to_bytes()).await;
                }
                continue;
            }
        }

        // 2. Pulse handling
        if frame.header.is_pulse() {
            if let Some((code, _)) = frame.get_pulse_data() {
                if code == pulse_code::PULSE_HEARTBEAT
                    && (frame.header.target_pin == 0 || frame.header.target_pin == RELAY_PIN)
                {
                    // Relay presence ping
                    continue;
                }
                if code == pulse_code::PULSE_CANCEL {
                    let mut dl = state.deadlock.lock().await;
                    dl.remove_dependency(frame.header.sender_pin, Some(frame.header.transaction_id));
                }
            }
        }

        // 3. Rendezvous & Deadlock cycle detection
        if frame.header.msg_type == MsgType::MsgSend as u8 {
            // Authorization: claimed capabilities must fit the DECLARED
            // registration mask (defense at the trust anchor — the Rust
            // relay does not yet verify CA-signed manifests; see the
            // qualification gaps in ARCHITECTURE.md)
            let declared = {
                let grants = state.grants.read().await;
                grants.get(&frame.header.sender_pin).copied()
            };
            if let Some(allowed) = declared {
                if frame.header.capabilities_mask & !allowed != 0 {
                    warn!(
                        sender = format!("0x{:016X}", frame.header.sender_pin),
                        claimed = frame.header.capabilities_mask,
                        granted = allowed,
                        "Claimed capabilities exceed registration grants, refusing"
                    );
                    let err_reply = frame.create_reply(
                        error_code::EACP_ERR_CAPABILITY_DENIED,
                        Some(&serde_json::json!({
                            "error": "claimed capabilities exceed registration grants"
                        })),
                    );
                    let _ = tx.send(err_reply.to_bytes()).await;
                    continue;
                }
            }
            let mut dl = state.deadlock.lock().await;
            if !dl.add_dependency(
                frame.header.sender_pin,
                frame.header.target_pin,
                frame.header.transaction_id,
            ) {
                // Deadlock detected! Reply immediately with error
                warn!(
                    sender = format!("0x{:016X}", frame.header.sender_pin),
                    target = format!("0x{:016X}", frame.header.target_pin),
                    "Deadlock detected on MsgSend rendezvous, rejecting"
                );
                let err_reply = frame.create_reply(error_code::EACP_ERR_DEADLOCK_DETECTED, None);
                let _ = tx.send(err_reply.to_bytes()).await;
                continue;
            }
        } else if frame.header.msg_type == MsgType::MsgReply as u8 {
            let mut dl = state.deadlock.lock().await;
            dl.remove_dependency(frame.header.target_pin, Some(frame.header.transaction_id));
        }

        // 4. Route frame to target
        let target_pin = frame.header.target_pin;
        let target_tx = {
            let routes = state.routes.read().await;
            routes.get(&target_pin).cloned()
        };

        let raw_frame_bytes = frame.to_bytes();

        if let Some(target_chan) = target_tx {
            if let Err(_) = target_chan.send(raw_frame_bytes).await {
                // Target channel closed, unregister
                state.unregister_agent(target_pin).await;
            }
        } else {
            // Target is offline
            if frame.header.is_urgent() {
                if frame.header.msg_type == MsgType::MsgSend as u8 {
                    let mut dl = state.deadlock.lock().await;
                    dl.remove_dependency(frame.header.sender_pin, Some(frame.header.transaction_id));
                    let err_reply = frame.create_reply(error_code::EACP_ERR_UNKNOWN_PIN, None);
                    let _ = tx.send(err_reply.to_bytes()).await;
                }
            } else {
                // Buffer in push queue — global budget enforced with an
                // EXPLICIT refusal (parity with the Python relay: never a
                // silent drop, and the deadlock edge is released)
                let timeout_ms = frame.get_timeout_ms();
                let full = {
                    let mut queues = state.push_queues.lock().await;
                    let queue = queues.entry(target_pin).or_insert_with(VecDeque::new);
                    if queue.len() >= state.config.max_push_queue {
                        true
                    } else {
                        queue.push_back((Instant::now(), timeout_ms, raw_frame_bytes));
                        false
                    }
                };
                if full {
                    if frame.header.msg_type == MsgType::MsgSend as u8 {
                        let mut dl = state.deadlock.lock().await;
                        dl.remove_dependency(frame.header.sender_pin, Some(frame.header.transaction_id));
                        let err_reply = frame.create_reply(
                            error_code::EACP_ERR_QUEUE_FULL,
                            Some(&serde_json::json!({
                                "error": "offline queue budget exceeded"
                            })),
                        );
                        let _ = tx.send(err_reply.to_bytes()).await;
                    }
                }
            }
        }
    }

    if let Some(pin) = registered_pin {
        state.unregister_agent(pin).await;
    }
    writer_task.abort();
}
