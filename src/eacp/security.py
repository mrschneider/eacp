"""
EACP Security Subsystem: PlatSec capability enforcement and Ed25519 Agent-PIN identity.
"""

from __future__ import annotations
import hashlib
import os
import ssl
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import Capability, EacpError, FrameFlags
from .frame import CryptoEnvelope, EacpFrame


def compute_pin(public_bytes: bytes) -> int:
    """
    Derives 64-bit Agent-PIN deterministically from 32-byte Ed25519 public key:
    First8Bytes(SHA-256(PK_agent)) unpacked as big-endian uint64.
    """
    digest = hashlib.sha256(public_bytes).digest()
    return struct.unpack(">Q", digest[:8])[0]


def format_pin(pin: int) -> str:
    """Formats 64-bit PIN as standard 0xXXXX_XXXX_XXXX_XXXX hexadecimal string."""
    h = f"{pin:016X}"
    return f"0x{h[0:4]}_{h[4:8]}_{h[8:12]}_{h[12:16]}"


@dataclass
class AgentIdentity:
    """
    Cryptographic identity for an EACP agent containing Ed25519 keypair and Agent-PIN.
    """
    _private_key: ed25519.Ed25519PrivateKey
    _public_key: ed25519.Ed25519PublicKey
    public_bytes: bytes
    pin: int

    @classmethod
    def generate(cls) -> AgentIdentity:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pin = compute_pin(pub_bytes)
        return cls(_private_key=priv, _public_key=pub, public_bytes=pub_bytes, pin=pin)

    @classmethod
    def from_private_bytes(cls, raw_bytes: bytes) -> AgentIdentity:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pin = compute_pin(pub_bytes)
        return cls(_private_key=priv, _public_key=pub, public_bytes=pub_bytes, pin=pin)

    @property
    def pin_hex(self) -> str:
        return format_pin(self.pin)

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def sign_frame(self, frame: EacpFrame, session_handle: int = 0) -> None:
        """
        Signs an EACP frame:
        Sets FLAG_SIGNED, attaches session_handle and 64-byte Ed25519 signature to Slot 3.
        """
        frame.sender_pin = self.pin
        frame.flags |= FrameFlags.FLAG_SIGNED
        frame.envelope = CryptoEnvelope(session_handle=session_handle, signature=b"")
        signed_data = frame.get_signed_bytes()
        sig = self.sign(signed_data)
        frame.envelope.signature = sig


@dataclass
class AgentVerifier:
    """
    Verification handle for remote Agent-PIN using its Ed25519 public key.
    """
    _public_key: ed25519.Ed25519PublicKey
    public_bytes: bytes
    pin: int

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes) -> AgentVerifier:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pin = compute_pin(pub_bytes)
        return cls(_public_key=pub, public_bytes=pub_bytes, pin=pin)

    def verify(self, signature: bytes, data: bytes) -> bool:
        if len(signature) != 64:
            return False
        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def verify_frame(self, frame: EacpFrame) -> bool:
        """
        Verifies frame signature against this agent's public key.
        Checks that frame.sender_pin matches this PIN and signature is valid.
        """
        if frame.sender_pin != self.pin:
            return False
        if not (frame.flags & FrameFlags.FLAG_SIGNED):
            return False
        if not frame.envelope or not frame.envelope.signature:
            return False
        
        signed_bytes = frame.get_signed_bytes()
        return self.verify(frame.envelope.signature, signed_bytes)


@dataclass
class SecurityManifest:
    """
    Security manifest for an agent registering its allowed capabilities.
    """
    pin: int
    allowed_capabilities: Capability = Capability.NONE
    public_bytes: Optional[bytes] = None


class PlatSecException(Exception):
    def __init__(self, code: EacpError | int, message: str):
        super().__init__(message)
        self.code = EacpError(code)


class PlatSecGate:
    """
    EACP Platform Security Gate (PlatSec):
    Validates capability bitmask invariant:
    Granted = Frame.CapabilitiesMask & Manifest.AllowedCapabilities
    Required = ToolRegistry[Action].RequiredCapabilities
    If (Granted & Required) != Required => EACP_ERR_CAPABILITY_DENIED
    """

    def __init__(self, manifest: SecurityManifest, strict_mode: bool = False):
        self.manifest = manifest
        self.strict_mode = strict_mode
        self._tool_registry: Dict[str, Capability] = {}

    def register_tool(self, action: str, required_caps: Capability) -> None:
        self._tool_registry[action] = required_caps

    def get_tool_requirements(self, action: str) -> Optional[Capability]:
        return self._tool_registry.get(action)

    def evaluate(
        self,
        frame_capabilities: int,
        action: str,
        caller_grants: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """Three-layer authorization (fail-closed on every layer):

        1. `caller_grants` — the AUTHENTICATED caller's CA-attested grants
           (None only when no caller attestation is available: relay-side
           registration bounds claims in that case; with a configured CA the
           receiver passes 0 for a caller that presented no valid manifest).
        2. `frame_capabilities` — the request's attenuated permission
           (the caller may ask for LESS than it holds, never more).
        3. `self.manifest.allowed_capabilities` — the target's own policy.

        effective = caller_grants & claimed & target_policy; the tool's
        required bits must be a subset of effective.
        """
        required = self.get_tool_requirements(action)
        if required is None:
            if self.strict_mode:
                return False, EacpError.EACP_ERR_CAPABILITY_DENIED
            return True, EacpError.EACP_SUCCESS

        if required == Capability.NONE:
            return True, EacpError.EACP_SUCCESS

        effective = frame_capabilities
        if caller_grants is not None:
            effective &= caller_grants
        effective &= int(self.manifest.allowed_capabilities)
        if (effective & int(required)) != int(required):
            return False, EacpError.EACP_ERR_CAPABILITY_DENIED

        return True, EacpError.EACP_SUCCESS

    def check_or_raise(
        self,
        frame: EacpFrame,
        action: Optional[str] = None,
        caller_grants: Optional[int] = None,
    ) -> None:
        act = action if action is not None else frame.verb
        allowed, err = self.evaluate(frame.capabilities_mask, act, caller_grants=caller_grants)
        if not allowed:
            required = self.get_tool_requirements(act)
            raise PlatSecException(
                err,
                f"PlatSec capability denied for action '{act}': required={required!r}, granted={frame.capabilities_mask & self.manifest.allowed_capabilities}",
            )


@dataclass
class SignedManifest:
    """
    Enterprise-attested Security Manifest.
    Signed by an Enterprise CA to prevent rogue agent key registration.
    """
    manifest: SecurityManifest
    ca_pin: int
    ca_public_bytes: bytes
    signature: bytes
    expires_at: float

    def canonical_bytes(self) -> bytes:
        pub = self.manifest.public_bytes or b""
        return f"{self.manifest.pin}|{int(self.manifest.allowed_capabilities)}|{self.expires_at:.2f}|".encode("utf-8") + pub

    def is_valid(self, trusted_ca_public_bytes: Optional[bytes] = None) -> bool:
        """Verifies the CA signature.

        `trusted_ca_public_bytes` is the CA key CONFIGURED BY THE VERIFIER
        (e.g. the relay's `EnterpriseCA.public_bytes`). When given, the
        signature is checked against *that* key — never against
        `ca_public_bytes` carried inside the submitted manifest, which an
        attacker controls (a manifest signed by an unrelated CA with a
        spoofed `ca_pin` must not pass). Without a trusted key this method
        retains its legacy self-consistent check and callers should not
        treat the result as an authenticated attestation.
        """
        if time.time() > self.expires_at:
            return False
        key_bytes = trusted_ca_public_bytes if trusted_ca_public_bytes is not None else self.ca_public_bytes
        try:
            ca_pub = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            ca_pub.verify(self.signature, self.canonical_bytes())
            return True
        except Exception:
            return False

    @classmethod
    def from_dict(cls, d: Dict) -> "SignedManifest":
        return cls(
            manifest=SecurityManifest(
                pin=d["pin"],
                allowed_capabilities=Capability(d["allowed_capabilities"]),
                public_bytes=bytes.fromhex(d["public_bytes"]) if d.get("public_bytes") else None,
            ),
            ca_pin=d["ca_pin"],
            ca_public_bytes=bytes.fromhex(d["ca_public_bytes"]),
            signature=bytes.fromhex(d["signature"]),
            expires_at=d["expires_at"],
        )

    def to_dict(self) -> Dict:
        return {
            "pin": self.manifest.pin,
            "allowed_capabilities": int(self.manifest.allowed_capabilities),
            "public_bytes": (self.manifest.public_bytes or b"").hex(),
            "ca_pin": self.ca_pin,
            "ca_public_bytes": self.ca_public_bytes.hex(),
            "signature": self.signature.hex(),
            "expires_at": self.expires_at,
        }


class EnterpriseCA:
    """
    Enterprise Certificate Authority for Agent-PIN registration and PlatSec manifest signing.
    """

    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self._priv = private_key or ed25519.Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self.public_bytes = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.ca_pin = compute_pin(self.public_bytes)

    def sign_manifest(self, manifest: SecurityManifest, ttl_seconds: float = 86400.0) -> SignedManifest:
        expires_at = time.time() + ttl_seconds
        signed_mf = SignedManifest(
            manifest=manifest,
            ca_pin=self.ca_pin,
            ca_public_bytes=self.public_bytes,
            signature=b"",
            expires_at=expires_at,
        )
        sig = self._priv.sign(signed_mf.canonical_bytes())
        signed_mf.signature = sig
        return signed_mf


def encrypt_payload_aes_gcm(payload: bytes, key_256: bytes) -> bytes:
    """
    Encrypts payload using AES-256-GCM for zero-trust confidential agent IPC (FLAG_ENCRYPTED).
    Prefixes output with 12-byte random nonce.
    """
    if len(key_256) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    aesgcm = AESGCM(key_256)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, payload, None)
    return nonce + ciphertext


def decrypt_payload_aes_gcm(encrypted: bytes, key_256: bytes) -> bytes:
    """Decrypts AES-256-GCM encrypted payload."""
    if len(encrypted) < 28:
        raise ValueError("Encrypted buffer too short")
    aesgcm = AESGCM(key_256)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def create_server_ssl_context(
    certfile: str,
    keyfile: str,
    ca_certfile: Optional[str] = None,
    verify_client: bool = True,
) -> ssl.SSLContext:
    """Configures TLS 1.3 / mTLS server context for enterprise cloud/edge relay."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if ca_certfile and verify_client:
        ctx.load_verify_locations(cafile=ca_certfile)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def create_client_ssl_context(
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    ca_certfile: Optional[str] = None,
    verify_server: bool = True,
) -> ssl.SSLContext:
    """Configures TLS 1.3 / mTLS client context for enterprise agents.

    Secure by default: `verify_server=True` (the default) always verifies —
    against `ca_certfile` when given, otherwise against the system trust
    store. Disabling verification requires the EXPLICIT
    `verify_server=False` development opt-out; it is never triggered by
    merely omitting a CA file.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify_server:
        if ca_certfile:
            ctx.load_verify_locations(cafile=ca_certfile)
        else:
            ctx.load_default_certs()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    else:
        # explicit development opt-out — never the default path
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if certfile and keyfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx
