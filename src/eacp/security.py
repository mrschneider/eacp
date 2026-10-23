"""
EACP Security Subsystem: PlatSec capability enforcement and Ed25519 Agent-PIN identity.
"""

from __future__ import annotations
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

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

    def evaluate(self, frame_capabilities: int, action: str) -> Tuple[bool, int]:
        required = self.get_tool_requirements(action)
        if required is None:
            if self.strict_mode:
                return False, EacpError.EACP_ERR_CAPABILITY_DENIED
            return True, EacpError.EACP_SUCCESS

        if required == Capability.NONE:
            return True, EacpError.EACP_SUCCESS

        granted = (frame_capabilities & int(self.manifest.allowed_capabilities))
        if (granted & int(required)) != int(required):
            return False, EacpError.EACP_ERR_CAPABILITY_DENIED

        return True, EacpError.EACP_SUCCESS

    def check_or_raise(self, frame: EacpFrame, action: Optional[str] = None) -> None:
        act = action if action is not None else frame.verb
        allowed, err = self.evaluate(frame.capabilities_mask, act)
        if not allowed:
            required = self.get_tool_requirements(act)
            raise PlatSecException(
                err,
                f"PlatSec capability denied for action '{act}': required={required!r}, granted={frame.capabilities_mask & self.manifest.allowed_capabilities}",
            )
