"""
EACP Immutable Audit Ledger:
Append-only cryptographically chained Write-Ahead Log (WAL) for SOC2 / ISO 27001 compliance.
Verifiable tamper-evident execution trail.
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import List, Optional


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    prev_hash: str
    tx_id: int
    sender_pin: int
    target_pin: int
    verb: str
    capabilities_mask: int
    status: int
    data_digest: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        body = f"{self.index}|{self.timestamp:.6f}|{self.prev_hash}|{self.tx_id}|{self.sender_pin}|{self.target_pin}|{self.verb}|{self.capabilities_mask}|{self.status}|{self.data_digest}"
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditLedger:
    """
    Append-only cryptographically chained audit ledger.
    Every authorization decision and rendezvous transaction generates an entry.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path
        self._entries: List[AuditEntry] = []
        self._last_hash = self.GENESIS_HASH

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def record(
        self,
        tx_id: int,
        sender_pin: int,
        target_pin: int,
        verb: str,
        capabilities_mask: int,
        status: int,
        data_payload: Optional[bytes | str] = None,
    ) -> AuditEntry:
        """Appends a cryptographically chained audit record."""
        index = len(self._entries)
        now = time.time()
        
        # Digest payload content (without storing sensitive PII in plain text)
        if data_payload is None:
            data_digest = ""
        elif isinstance(data_payload, bytes):
            data_digest = hashlib.sha256(data_payload).hexdigest()
        else:
            data_digest = hashlib.sha256(str(data_payload).encode("utf-8")).hexdigest()

        entry = AuditEntry(
            index=index,
            timestamp=now,
            prev_hash=self._last_hash,
            tx_id=tx_id,
            sender_pin=sender_pin,
            target_pin=target_pin,
            verb=verb,
            capabilities_mask=capabilities_mask,
            status=status,
            data_digest=data_digest,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        self._last_hash = entry.entry_hash

        # Persist if file backing configured
        if self.file_path:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry)) + "\n")

        return entry

    def verify_chain(self) -> bool:
        """
        Cryptographic verification of the entire ledger chain:
        Validates sequential indices, prev_hash link, and individual entry_hash integrity.
        """
        expected_prev = self.GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                return False
            if entry.prev_hash != expected_prev:
                return False
            if entry.compute_hash() != entry.entry_hash:
                return False
            expected_prev = entry.entry_hash
        return True
