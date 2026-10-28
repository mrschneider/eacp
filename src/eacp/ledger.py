"""
EACP Immutable Audit Ledger:
Append-only cryptographically chained Write-Ahead Log (WAL).

Honest scope (mechanism, not certification): the chain gives TAMPER
EVIDENCE over the recorded entries — a hash chain alone establishes neither
legal non-repudiation nor SOC 2 / ISO 27001 compliance; those require
external controls (signed checkpoints, access control, retention policy).
What ships here: durable appends (flushed to the OS on every record,
fsync'd every `fsync_every` records and on close), recovery of an existing
file AT STARTUP with full chain verification (a broken chain raises
`LedgerIntegrityError` instead of silently starting a fresh chain over
historical content), and size-based rotation to `<path>.1` that preserves
index/hash continuity inside the surviving file.
"""

from __future__ import annotations
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from typing import List, Optional


class LedgerIntegrityError(Exception):
    """The on-disk ledger could not be recovered: corrupt line or broken
    chain. Loud by design — an audit trail that quietly restarts is worse
    than one that refuses."""


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

    def __init__(
        self,
        file_path: Optional[str] = None,
        fsync_every: int = 50,
        rotate_bytes: int = 64 * 1024 * 1024,
    ):
        self.file_path = file_path
        self.fsync_every = max(1, fsync_every)
        self.rotate_bytes = rotate_bytes
        self._entries: List[AuditEntry] = []
        self._last_hash = self.GENESIS_HASH
        # absolute next index — len(self._entries) is NOT the next index
        # after recovering a rotated segment (REL-02): a segment starting
        # at N must continue at N+len, never restart from len
        self._next_index = 0
        self._fh = None
        self._bytes_written = 0
        self._since_fsync = 0
        if file_path:
            self._recover()

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    # ---- recovery ---------------------------------------------------------
    def _recover(self) -> None:
        """Loads an existing ledger file and VERIFIES its chain before
        accepting it. Corrupt content or broken links raise — never a
        silent fresh chain on top of historical records."""
        if not os.path.exists(self.file_path):
            return
        recovered: List[AuditEntry] = []
        with open(self.file_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    entry = AuditEntry(**d)
                except Exception as e:
                    raise LedgerIntegrityError(
                        f"{self.file_path}:{lineno}: unreadable ledger entry ({e})"
                    ) from e
                recovered.append(entry)
        if not recovered:
            return
        # internal chain: indices sequential from the file's own start
        # (rotation restarts the file mid-chain with a non-zero index) and
        # prev_hash/entry_hash consistent; genesis required when index==0
        start = recovered[0].index
        if start == 0 and recovered[0].prev_hash != self.GENESIS_HASH:
            raise LedgerIntegrityError(
                f"{self.file_path}: first entry claims index 0 but prev_hash is not genesis"
            )
        expected_prev = recovered[0].prev_hash
        for offset, entry in enumerate(recovered):
            if entry.index != start + offset:
                raise LedgerIntegrityError(
                    f"{self.file_path}: index discontinuity at file offset {offset} "
                    f"(expected {start + offset}, got {entry.index})"
                )
            if entry.prev_hash != expected_prev:
                raise LedgerIntegrityError(
                    f"{self.file_path}: chain broken at index {entry.index} "
                    f"(prev_hash mismatch — entries were altered or removed)"
                )
            if entry.compute_hash() != entry.entry_hash:
                raise LedgerIntegrityError(
                    f"{self.file_path}: entry hash mismatch at index {entry.index} (tampered content)"
                )
            expected_prev = entry.entry_hash
        self._entries = recovered
        self._last_hash = recovered[-1].entry_hash
        self._next_index = recovered[-1].index + 1
        self._bytes_written = os.path.getsize(self.file_path)

    # ---- durable append ----------------------------------------------------
    def _handle(self):
        if self._fh is None:
            self._fh = open(self.file_path, "a", encoding="utf-8")
        return self._fh

    def _rotate(self) -> None:
        """Size-based rotation: current file becomes `<path>.1`, a fresh
        base starts. Index/hash continuity is preserved INSIDE each file
        (recovery accepts a non-genesis start); the previous file remains
        as the archived segment."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        backup = self.file_path + ".1"
        if os.path.exists(backup):
            os.unlink(backup)
        os.replace(self.file_path, backup)
        self._bytes_written = 0

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
        index = self._next_index
        self._next_index += 1
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

        # Persist: one handle, flushed every record, fsync'd periodically
        if self.file_path:
            if self._bytes_written >= self.rotate_bytes:
                self._rotate()
            line = json.dumps(asdict(entry)) + "\n"
            fh = self._handle()
            fh.write(line)
            fh.flush()
            self._bytes_written += len(line)
            self._since_fsync += 1
            if self._since_fsync >= self.fsync_every:
                os.fsync(fh.fileno())
                self._since_fsync = 0

        return entry

    def close(self) -> None:
        """Final durability barrier (fsync + release)."""
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            finally:
                self._fh.close()
                self._fh = None

    def verify_chain(self) -> bool:
        """
        Cryptographic verification of the entire ledger chain:
        Validates sequential indices, prev_hash link, and individual entry_hash integrity.
        """
        if not self._entries:
            return True
        # indices are absolute but the FILE may start mid-chain (rotated
        # segment): verify continuity from the file's own first index, and
        # require the genesis anchor only when the segment claims index 0
        start = self._entries[0].index
        if start == 0 and self._entries[0].prev_hash != self.GENESIS_HASH:
            return False
        expected_prev = self._entries[0].prev_hash
        for offset, entry in enumerate(self._entries):
            if entry.index != start + offset:
                return False
            if entry.prev_hash != expected_prev:
                return False
            if entry.compute_hash() != entry.entry_hash:
                return False
            expected_prev = entry.entry_hash
        return True