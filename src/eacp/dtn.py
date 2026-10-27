"""
EACP Disruption-Tolerant Networking (DTN) Module.
Implements RFC 9171 / DARPA Bundle Protocol custody transfer and store-and-forward
resilience for autonomous multi-agent meshes operating in partitioned or lossy environments.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
import time
from typing import Dict, List, Optional, Set, Tuple


class CustodySignal(IntEnum):
    CUSTODY_ACCEPTED = 1   # Custodian node successfully stored bundle and accepted custody responsibility
    CUSTODY_REFUSED = 2    # Custodian node rejected bundle (buffer full, expired, etc.)
    CUSTODY_RELEASED = 3   # Previous custodian node released responsibility after handover
    DELIVERY_RECEIPT = 4   # Final destination agent received and processed bundle


class CustodyRefusalReason(IntEnum):
    NONE = 0
    BUFFER_EXHAUSTED = 1
    LIFETIME_EXPIRED = 2
    UNTRUSTED_CUSTODIAN = 3
    DUPLICATE_BUNDLE = 4
    HOP_COUNT_EXCEEDED = 5


@dataclass
class Bundle:
    """
    DTN Bundle Protocol envelope wrapping arbitrary agent payload or serialized EacpFrame.
    Preserves custody handover and routing state across disconnected edge hops.
    """
    bundle_id: int
    source_pin: int
    destination_pin: int
    custodian_pin: int
    creation_time_s: float
    lifetime_s: float = 3600.0
    custody_transfer_requested: bool = True
    payload: bytes = b""
    hops: int = 0
    max_hops: int = 16

    def is_expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return (t - self.creation_time_s) > self.lifetime_s

    def size_bytes(self) -> int:
        return 64 + len(self.payload)


@dataclass(frozen=True)
class CustodyReport:
    bundle_id: int
    signal: CustodySignal
    reporter_pin: int
    reason: CustodyRefusalReason = CustodyRefusalReason.NONE
    timestamp: float = field(default_factory=time.time)


class CustodyStore:
    """
    Store-and-forward DTN custody manager.
    Retains bundles in custody until the downstream hop explicitly confirms custody acceptance,
    preventing message loss when connections drop mid-flight.
    """

    def __init__(
        self,
        local_pin: int,
        max_bundles: int = 1000,
        max_storage_bytes: int = 64 * 1024 * 1024,  # 64 MB
        seen_cache_size: int = 5000,
    ) -> None:
        self.local_pin = local_pin
        self.max_bundles = max_bundles
        self.max_storage_bytes = max_storage_bytes
        self.seen_cache_size = seen_cache_size

        # In-custody inventory: bundle_id -> Bundle
        self._bundles: Dict[int, Bundle] = {}
        # Track current storage byte footprint
        self._storage_used: int = 0
        # Duplicate suppression ring/set
        self._seen_ids: Set[int] = set()
        self._seen_order: deque = deque()

    @property
    def bundle_count(self) -> int:
        return len(self._bundles)

    @property
    def storage_used(self) -> int:
        return self._storage_used

    def _mark_seen(self, bundle_id: int) -> None:
        if bundle_id not in self._seen_ids:
            self._seen_ids.add(bundle_id)
            self._seen_order.append(bundle_id)
            if len(self._seen_order) > self.seen_cache_size:
                # popleft: O(1) ring eviction (list.pop(0) shifted the
                # whole 5000-entry ring on every bundle past capacity)
                oldest = self._seen_order.popleft()
                self._seen_ids.discard(oldest)

    def admit_bundle(
        self,
        bundle: Bundle,
        now: Optional[float] = None,
    ) -> Tuple[bool, CustodyReport]:
        """
        Attempts to admit and take custody of a bundle from upstream.
        Returns (accepted, CustodyReport).
        """
        t = now if now is not None else time.time()

        # 1. Lifetime check
        if bundle.is_expired(now=t):
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.LIFETIME_EXPIRED,
                timestamp=t,
            )

        # 2. Hop limit check
        if bundle.hops >= bundle.max_hops:
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.HOP_COUNT_EXCEEDED,
                timestamp=t,
            )

        # 3. Duplicate suppression check
        if bundle.bundle_id in self._seen_ids or bundle.bundle_id in self._bundles:
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.DUPLICATE_BUNDLE,
                timestamp=t,
            )

        # 4. Storage capacity check
        bundle_size = bundle.size_bytes()
        if (
            len(self._bundles) >= self.max_bundles
            or (self._storage_used + bundle_size) > self.max_storage_bytes
        ):
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.BUFFER_EXHAUSTED,
                timestamp=t,
            )

        # 5. Take custody
        self._mark_seen(bundle.bundle_id)
        if bundle.custody_transfer_requested:
            bundle.custodian_pin = self.local_pin

        self._bundles[bundle.bundle_id] = bundle
        self._storage_used += bundle_size

        signal = (
            CustodySignal.CUSTODY_ACCEPTED
            if bundle.custody_transfer_requested
            else CustodySignal.DELIVERY_RECEIPT
        )

        return True, CustodyReport(
            bundle_id=bundle.bundle_id,
            signal=signal,
            reporter_pin=self.local_pin,
            reason=CustodyRefusalReason.NONE,
            timestamp=t,
        )

    def forward_bundle(
        self,
        bundle_id: int,
        next_hop_pin: int,
        now: Optional[float] = None,
    ) -> Tuple[Optional[Bundle], Optional[CustodyReport]]:
        """
        Prepares a bundle in custody for forwarding to next-hop custodian.
        Increments hops counter.
        """
        t = now if now is not None else time.time()
        bundle = self._bundles.get(bundle_id)
        if not bundle:
            return None, None

        if bundle.is_expired(now=t):
            self.release_custody(bundle_id)
            return None, CustodyReport(
                bundle_id=bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.LIFETIME_EXPIRED,
                timestamp=t,
            )

        bundle.hops += 1
        if bundle.hops > bundle.max_hops:
            self.release_custody(bundle_id)
            return None, CustodyReport(
                bundle_id=bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.HOP_COUNT_EXCEEDED,
                timestamp=t,
            )

        return bundle, None

    def process_custody_report(self, report: CustodyReport) -> bool:
        """
        Processes a custody report from downstream.
        If downstream accepted custody, releases the local copy safely.
        """
        if report.signal in (CustodySignal.CUSTODY_ACCEPTED, CustodySignal.DELIVERY_RECEIPT):
            return self.release_custody(report.bundle_id)
        return False

    def release_custody(self, bundle_id: int) -> bool:
        """Removes bundle from custody store and frees storage accounting."""
        bundle = self._bundles.pop(bundle_id, None)
        if bundle is not None:
            self._storage_used = max(0, self._storage_used - bundle.size_bytes())
            return True
        return False

    def prune_expired(self, now: Optional[float] = None) -> List[int]:
        """Evicts expired bundles from custody store."""
        t = now if now is not None else time.time()
        expired: List[int] = []
        for bundle_id, bundle in list(self._bundles.items()):
            if bundle.is_expired(now=t):
                expired.append(bundle_id)
                self.release_custody(bundle_id)
        return expired

    def get_bundle(self, bundle_id: int) -> Optional[Bundle]:
        return self._bundles.get(bundle_id)

    def list_bundles(self) -> List[Bundle]:
        return list(self._bundles.values())
