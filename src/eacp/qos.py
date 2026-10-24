"""
EACP Quality of Service (QoS) & Ownership Arbitration Module.
Implements military C4I / OMG DDS (Data Distribution Service) QoS contract semantics
and failover arbitration for autonomous multi-agent meshes.
"""

from dataclasses import dataclass, field
from enum import IntEnum
import time
from typing import Dict, List, Optional, Set, Tuple


class ReliabilityKind(IntEnum):
    BEST_EFFORT = 0  # Fire-and-forget; frames may drop during network congestion
    RELIABLE = 1     # Guaranteed delivery; requires transport/rendezvous acknowledgement


class DurabilityKind(IntEnum):
    VOLATILE = 0         # No history retained for late-joining or reconnecting agents
    TRANSIENT_LOCAL = 1  # In-memory history maintained for currently running sessions
    PERSISTENT = 2       # Chained to append-only audit ledger across restarts


class OwnershipKind(IntEnum):
    SHARED = 0     # Multiple agents can concurrently invoke/publish to the action/topic
    EXCLUSIVE = 1  # Exactly one primary agent holds the execution lease at any given time


class LivelinessKind(IntEnum):
    AUTOMATIC = 0              # Keepalive inferred from transport/rendezvous frames
    MANUAL_BY_PARTICIPANT = 1  # Explicit pulse heartbeats required within lease window


@dataclass(frozen=True)
class QosProfile:
    """
    Contractual QoS specification governing communication between agents.
    Follows DDS Requested vs. Offered (RxO) contract model.
    """
    reliability: ReliabilityKind = ReliabilityKind.RELIABLE
    durability: DurabilityKind = DurabilityKind.VOLATILE
    ownership: OwnershipKind = OwnershipKind.SHARED
    ownership_strength: int = 0          # 0..1000; higher strength preempts lower in EXCLUSIVE mode
    deadline_ms: int = 0                 # Max tolerated turnaround/update latency (0 = unlimited)
    latency_budget_ms: int = 0           # Hint to transport layer for batching vs immediate flush
    liveliness_lease_ms: int = 30000     # Lease period for liveliness checks before failover


@dataclass
class QosViolation:
    violation_type: str  # 'RXO_INCOMPATIBLE', 'DEADLINE_MISSED', 'LIVELINESS_LOST'
    entity_pin: int
    target_or_topic: str
    details: str
    timestamp: float = field(default_factory=time.time)


class QosContractEvaluator:
    """
    Evaluates DDS Requested vs. Offered (RxO) contract compatibility.
    A consumer requesting a contract can only bind to a provider offering
    an equal or strictly stronger guarantee.
    """

    @staticmethod
    def check_rxo_compatibility(
        offered: QosProfile,
        requested: QosProfile,
    ) -> Tuple[bool, Optional[str]]:
        # 1. Reliability: Offered must be >= Requested
        # (Offered RELIABLE satisfies Requested BEST_EFFORT, but not vice-versa)
        if requested.reliability > offered.reliability:
            return (
                False,
                f"Incompatible Reliability: requested {requested.reliability.name} "
                f"but offered {offered.reliability.name}",
            )

        # 2. Durability: Offered must be >= Requested
        if requested.durability > offered.durability:
            return (
                False,
                f"Incompatible Durability: requested {requested.durability.name} "
                f"but offered {offered.durability.name}",
            )

        # 3. Ownership: Ownership kinds must match
        if requested.ownership != offered.ownership:
            return (
                False,
                f"Incompatible Ownership kind: requested {requested.ownership.name} "
                f"vs offered {offered.ownership.name}",
            )

        # 4. Deadline: Offered deadline must be <= Requested deadline (if requested > 0)
        # (Provider must commit to responding at least as fast as consumer demands)
        if requested.deadline_ms > 0:
            if offered.deadline_ms == 0 or offered.deadline_ms > requested.deadline_ms:
                return (
                    False,
                    f"Incompatible Deadline: requested {requested.deadline_ms}ms "
                    f"cannot be satisfied by offered {offered.deadline_ms}ms",
                )

        # 5. Latency Budget: Offered must be <= Requested (if requested > 0)
        if requested.latency_budget_ms > 0:
            if offered.latency_budget_ms > requested.latency_budget_ms:
                return (
                    False,
                    f"Incompatible Latency Budget: requested {requested.latency_budget_ms}ms "
                    f"exceeded by offered {offered.latency_budget_ms}ms",
                )

        return True, None


@dataclass
class CandidateRegistration:
    agent_pin: int
    strength: int
    lease_ms: int
    last_heartbeat: float


class OwnershipArbitrator:
    """
    DDS Exclusive Ownership Arbitrator with automatic failover.
    For a given topic/role, tracks candidate agents by ownership strength.
    If the active primary agent misses its liveliness lease, ownership
    fails over deterministically to the next-highest live candidate.
    """

    def __init__(self) -> None:
        # topic -> {agent_pin -> CandidateRegistration}
        self._topics: Dict[str, Dict[int, CandidateRegistration]] = {}
        # topic -> current_owner_pin
        self._active_owners: Dict[str, Optional[int]] = {}

    def register_candidate(
        self,
        topic: str,
        agent_pin: int,
        strength: int = 100,
        lease_ms: int = 30000,
        now: Optional[float] = None,
    ) -> None:
        t = now if now is not None else time.time()
        if topic not in self._topics:
            self._topics[topic] = {}
        self._topics[topic][agent_pin] = CandidateRegistration(
            agent_pin=agent_pin,
            strength=strength,
            lease_ms=lease_ms,
            last_heartbeat=t,
        )
        self.evaluate_topic(topic, now=t)

    def unregister_candidate(self, topic: str, agent_pin: int, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        if topic in self._topics and agent_pin in self._topics[topic]:
            del self._topics[topic][agent_pin]
            if self._active_owners.get(topic) == agent_pin:
                self._active_owners[topic] = None
            self.evaluate_topic(topic, now=t)

    def heartbeat(self, agent_pin: int, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        for candidates in self._topics.values():
            if agent_pin in candidates:
                candidates[agent_pin].last_heartbeat = t

    def evaluate_topic(self, topic: str, now: Optional[float] = None) -> Optional[int]:
        """
        Determines the current owner for topic.
        Returns the winning agent_pin, or None if no candidate is alive.
        """
        t = now if now is not None else time.time()
        candidates = self._topics.get(topic, {})
        if not candidates:
            self._active_owners[topic] = None
            return None

        # Filter candidates whose liveliness lease has not expired
        live_candidates: List[CandidateRegistration] = []
        for c in candidates.values():
            elapsed_ms = (t - c.last_heartbeat) * 1000.0
            if elapsed_ms <= c.lease_ms:
                live_candidates.append(c)

        if not live_candidates:
            self._active_owners[topic] = None
            return None

        # Sort by strength desc, tie-break by higher agent_pin
        live_candidates.sort(key=lambda c: (c.strength, c.agent_pin), reverse=True)
        winner = live_candidates[0].agent_pin
        self._active_owners[topic] = winner
        return winner

    def get_owner(self, topic: str, now: Optional[float] = None) -> Optional[int]:
        return self.evaluate_topic(topic, now=now)


@dataclass
class _PendingDeadline:
    tx_id: int
    agent_pin: int
    topic_or_verb: str
    deadline_ms: int
    start_time: float


class DeadlineMonitor:
    """
    Monitors synchronous rendezvous and async tasks against contractual deadlines.
    Emits violations when operations exceed their agreed latency ceiling.
    """

    def __init__(self) -> None:
        self._pending: Dict[int, _PendingDeadline] = {}

    def start_deadline(
        self,
        tx_id: int,
        agent_pin: int,
        topic_or_verb: str,
        deadline_ms: int,
        now: Optional[float] = None,
    ) -> None:
        if deadline_ms <= 0:
            return
        t = now if now is not None else time.time()
        self._pending[tx_id] = _PendingDeadline(
            tx_id=tx_id,
            agent_pin=agent_pin,
            topic_or_verb=topic_or_verb,
            deadline_ms=deadline_ms,
            start_time=t,
        )

    def acknowledge(self, tx_id: int) -> bool:
        """Removes a completed transaction from deadline monitoring."""
        return self._pending.pop(tx_id, None) is not None

    def check_violations(self, now: Optional[float] = None) -> List[QosViolation]:
        t = now if now is not None else time.time()
        violations: List[QosViolation] = []
        expired_tx_ids: List[int] = []

        for tx_id, item in self._pending.items():
            elapsed_ms = (t - item.start_time) * 1000.0
            if elapsed_ms > item.deadline_ms:
                violations.append(
                    QosViolation(
                        violation_type="DEADLINE_MISSED",
                        entity_pin=item.agent_pin,
                        target_or_topic=item.topic_or_verb,
                        details=(
                            f"Transaction {tx_id} elapsed {elapsed_ms:.1f}ms "
                            f"exceeded deadline of {item.deadline_ms}ms"
                        ),
                        timestamp=t,
                    )
                )
                expired_tx_ids.append(tx_id)

        for tx_id in expired_tx_ids:
            del self._pending[tx_id]

        return violations
