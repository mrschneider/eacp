"""
Tactical & Military Resiliency Test Suite for EACP:
1. DDS-style Requested vs. Offered (RxO) QoS contract evaluation
2. DDS-style Exclusive Ownership Arbitration & Liveliness failover
3. Contractual Deadline Monitoring & Violation Detection
4. RFC 9171 / DARPA DTN Bundle Protocol Store-and-Forward Custody Transfer
5. Custody Handover, Duplicate Suppression, and Expiry Pruning
"""

import unittest

from eacp.qos import (
    DeadlineMonitor,
    DurabilityKind,
    OwnershipArbitrator,
    OwnershipKind,
    QosContractEvaluator,
    QosProfile,
    ReliabilityKind,
)
from eacp.dtn import (
    Bundle,
    CustodyRefusalReason,
    CustodyReport,
    CustodySignal,
    CustodyStore,
)


class TestTacticalResiliency(unittest.TestCase):
    def test_qos_rxo_compatibility(self):
        """RxO contract compatibility checks between publisher/offered and subscriber/requested."""
        offered = QosProfile(
            reliability=ReliabilityKind.RELIABLE,
            durability=DurabilityKind.TRANSIENT_LOCAL,
            ownership=OwnershipKind.EXCLUSIVE,
            deadline_ms=50,
            latency_budget_ms=10,
        )

        # Exact match / compatible
        requested_ok = QosProfile(
            reliability=ReliabilityKind.RELIABLE,
            durability=DurabilityKind.TRANSIENT_LOCAL,
            ownership=OwnershipKind.EXCLUSIVE,
            deadline_ms=100,  # Consumer is fine with 100ms, producer offers 50ms (OK)
            latency_budget_ms=20,
        )
        compat, err = QosContractEvaluator.check_rxo_compatibility(offered, requested_ok)
        self.assertTrue(compat)
        self.assertIsNone(err)

        # Incompatible reliability: consumer demands RELIABLE, producer offers BEST_EFFORT
        best_effort_offered = QosProfile(
            reliability=ReliabilityKind.BEST_EFFORT,
            ownership=OwnershipKind.EXCLUSIVE,
        )
        compat, err = QosContractEvaluator.check_rxo_compatibility(
            best_effort_offered, requested_ok
        )
        self.assertFalse(compat)
        self.assertIn("Incompatible Reliability", str(err))

        # Incompatible durability: consumer wants PERSISTENT, producer offers TRANSIENT_LOCAL
        demanding_durability = QosProfile(
            durability=DurabilityKind.PERSISTENT,
            ownership=OwnershipKind.EXCLUSIVE,
        )
        compat, err = QosContractEvaluator.check_rxo_compatibility(
            offered, demanding_durability
        )
        self.assertFalse(compat)
        self.assertIn("Incompatible Durability", str(err))

        # Incompatible deadline: consumer demands 20ms, producer only guarantees 50ms
        tight_deadline = QosProfile(
            ownership=OwnershipKind.EXCLUSIVE,
            deadline_ms=20,
        )
        compat, err = QosContractEvaluator.check_rxo_compatibility(offered, tight_deadline)
        self.assertFalse(compat)
        self.assertIn("Incompatible Deadline", str(err))

    def test_qos_ownership_arbitration_and_failover(self):
        """Exclusive ownership arbitration with automatic failover upon missed liveliness lease."""
        arbitrator = OwnershipArbitrator()
        topic = "flight-control"
        t0 = 1000.0

        agent_primary = 0xAAAA_1111_2222_3333
        agent_backup = 0xBBBB_4444_5555_6666

        # Register primary (strength 200, lease 5s) and backup (strength 100, lease 5s)
        arbitrator.register_candidate(topic, agent_primary, strength=200, lease_ms=5000, now=t0)
        arbitrator.register_candidate(topic, agent_backup, strength=100, lease_ms=5000, now=t0)

        # Primary has higher strength -> wins ownership
        self.assertEqual(arbitrator.get_owner(topic, now=t0), agent_primary)

        # At t0 + 2s, primary sends heartbeat
        arbitrator.heartbeat(agent_primary, now=t0 + 2.0)

        # At t0 + 6s:
        # Primary last heartbeat was t0 + 2s (4s elapsed <= 5s lease) -> still primary
        # Backup last heartbeat was t0 (6s elapsed > 5s lease, expired)
        self.assertEqual(arbitrator.get_owner(topic, now=t0 + 6.0), agent_primary)

        # Backup sends heartbeat at t0 + 6.5s
        arbitrator.heartbeat(agent_backup, now=t0 + 6.5)

        # At t0 + 8s:
        # Primary last heartbeat was t0 + 2s (6s elapsed > 5s lease -> EXPIRED!)
        # Backup last heartbeat was t0 + 6.5s (1.5s elapsed <= 5s lease -> ALIVE)
        # Failover occurs! Backup becomes primary owner!
        self.assertEqual(arbitrator.get_owner(topic, now=t0 + 8.0), agent_backup)

        # Primary recovers and pulses heartbeat at t0 + 9s
        arbitrator.heartbeat(agent_primary, now=t0 + 9.0)
        # Primary preempts backup due to higher strength
        self.assertEqual(arbitrator.get_owner(topic, now=t0 + 9.0), agent_primary)

    def test_qos_deadline_monitor(self):
        """Monitors task execution against agreed deadlines and detects overruns."""
        monitor = DeadlineMonitor()
        t0 = 1000.0
        agent = 0x1234_5678

        # Task 1: 50ms deadline
        monitor.start_deadline(tx_id=1, agent_pin=agent, topic_or_verb="query", deadline_ms=50, now=t0)
        # Task 2: 200ms deadline
        monitor.start_deadline(tx_id=2, agent_pin=agent, topic_or_verb="compute", deadline_ms=200, now=t0)

        # Complete task 1 within 30ms
        self.assertTrue(monitor.acknowledge(tx_id=1))

        # Check violations at t0 + 0.1s (100ms elapsed) -> Task 2 still within 200ms
        violations = monitor.check_violations(now=t0 + 0.100)
        self.assertEqual(len(violations), 0)

        # Check violations at t0 + 0.250s (250ms elapsed) -> Task 2 missed 200ms deadline!
        violations = monitor.check_violations(now=t0 + 0.250)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "DEADLINE_MISSED")
        self.assertIn("Transaction 2", violations[0].details)

    def test_dtn_admit_bundle_and_custody_transfer(self):
        """Bundle admission, custody assignment and duplicate suppression."""
        local_pin = 0x7070_7070_7070_7070
        store = CustodyStore(local_pin=local_pin, max_bundles=10)
        t0 = 1000.0

        bundle = Bundle(
            bundle_id=101,
            source_pin=0x1111,
            destination_pin=0x9999,
            custodian_pin=0x1111,
            creation_time_s=t0,
            lifetime_s=300.0,
            custody_transfer_requested=True,
            payload=b"Strategic mission vector coordinates",
        )

        # 1. Admit valid bundle -> custody accepted
        ok, report = store.admit_bundle(bundle, now=t0)
        self.assertTrue(ok)
        self.assertEqual(report.signal, CustodySignal.CUSTODY_ACCEPTED)
        self.assertEqual(bundle.custodian_pin, local_pin)
        self.assertEqual(store.bundle_count, 1)

        # 2. Duplicate bundle transmission is refused
        dup_bundle = Bundle(
            bundle_id=101,
            source_pin=0x1111,
            destination_pin=0x9999,
            custodian_pin=0x1111,
            creation_time_s=t0,
            lifetime_s=300.0,
            payload=b"Duplicate data",
        )
        ok, report = store.admit_bundle(dup_bundle, now=t0)
        self.assertFalse(ok)
        self.assertEqual(report.signal, CustodySignal.CUSTODY_REFUSED)
        self.assertEqual(report.reason, CustodyRefusalReason.DUPLICATE_BUNDLE)

    def test_dtn_custody_handover_release(self):
        """End-to-end custody handover across nodes A and B with release upon receipt."""
        pin_a = 0x1111_0000_0000_0000
        pin_b = 0x2222_0000_0000_0000
        store_a = CustodyStore(local_pin=pin_a)
        store_b = CustodyStore(local_pin=pin_b)
        t0 = 2000.0

        bundle = Bundle(
            bundle_id=505,
            source_pin=pin_a,
            destination_pin=0x9999,
            custodian_pin=pin_a,
            creation_time_s=t0,
            lifetime_s=600.0,
            custody_transfer_requested=True,
            payload=b"Payload across severed WAN link",
        )

        # Custodian A stores the bundle
        ok, _ = store_a.admit_bundle(bundle, now=t0)
        self.assertTrue(ok)
        self.assertEqual(store_a.bundle_count, 1)

        # Link becomes available: A forwards bundle to B
        fwd_bundle, err_report = store_a.forward_bundle(505, next_hop_pin=pin_b, now=t0 + 10.0)
        self.assertIsNotNone(fwd_bundle)
        self.assertIsNone(err_report)
        assert fwd_bundle is not None
        self.assertEqual(fwd_bundle.hops, 1)

        # B admits bundle and accepts custody
        b_accepted, b_report = store_b.admit_bundle(fwd_bundle, now=t0 + 10.0)
        self.assertTrue(b_accepted)
        self.assertEqual(b_report.signal, CustodySignal.CUSTODY_ACCEPTED)
        self.assertEqual(store_b.bundle_count, 1)

        # B sends CustodyReport back to A -> A releases bundle from local store
        released = store_a.process_custody_report(b_report)
        self.assertTrue(released)
        self.assertEqual(store_a.bundle_count, 0)
        self.assertEqual(store_a.storage_used, 0)

    def test_dtn_expiry_and_pruning(self):
        """Bundle lifetime expiration on admission and proactive queue pruning."""
        store = CustodyStore(local_pin=0x7070)
        t0 = 5000.0

        # 1. Expired bundle on admission is refused
        expired_bundle = Bundle(
            bundle_id=601,
            source_pin=0x1111,
            destination_pin=0x9999,
            custodian_pin=0x1111,
            creation_time_s=t0 - 100.0,
            lifetime_s=60.0,  # 100s elapsed > 60s lifetime
            payload=b"Old telemetry",
        )
        ok, report = store.admit_bundle(expired_bundle, now=t0)
        self.assertFalse(ok)
        self.assertEqual(report.reason, CustodyRefusalReason.LIFETIME_EXPIRED)

        # 2. Bundle admitted fresh, then expires over time
        fresh_bundle = Bundle(
            bundle_id=602,
            source_pin=0x1111,
            destination_pin=0x9999,
            custodian_pin=0x1111,
            creation_time_s=t0,
            lifetime_s=30.0,
            payload=b"Fresh telemetry",
        )
        ok, _ = store.admit_bundle(fresh_bundle, now=t0)
        self.assertTrue(ok)
        self.assertEqual(store.bundle_count, 1)

        # Prune at t0 + 10s -> still fresh
        evicted = store.prune_expired(now=t0 + 10.0)
        self.assertEqual(len(evicted), 0)
        self.assertEqual(store.bundle_count, 1)

        # Prune at t0 + 35s -> expired, evicted!
        evicted = store.prune_expired(now=t0 + 35.0)
        self.assertEqual(evicted, [602])
        self.assertEqual(store.bundle_count, 0)

    def test_dtn_hop_limit_and_capacity_guard(self):
        """Enforces hop limits against routing loops and capacity caps against DoS."""
        store = CustodyStore(local_pin=0x7070, max_bundles=2)
        t0 = 1000.0

        # Hop limit
        looping_bundle = Bundle(
            bundle_id=701,
            source_pin=0x1111,
            destination_pin=0x9999,
            custodian_pin=0x1111,
            creation_time_s=t0,
            lifetime_s=300.0,
            hops=16,
            max_hops=16,
            payload=b"Looping packet",
        )
        ok, report = store.admit_bundle(looping_bundle, now=t0)
        self.assertFalse(ok)
        self.assertEqual(report.reason, CustodyRefusalReason.HOP_COUNT_EXCEEDED)

        # Capacity guard (max 2 bundles)
        b1 = Bundle(bundle_id=1, source_pin=1, destination_pin=2, custodian_pin=1, creation_time_s=t0, lifetime_s=100)
        b2 = Bundle(bundle_id=2, source_pin=1, destination_pin=2, custodian_pin=1, creation_time_s=t0, lifetime_s=100)
        b3 = Bundle(bundle_id=3, source_pin=1, destination_pin=2, custodian_pin=1, creation_time_s=t0, lifetime_s=100)

        self.assertTrue(store.admit_bundle(b1, now=t0)[0])
        self.assertTrue(store.admit_bundle(b2, now=t0)[0])
        ok, report = store.admit_bundle(b3, now=t0)
        self.assertFalse(ok)
        self.assertEqual(report.reason, CustodyRefusalReason.BUFFER_EXHAUSTED)


if __name__ == "__main__":
    unittest.main()
