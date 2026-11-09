"""Regressions for bounded resources and faster signed request processing."""
import asyncio
import copy
import hashlib
import json
import tempfile
import threading
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from eacp.budget import PayloadTokenMeter
from eacp.client import RSessionBase
from eacp.constants import EacpError
from eacp.dtn import Bundle, CustodyStore
from eacp.frame import EacpFrame, ExecutionConstraints
from eacp.ledger import AuditLedger, LedgerIntegrityError
from eacp.qos import OwnershipArbitrator
from eacp.relay import EacpRelay
from eacp.security import AgentIdentity, AgentVerifier


class VerifyCacheTests(unittest.TestCase):
    """Regression tests for AgentVerifier.verify cache + LRU eviction."""

    def _frame(self, ident):
        frame = EacpFrame(verb='echo', data=b'x' * 4096)
        ident.sign_frame(frame)
        return frame

    def test_cache_hit_is_equivalent_to_full_verify(self):
        ident = AgentIdentity.generate()
        v = AgentVerifier.from_public_bytes(ident.public_bytes)
        f = self._frame(ident)
        data = f.get_signed_bytes()
        sig = f.envelope.signature
        self.assertTrue(v.verify(sig, data))
        # second call is a cache hit and must return the same result
        self.assertTrue(v.verify(sig, data))

    def test_tampered_data_is_never_served_from_cache(self):
        # A cache hit must correspond ONLY to the exact bytes verified:
        # mutating the data changes its SHA-256, so the lookup misses and the
        # curve op runs on the tampered bytes and rejects.
        ident = AgentIdentity.generate()
        v = AgentVerifier.from_public_bytes(ident.public_bytes)
        f = self._frame(ident)
        data = f.get_signed_bytes()
        sig = f.envelope.signature
        self.assertTrue(v.verify(sig, data))
        tampered = bytearray(data); tampered[5] ^= 0x01
        self.assertFalse(v.verify(sig, bytes(tampered)))
        # a wrong signature is still rejected (no cache shortcut)
        self.assertFalse(v.verify(b'\x01' * 64, data))

    def test_lru_eviction_bounds_cache_and_keeps_hot_entry(self):
        ident = AgentIdentity.generate()
        v = AgentVerifier.from_public_bytes(ident.public_bytes)
        v._verify_cache_max = 4
        frames = [self._frame(ident) for _ in range(6)]
        for fr in frames:
            v.verify_frame(fr)
        self.assertLessEqual(len(v._verify_cache), 4)
        # the hot frame (touched last) survives, an early one is evicted
        self.assertIn((hashlib.sha256(frames[-1].get_signed_bytes()).digest(),
                       frames[-1].envelope.signature), v._verify_cache)


class SerializationTests(unittest.TestCase):
    def test_atomic_sign_pack_matches_legacy_bytes(self):
        ident = AgentIdentity.generate()
        values = [None, b'raw', {'text': '漢字', 'n': 1e-7},
                  {'n': 2**100}, {'rows': ['x'*100 for _ in range(1000)]}]
        for value in values:
            with self.subTest(type=type(value), length=len(str(value))):
                old = EacpFrame(verb='echo', data=copy.deepcopy(value))
                new = EacpFrame(verb='echo', data=copy.deepcopy(value))
                ident.sign_frame(old, session_handle=19)
                expected = old.pack()
                with patch('eacp.frame.json.dumps', wraps=json.dumps) as dumps:
                    actual = ident.pack_frame(new, session_handle=19)
                    self.assertEqual(dumps.call_count, 0 if value is None or isinstance(value, bytes) else 1)
                self.assertEqual(actual, expected)
                verifier = AgentVerifier.from_public_bytes(ident.public_bytes)
                self.assertTrue(verifier.verify_frame(EacpFrame.unpack(actual)))

    def test_nested_mutation_is_not_hidden_by_sign_pack(self):
        ident = AgentIdentity.generate()
        frame = EacpFrame(verb='echo', data={'rows': [{'value': 1}]})
        wire = ident.pack_frame(frame)
        frame.data['rows'][0]['value'] = 2
        verifier = AgentVerifier.from_public_bytes(ident.public_bytes)
        self.assertFalse(verifier.verify_frame(frame))
        self.assertTrue(verifier.verify_frame(EacpFrame.unpack(wire)))
        self.assertNotEqual(frame.pack(), wire)

    def test_meter_preserves_whitespace_unicode_and_rounding(self):
        meter = PayloadTokenMeter()
        for value in ({'x': '漢'}, {}, None, {'n': 1.0}, {'rows': [1, 2]}):
            frame = EacpFrame(data=value)
            result = {'value': 'é'}
            req = len(json.dumps(value or {}).encode())
            res = len(json.dumps(result, default=str).encode())
            self.assertEqual(meter.estimate_request(frame), (req+3)//4)
            self.assertEqual(meter.measure(frame, result), (req+res+3)//4)
            self.assertEqual(meter.measure_with_request_size(meter.request_size(frame), result), (req+res+3)//4)


class HandlerTests(unittest.IsolatedAsyncioTestCase):
    def session(self):
        session = RSessionBase(max_concurrent_handlers=1)
        session.reply = AsyncMock()
        return session

    async def test_blocking_handler_leaves_loop_responsive(self):
        session = self.session()
        started, release = threading.Event(), threading.Event()
        def handler(frame):
            started.set()
            release.wait(2)
            return {'ok': True}
        session.register_handler('wait', handler)
        task = asyncio.create_task(session._dispatch_handler(EacpFrame(verb='wait')))
        try:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(.005)
            self.assertTrue(started.is_set())
            self.assertFalse(task.done())
        finally:
            release.set()
        await task
        self.assertEqual(session.reply.call_args.kwargs['status'], EacpError.EACP_SUCCESS)

    async def test_loop_affinity_opt_out_and_async_handler(self):
        session = self.session()
        owner = threading.get_ident()
        seen = []
        def inline(frame):
            seen.append(threading.get_ident())
            return {}
        session.register_handler('inline', inline, run_in_thread=False)
        await session._dispatch_handler(EacpFrame(verb='inline'))
        async def aio(frame):
            seen.append(threading.get_ident())
            return {}
        session.register_handler('aio', aio)
        await session._dispatch_handler(EacpFrame(verb='aio'))
        self.assertEqual(seen, [owner, owner])

    async def test_cancelled_worker_keeps_concurrency_slot_until_finished(self):
        session = self.session()
        started, release = threading.Event(), threading.Event()
        second_started = threading.Event()
        def blocking(frame):
            if frame.transaction_id == 1:
                started.set()
                release.wait(2)
            else:
                second_started.set()
            return {}
        session.register_handler('wait', blocking)
        first = asyncio.create_task(session._dispatch_handler(EacpFrame(verb='wait', transaction_id=1,
            constraints=ExecutionConstraints(token_budget=100))))
        try:
            for _ in range(100):
                if started.is_set(): break
                await asyncio.sleep(.005)
            self.assertTrue(started.is_set())
            first.cancel()
            second = asyncio.create_task(session._dispatch_handler(EacpFrame(verb='wait', transaction_id=2)))
            await asyncio.sleep(.02)
            self.assertFalse(second_started.is_set())
            self.assertFalse(first.done())
            self.assertEqual(session.ledger.reserved, 100)
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await first
        await second
        self.assertTrue(second_started.is_set())
        self.assertEqual(session.ledger.reserved, 0)

    async def test_request_estimate_is_not_serialized_again_after_handler(self):
        session = self.session()
        session.register_handler('echo', lambda f: {'ok': True})
        frame = EacpFrame(verb='echo', data={'text': 'hello'},
                          constraints=ExecutionConstraints(token_budget=1000))
        with patch.object(session.token_meter, 'request_size', wraps=session.token_meter.request_size) as size:
            await session._dispatch_handler(frame)
            self.assertEqual(size.call_count, 1)


class CustodyTests(unittest.TestCase):
    @staticmethod
    def bundle(bid, lifetime):
        return Bundle(bid, 1, 2, 0, 0, lifetime_s=lifetime)

    def test_mixed_expiry_and_boundary(self):
        store = CustodyStore(1)
        store.admit_bundle(self.bundle(1, 100), now=0)
        store.admit_bundle(self.bundle(2, 1), now=0)
        self.assertEqual(store.prune_expired(now=1), [])
        self.assertEqual(store.prune_expired(now=2), [2])
        self.assertEqual(store.bundle_count, 1)
        self.assertEqual(store.storage_used, store.get_bundle(1).size_bytes())

    def test_release_churn_compacts_tombstones(self):
        store = CustodyStore(1, seen_cache_size=1)
        store.admit_bundle(self.bundle(0, 1000), now=0)
        for bid in range(1, 5000):
            store.admit_bundle(self.bundle(bid, 10), now=0)
            store.release_custody(bid)
        self.assertLessEqual(len(store._expiry_heap), 2*store.bundle_count+64)
        self.assertEqual(store.prune_expired(now=11), [])
        self.assertEqual(store.prune_expired(now=1001), [0])

    def test_no_expiry_does_not_copy_inventory(self):
        store = CustodyStore(1, max_bundles=20001)
        for bid in range(20000):
            store.admit_bundle(self.bundle(bid, 100), now=0)
        tracemalloc.start()
        try:
            self.assertEqual(store.prune_expired(now=1), [])
            self.assertLess(tracemalloc.get_traced_memory()[1], 16384)
        finally:
            tracemalloc.stop()


class OwnershipTests(unittest.TestCase):
    def test_heartbeat_updates_only_registered_topics_and_unregister_cleans_index(self):
        arb = OwnershipArbitrator()
        arb.register_candidate('a', 1, lease_ms=1000, now=0)
        arb.register_candidate('b', 1, lease_ms=1000, now=0)
        arb.register_candidate('unrelated', 2, now=0)
        arb.heartbeat(1, now=2)
        self.assertEqual(arb.get_owner('a', now=2), 1)
        self.assertEqual(arb.get_owner('b', now=2), 1)
        self.assertEqual(arb._topics['unrelated'][2].last_heartbeat, 0)
        arb.unregister_candidate('a', 1)
        arb.unregister_candidate('b', 1)
        self.assertNotIn(1, arb._agent_topics)
        arb.heartbeat(1)

    def test_strength_pin_tie_and_expiry(self):
        arb = OwnershipArbitrator()
        for pin, strength, lease in [(1, 100, 2000), (2, 100, 2000), (3, 200, 1000)]:
            arb.register_candidate('t', pin, strength, lease, now=0)
        self.assertEqual(arb.get_owner('t', now=1), 3)
        self.assertEqual(arb.get_owner('t', now=1.1), 2)
        self.assertIsNone(arb.get_owner('t', now=3))


class AuditTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name)/'audit.log')
    def tearDown(self):
        self.tmp.cleanup()
    @staticmethod
    def record(ledger, i):
        return ledger.record(i, 1, 2, 'echo', 0, 0)
    async def append(self, ledger, i):
        return await ledger.record_async(i, 1, 2, 'echo', 0, 0)

    async def test_bounded_retention_and_full_file_verification(self):
        ledger = AuditLedger(self.path, max_memory_entries=2)
        try:
            for i in range(20):
                await self.append(ledger, i)
            self.assertEqual([e.index for e in ledger.entries], [18, 19])
            self.assertTrue(ledger.verify_chain())
        finally:
            await ledger.close_async()
        recovered = AuditLedger(self.path, max_memory_entries=1)
        self.assertEqual(recovered.entries[0].index, 19)
        self.assertEqual(self.record(recovered, 20).index, 20)
        recovered.close()
        lines = Path(self.path).read_text().splitlines()
        entry = json.loads(lines[0]); entry['status'] = 77
        lines[0] = json.dumps(entry)
        Path(self.path).write_text('\n'.join(lines)+'\n')
        with self.assertRaises(LedgerIntegrityError):
            AuditLedger(self.path, max_memory_entries=1)

    async def test_queue_limit_order_and_cancelled_write_are_durable(self):
        ledger = AuditLedger(self.path, write_queue_size=1, fsync_every=1)
        started, release = threading.Event(), threading.Event()
        original = ledger._record
        def slow(*args, **kwargs):
            started.set(); release.wait(2)
            return original(*args, **kwargs)
        with patch.object(ledger, '_record', slow):
            first = asyncio.create_task(self.append(ledger, 1))
            try:
                for _ in range(100):
                    if started.is_set(): break
                    await asyncio.sleep(.005)
                self.assertTrue(started.is_set())
                first.cancel()
                second = asyncio.create_task(self.append(ledger, 2))
                await asyncio.sleep(.02)
                self.assertFalse(first.done())
                self.assertEqual(ledger._executor._work_queue.qsize(), 0)
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await first
            result = await second
            self.assertEqual(result.index, 1)
        await ledger.close_async()
        recovered = AuditLedger(self.path)
        self.assertEqual([e.tx_id for e in recovered.entries], [1, 2])
        self.assertTrue(recovered.verify_chain())
        recovered.close()

    async def test_write_failure_is_reported_and_poisons_further_appends(self):
        ledger = AuditLedger(self.path, fsync_every=1)
        try:
            with patch('eacp.ledger.os.fsync', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError):
                    await self.append(ledger, 1)
            self.assertEqual(ledger.entries, [])
            with self.assertRaises(LedgerIntegrityError):
                await self.append(ledger, 2)
        finally:
            await ledger.close_async()

    async def test_close_drains_submitted_writes(self):
        ledger = AuditLedger(self.path, write_queue_size=4)
        tasks = [asyncio.create_task(self.append(ledger, i)) for i in range(4)]
        await asyncio.sleep(0)
        await ledger.close_async()
        results = await asyncio.gather(*tasks)
        self.assertEqual([e.index for e in results], list(range(4)))
        self.assertIsNone(ledger._executor)
        with self.assertRaises(RuntimeError):
            await self.append(ledger, 5)

    async def test_live_relay_audit_survives_concurrent_signed_traffic(self):
        relay = EacpRelay(audit_file_path=self.path, audit_queue_size=2,
                          audit_max_memory_entries=3)
        await relay.start(host='127.0.0.1', port=0)
        port = relay.server.sockets[0].getsockname()[1]
        caller = RSessionBase(heartbeat_interval_s=0)
        target = RSessionBase(heartbeat_interval_s=0)
        async def echo(frame):
            return {'n': frame.data['n']}
        target.register_handler('echo', echo)
        try:
            await target.connect(host='127.0.0.1', port=port)
            await caller.connect(host='127.0.0.1', port=port)
            results = await asyncio.gather(*(
                caller.send(target_pin=target.pin, verb='echo', data={'n': i})
                for i in range(20)
            ))
            self.assertEqual([r.data for r in results], [{'n': i} for i in range(20)])
            self.assertEqual(len(relay.ledger.entries), 3)
        finally:
            await caller.close()
            await target.close()
            await relay.stop()
        recovered = AuditLedger(self.path, max_memory_entries=None)
        try:
            self.assertGreaterEqual(len(recovered.entries), 40)
            self.assertTrue(recovered.verify_chain())
        finally:
            recovered.close()

    async def test_zero_retention_continues_chain_on_recovery(self):
        ledger = AuditLedger(self.path, max_memory_entries=0)
        await self.append(ledger, 1)
        self.assertEqual(ledger.entries, [])
        await ledger.close_async()
        recovered = AuditLedger(self.path, max_memory_entries=0)
        self.assertEqual(self.record(recovered, 2).index, 1)
        recovered.close()
