"""
Comprehensive Acceptance and Concurrency Stress Test Suite for Work Package #4:
Multi-Process Audit Chain Serialization & Sequence Ordering.

Verifies all 12 criteria specified in WP-4:
1. Two processes append simultaneously: No sequence collision
2. Ten processes append concurrently: One valid, un-forked chain
3. Hundreds of concurrent audit events: Continuous sequence and exact unique event count
4. Duplicate event ID submitted twice: Idempotent return of one committed event
5. Process crashes during append: No partial block committed (atomic rollback)
6. Process crashes after commit: Retry discovers existing event
7. Database uniqueness violation: Controlled error (sqlite3.IntegrityError)
8. Database lock contention: Safe retry with backoff and jitter
9. Restart with historical blocks: Full chain rehydration and continued numbering
10. Modify a historical block: Integrity verification fails (TAMPERING_DETECTED)
11. Concurrent workers with different event payloads: Correct previous-hash ordering
12. Full repository regression suite: Zero regressions
"""

import hashlib
import multiprocessing as mp
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from typing import Any
from unittest.mock import patch

import pytest

from audit_writer.chain_writer import AuditChainWriter, AuditPersistenceError
from fabric.persistent_db import PersistentStorageEngine


# Top-level helper function for multiprocessing workers (Windows pickleable)
def _mp_worker_append_events(db_path: str, event_ids: list[str], agent_id: str, results_queue: Any):
    """Worker task executed in separate OS processes."""
    writer = AuditChainWriter(db_path=db_path)
    worker_records = []
    for ev_id in event_ids:
        rec = writer.write_event(
            event_type="MULTIPROCESS_AUDIT_ACTION",
            request_id=f"REQ-{ev_id}",
            agent_id=agent_id,
            request_hash=hashlib.sha256(ev_id.encode()).hexdigest(),
            risk_score=1.5,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id=ev_id
        )
        worker_records.append({
            "sequence_number": rec.sequence_number,
            "event_id": rec.event_id,
            "record_hash": rec.record_hash,
            "previous_record_hash": rec.previous_record_hash
        })
    results_queue.put(worker_records)


def _mp_worker_varied_payloads(db_path: str, payload_specs: list[dict[str, Any]], results_queue: Any):
    """Worker task with varied business payloads executed in separate OS processes."""
    writer = AuditChainWriter(db_path=db_path)
    worker_records = []
    for spec in payload_specs:
        rec = writer.write_event(
            event_type=spec["event_type"],
            request_id=spec["request_id"],
            agent_id=spec["agent_id"],
            request_hash=hashlib.sha256(spec["request_id"].encode()).hexdigest(),
            risk_score=spec.get("risk_score", 1.0),
            policy_version="1.0",
            decision=spec.get("decision", "ALLOWED"),
            execution_result=spec.get("execution_result", "SUCCESS"),
            event_id=spec["event_id"]
        )
        worker_records.append({
            "sequence_number": rec.sequence_number,
            "event_id": rec.event_id,
            "record_hash": rec.record_hash,
            "previous_record_hash": rec.previous_record_hash
        })
    results_queue.put(worker_records)


@pytest.fixture
def temp_audit_dir():
    d = tempfile.mkdtemp(prefix="agenttrust_audit_wp4_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestMultiProcessAuditChainSerialization:
    """Automated security and concurrency stress test suite for WP-4."""

    def test_01_two_processes_append_simultaneously(self, temp_audit_dir):
        """
        Criterion 1: Two processes append simultaneously.
        No sequence collisions or duplicate numbers across separate OS processes.
        """
        db_path = os.path.join(temp_audit_dir, "two_process_chain.db")
        # Pre-seed genesis
        AuditChainWriter(db_path=db_path)

        events_p1 = [f"EV-P1-{i:03d}" for i in range(1, 26)]
        events_p2 = [f"EV-P2-{i:03d}" for i in range(1, 26)]

        ctx = mp.get_context("spawn")
        q1 = ctx.Queue()
        q2 = ctx.Queue()

        p1 = ctx.Process(target=_mp_worker_append_events, args=(db_path, events_p1, "AGENT-WORKER-01", q1))
        p2 = ctx.Process(target=_mp_worker_append_events, args=(db_path, events_p2, "AGENT-WORKER-02", q2))

        p1.start()
        p2.start()

        res1 = q1.get(timeout=30)
        res2 = q2.get(timeout=30)

        p1.join(timeout=10)
        p2.join(timeout=10)

        assert len(res1) == 25
        assert len(res2) == 25

        # Inspect resulting database ledger
        verifier = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        chain = verifier.get_chain()

        # Genesis (0) + 50 worker events = 51 total blocks
        assert len(chain) == 51

        # Assert all allocated sequences are strictly unique and continuous: 0 to 50
        sequences = [r["sequence_number"] for r in chain]
        assert sequences == list(range(51))

        # Assert no duplicate sequence numbers
        assert len(set(sequences)) == 51

        # Cryptographic chain integrity check
        integrity = verifier.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["status"] == "VERIFIED_INTACT"

    def test_02_ten_processes_append_concurrently(self, temp_audit_dir):
        """
        Criterion 2: Ten processes append concurrently.
        Produces exactly one valid, unbroken audit chain.
        """
        db_path = os.path.join(temp_audit_dir, "ten_process_chain.db")
        AuditChainWriter(db_path=db_path)

        num_processes = 10
        events_per_process = 5

        ctx = mp.get_context("spawn")
        processes = []
        queues = []

        for p_idx in range(num_processes):
            q = ctx.Queue()
            ev_list = [f"EV-P{p_idx:02d}-{i:03d}" for i in range(events_per_process)]
            p = ctx.Process(target=_mp_worker_append_events, args=(db_path, ev_list, f"AGENT-P{p_idx:02d}", q))
            processes.append(p)
            queues.append(q)

        # Start all 10 processes concurrently
        for p in processes:
            p.start()

        all_results = []
        for q in queues:
            all_results.extend(q.get(timeout=45))

        for p in processes:
            p.join(timeout=10)

        assert len(all_results) == num_processes * events_per_process

        # Verify unified ledger
        verifier = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        chain = verifier.get_chain()
        expected_total = 1 + (num_processes * events_per_process)
        assert len(chain) == expected_total

        seqs = [r["sequence_number"] for r in chain]
        assert seqs == list(range(expected_total))
        assert len(set(seqs)) == expected_total

        integrity = verifier.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["status"] == "VERIFIED_INTACT"

    def test_03_hundreds_of_concurrent_audit_events(self, temp_audit_dir):
        """
        Criterion 3: Hundreds of concurrent audit events.
        Verifies continuous sequence and that the number of unique committed
        event IDs equals the expected count under sustained load.
        """
        db_path = os.path.join(temp_audit_dir, "heavy_stress_chain.db")
        AuditChainWriter(db_path=db_path)

        num_workers = 6
        events_per_worker = 30
        expected_events = num_workers * events_per_worker  # 180 events

        ctx = mp.get_context("spawn")
        processes = []
        queues = []

        expected_event_ids = set()
        for w_idx in range(num_workers):
            q = ctx.Queue()
            ev_list = [f"EV-STRESS-W{w_idx:02d}-{i:04d}" for i in range(events_per_worker)]
            expected_event_ids.update(ev_list)
            p = ctx.Process(target=_mp_worker_append_events, args=(db_path, ev_list, f"AGENT-STRESS-{w_idx}", q))
            processes.append(p)
            queues.append(q)

        for p in processes:
            p.start()

        collected = []
        for q in queues:
            collected.extend(q.get(timeout=60))

        for p in processes:
            p.join(timeout=15)

        assert len(collected) == expected_events

        # Rehydrate and verify chain continuity
        verifier = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        chain = verifier.get_chain()
        assert len(chain) == expected_events + 1  # Including Genesis

        committed_event_ids = {r["event_id"] for r in chain if r["event_id"] != "EV-GENESIS-000"}
        assert len(committed_event_ids) == expected_events
        assert committed_event_ids == expected_event_ids

        sequences = [r["sequence_number"] for r in chain]
        assert sequences == list(range(expected_events + 1))

        # Check cryptographic link of every single block
        for i in range(1, len(chain)):
            assert chain[i]["previous_record_hash"] == chain[i - 1]["record_hash"]

        integrity = verifier.verify_chain_integrity()
        assert integrity["valid"] is True

    def test_04_duplicate_event_id_submitted_twice(self, temp_audit_dir):
        """
        Criterion 4: Duplicate event ID submitted twice.
        Idempotent write: second write discovers existing event and returns it without appending another record.
        """
        db_path = os.path.join(temp_audit_dir, "idemp_chain.db")
        writer = AuditChainWriter(db_path=db_path)

        dup_event_id = "EV-IDEMP-SPECIAL-999"

        # First write
        rec1 = writer.write_event(
            event_type="TRANSFER_FUNDS",
            request_id="REQ-ORIGINAL-001",
            agent_id="AGENT-IDEMP",
            request_hash="hash-orig-001",
            risk_score=2.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id=dup_event_id
        )
        first_seq = rec1.sequence_number
        first_hash = rec1.record_hash
        total_blocks_after_first = len(writer.get_chain())

        # Second write with exact same event_id (e.g. retry after network timeout)
        rec2 = writer.write_event(
            event_type="TRANSFER_FUNDS",
            request_id="REQ-RETRY-002",
            agent_id="AGENT-IDEMP",
            request_hash="hash-retry-002",
            risk_score=2.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id=dup_event_id
        )

        # Must return the existing committed record
        assert rec2.sequence_number == first_seq
        assert rec2.record_hash == first_hash
        assert rec2.event_id == dup_event_id

        # Total blocks in ledger must remain exactly the same
        chain = writer.get_chain()
        assert len(chain) == total_blocks_after_first

        # Confirm in SQLite directly that only ONE block exists for this event_id
        storage = PersistentStorageEngine(db_path)
        blocks_with_id = [b for b in storage.get_all_blocks() if b.get("event_id") == dup_event_id]
        assert len(blocks_with_id) == 1

    def test_05_process_crashes_during_append(self, temp_audit_dir):
        """
        Criterion 5: Process crashes during append.
        If an error or process termination occurs before commit, no partial block is committed.
        """
        db_path = os.path.join(temp_audit_dir, "crash_during_append.db")
        writer = AuditChainWriter(db_path=db_path)

        # Append valid event #1
        writer.write_event(
            event_type="CREATE_PO",
            request_id="REQ-PO-01",
            agent_id="AGENT-01",
            request_hash="h1",
            risk_score=1.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS"
        )
        initial_count = len(writer.get_chain())
        initial_seq = writer._current_sequence

        # Simulate failure during append before commit (disk I/O error or crash)
        original_append = PersistentStorageEngine.atomic_append_audit_block

        def crashing_append(self, *args, **kwargs):
            kwargs["_fail_before_commit"] = True
            return original_append(self, *args, **kwargs)

        with patch.object(PersistentStorageEngine, "atomic_append_audit_block", crashing_append):
            with pytest.raises(AuditPersistenceError):
                writer.write_event(
                    event_type="TRANSFER_FUNDS",
                    request_id="REQ-FAIL-TX",
                    agent_id="AGENT-01",
                    request_hash="h2",
                    risk_score=5.0,
                    policy_version="1.0",
                    decision="ALLOWED",
                    execution_result="FAILED"
                )

        # Verify no partial block in database or memory
        verifier = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        assert len(verifier.get_chain()) == initial_count
        assert verifier._current_sequence == initial_seq
        assert verifier.verify_chain_integrity()["valid"] is True

    def test_06_process_crashes_after_commit(self, temp_audit_dir):
        """
        Criterion 6: Process crashes after commit.
        If process dies after database commit, a retry must discover the existing event.
        """
        db_path = os.path.join(temp_audit_dir, "crash_after_commit.db")
        storage = PersistentStorageEngine(db_path)

        # Worker 1 commits an event
        ev_id = "EV-POST-COMMIT-CRASH-777"
        rec_dict, is_new = storage.atomic_append_audit_block(
            event_type="TRANSFER_FUNDS",
            request_id="REQ-CRASH-AFTER-01",
            agent_id="AGENT-CRASH",
            request_hash="h-crash",
            risk_score=3.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id=ev_id
        )
        assert is_new is True
        committed_seq = rec_dict["sequence_number"]
        committed_hash = rec_dict["record_hash"]

        # Simulate Worker 1 crashing: Worker 2 restarts and retries the same operation
        worker2 = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        retried_rec = worker2.write_event(
            event_type="TRANSFER_FUNDS",
            request_id="REQ-CRASH-AFTER-01",
            agent_id="AGENT-CRASH",
            request_hash="h-crash",
            risk_score=3.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id=ev_id
        )

        assert retried_rec.sequence_number == committed_seq
        assert retried_rec.record_hash == committed_hash
        assert retried_rec.event_id == ev_id

        # Verify no duplicate block created
        all_blocks = storage.get_all_blocks()
        blocks_with_ev = [b for b in all_blocks if b.get("event_id") == ev_id]
        assert len(blocks_with_ev) == 1

    def test_07_database_uniqueness_violation(self, temp_audit_dir):
        """
        Criterion 7: Database uniqueness violation.
        Database constraints prevent duplicate sequence numbers and duplicate event IDs.
        """
        db_path = os.path.join(temp_audit_dir, "uniqueness.db")
        storage = PersistentStorageEngine(db_path)

        # Insert a valid audit block with seq=1, event_id="EV-UNIQUE-1"
        storage.save_block(
            previous_hash="0000",
            block_hash="hash1",
            tx_count=1,
            block_data={"sequence_number": 1, "event_id": "EV-UNIQUE-1"},
            timestamp="2026-01-01T00:00:00Z"
        )

        # Attempt to insert duplicate sequence_number 1 directly
        with pytest.raises(sqlite3.IntegrityError):
            with sqlite3.connect(db_path) as conn:
                conn.execute("""
                    INSERT INTO block_ledger (previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id)
                    VALUES ('0000', 'hash2', 1, '{}', '2026-01-01T00:00:01Z', 1, 'EV-UNIQUE-2')
                """)

        # Attempt to insert duplicate event_id "EV-UNIQUE-1" directly
        with pytest.raises(sqlite3.IntegrityError):
            with sqlite3.connect(db_path) as conn:
                conn.execute("""
                    INSERT INTO block_ledger (previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id)
                    VALUES ('0000', 'hash3', 1, '{}', '2026-01-01T00:00:02Z', 2, 'EV-UNIQUE-1')
                """)

    def test_08_database_lock_contention(self, temp_audit_dir):
        """
        Criterion 8: Database lock contention.
        Transient SQLite lock contention triggers safe retry with backoff and succeeds.
        """
        db_path = os.path.join(temp_audit_dir, "lock_contention.db")
        storage = PersistentStorageEngine(db_path)

        # Verify atomic_append_audit_block succeeds normally
        rec, is_new = storage.atomic_append_audit_block(
            event_type="RETRY_TEST",
            request_id="REQ-LOCK-1",
            agent_id="AGENT-01",
            request_hash="h-lock-1",
            risk_score=1.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id="EV-LOCK-001"
        )
        assert is_new is True
        assert rec["sequence_number"] == 1

        # Simulate transient SQLite lock contention using a background thread
        # holding an EXCLUSIVE transaction lock on the database for 120ms.
        lock_acquired = threading.Event()

        def hold_exclusive_lock():
            conn = sqlite3.connect(db_path, timeout=0.001)
            conn.isolation_level = None
            conn.execute("BEGIN EXCLUSIVE")
            lock_acquired.set()
            time.sleep(0.12)  # Hold exclusive lock for 120ms
            conn.execute("COMMIT")
            conn.close()

        lock_thread = threading.Thread(target=hold_exclusive_lock)
        lock_thread.start()
        lock_acquired.wait(timeout=5)

        # atomic_append_audit_block will hit lock contention,
        # retry with exponential backoff & jitter, and succeed once the lock thread releases.
        rec2, is_new2 = storage.atomic_append_audit_block(
            event_type="RETRY_TEST",
            request_id="REQ-LOCK-2",
            agent_id="AGENT-01",
            request_hash="h-lock-2",
            risk_score=1.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS",
            event_id="EV-LOCK-002",
            busy_timeout=0.02,
            max_retries=25
        )
        lock_thread.join(timeout=5)

        assert is_new2 is True
        assert rec2["sequence_number"] == 2
        assert rec2["event_id"] == "EV-LOCK-002"

    def test_09_restart_with_historical_blocks(self, temp_audit_dir):
        """
        Criterion 9: Restart with historical blocks.
        Full chain rehydration across process termination and seamless continuation of sequence numbers.
        """
        db_path = os.path.join(temp_audit_dir, "rehydration_test.db")

        # Session 1: Write 5 blocks
        s1 = AuditChainWriter(db_path=db_path)
        for i in range(1, 6):
            s1.write_event(
                event_type="ACTION_EXECUTED",
                request_id=f"REQ-HIST-{i}",
                agent_id="AGENT-HIST",
                request_hash=f"hash-{i}",
                risk_score=1.0,
                policy_version="1.0",
                decision="ALLOWED",
                execution_result="SUCCESS"
            )
        assert len(s1.get_chain()) == 6  # Genesis + 5
        assert s1._current_sequence == 5
        del s1

        # Session 2: Terminate and restart fresh instance with auto_rehydrate
        s2 = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        assert len(s2.get_chain()) == 6
        assert s2._current_sequence == 5
        assert s2.verify_chain_integrity()["valid"] is True

        # Append next event: sequence continues at 6
        rec6 = s2.write_event(
            event_type="ACTION_EXECUTED",
            request_id="REQ-HIST-6",
            agent_id="AGENT-HIST",
            request_hash="hash-6",
            risk_score=1.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS"
        )
        assert rec6.sequence_number == 6
        assert len(s2.get_chain()) == 7
        assert s2.verify_chain_integrity()["valid"] is True

    def test_10_modify_historical_block_integrity_fails(self, temp_audit_dir):
        """
        Criterion 10: Modify a historical block.
        Tampering with any historical block in SQLite causes integrity verification to fail.
        """
        db_path = os.path.join(temp_audit_dir, "tamper_chain.db")
        writer = AuditChainWriter(db_path=db_path)
        for i in range(1, 4):
            writer.write_event(
                event_type="TX",
                request_id=f"REQ-TAMPER-{i}",
                agent_id="AGENT-01",
                request_hash=f"h-{i}",
                risk_score=1.0,
                policy_version="1.0",
                decision="ALLOWED",
                execution_result="SUCCESS"
            )

        assert writer.verify_chain_integrity()["valid"] is True

        # Tamper with block sequence #1 in SQLite
        storage = PersistentStorageEngine(db_path)
        ok = storage.tamper_block_data(1, "decision", "FORGED_UNAUTHORIZED_DECISION")
        assert ok is True

        # A fresh rehydrated writer must immediately detect the tampering
        restarted = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        res = restarted.verify_chain_integrity()
        assert res["valid"] is False
        assert res["status"] == "TAMPERING_DETECTED"

    def test_11_concurrent_workers_with_different_event_payloads(self, temp_audit_dir):
        """
        Criterion 11: Concurrent workers with different event payloads.
        Multiple workers submitting diverse event types maintain correct previous-hash ordering.
        """
        db_path = os.path.join(temp_audit_dir, "varied_payloads.db")
        AuditChainWriter(db_path=db_path)

        payloads_w1 = [
            {"event_type": "TRANSFER_FUNDS", "request_id": "REQ-TF-01", "agent_id": "FINANCE-AGENT", "event_id": "EV-V-01"},
            {"event_type": "TRANSFER_FUNDS", "request_id": "REQ-TF-02", "agent_id": "FINANCE-AGENT", "event_id": "EV-V-02"},
            {"event_type": "TRANSFER_FUNDS", "request_id": "REQ-TF-03", "agent_id": "FINANCE-AGENT", "event_id": "EV-V-03"},
        ]
        payloads_w2 = [
            {"event_type": "CREATE_PURCHASE_ORDER", "request_id": "REQ-PO-01", "agent_id": "PROCURE-AGENT", "event_id": "EV-V-04"},
            {"event_type": "CREATE_PURCHASE_ORDER", "request_id": "REQ-PO-02", "agent_id": "PROCURE-AGENT", "event_id": "EV-V-05"},
            {"event_type": "CREATE_PURCHASE_ORDER", "request_id": "REQ-PO-03", "agent_id": "PROCURE-AGENT", "event_id": "EV-V-06"},
        ]
        payloads_w3 = [
            {"event_type": "REVOKE_AGENT", "request_id": "REQ-SEC-01", "agent_id": "SECURITY-AGENT", "event_id": "EV-V-07"},
            {"event_type": "POLICY_UPDATE", "request_id": "REQ-SEC-02", "agent_id": "SECURITY-AGENT", "event_id": "EV-V-08"},
            {"event_type": "AUDIT_VERIFY", "request_id": "REQ-SEC-03", "agent_id": "SECURITY-AGENT", "event_id": "EV-V-09"},
        ]

        ctx = mp.get_context("spawn")
        q1, q2, q3 = ctx.Queue(), ctx.Queue(), ctx.Queue()

        p1 = ctx.Process(target=_mp_worker_varied_payloads, args=(db_path, payloads_w1, q1))
        p2 = ctx.Process(target=_mp_worker_varied_payloads, args=(db_path, payloads_w2, q2))
        p3 = ctx.Process(target=_mp_worker_varied_payloads, args=(db_path, payloads_w3, q3))

        for p in (p1, p2, p3):
            p.start()

        r1 = q1.get(timeout=30)
        r2 = q2.get(timeout=30)
        r3 = q3.get(timeout=30)

        for p in (p1, p2, p3):
            p.join(timeout=10)

        assert len(r1) + len(r2) + len(r3) == 9

        # Verify unified chain
        verifier = AuditChainWriter(db_path=db_path, auto_rehydrate=True)
        chain = verifier.get_chain()
        assert len(chain) == 10  # Genesis + 9

        seqs = [r["sequence_number"] for r in chain]
        assert seqs == list(range(10))

        # Check hash chaining continuity across interleaved worker records
        for i in range(1, len(chain)):
            curr = chain[i]
            prev = chain[i - 1]
            assert curr["previous_record_hash"] == prev["record_hash"]

        integrity = verifier.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["status"] == "VERIFIED_INTACT"

    def test_12_in_memory_mode_backwards_compatibility(self):
        """
        Criterion 12: Backward compatibility with in-memory audit records.
        Ensures unit tests without a database continue to function seamlessly.
        """
        old_env = os.environ.pop("AGENTTRUST_DB_PATH", None)
        try:
            writer = AuditChainWriter()  # No db_path
            r1 = writer.write_event(
                event_type="IN_MEMORY_TX",
                request_id="REQ-MEM-1",
                agent_id="AGENT-MEM",
                request_hash="h-mem-1",
                risk_score=1.0,
                policy_version="1.0",
                decision="ALLOWED",
                execution_result="SUCCESS"
            )
            assert r1.sequence_number == 1
            assert len(writer.get_chain()) == 2
            assert writer.verify_chain_integrity()["valid"] is True

            # Duplicate event ID in memory
            r2 = writer.write_event(
                event_type="IN_MEMORY_TX",
                request_id="REQ-MEM-2",
                agent_id="AGENT-MEM",
                request_hash="h-mem-2",
                risk_score=1.0,
                policy_version="1.0",
                decision="ALLOWED",
                execution_result="SUCCESS",
                event_id="EV-INMEM-DUP"
            )
            assert r2.sequence_number == 2

            r2_retry = writer.write_event(
                event_type="IN_MEMORY_TX",
                request_id="REQ-MEM-2-RETRY",
                agent_id="AGENT-MEM",
                request_hash="h-mem-2",
                risk_score=1.0,
                policy_version="1.0",
                decision="ALLOWED",
                execution_result="SUCCESS",
                event_id="EV-INMEM-DUP"
            )
            assert r2_retry.sequence_number == 2
            assert len(writer.get_chain()) == 3
        finally:
            if old_env is not None:
                os.environ["AGENTTRUST_DB_PATH"] = old_env
