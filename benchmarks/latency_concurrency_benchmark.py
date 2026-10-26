"""
AgentTrust Gateway Latency & Concurrency Scalability Benchmark.
Evaluates end-to-end Action Gateway latency percentiles (p50, p90, p95, p99),
throughput (requests/second), and error/timeout rates across controlled concurrency levels (1, 10, 25, 50).

Features:
- Machine Configuration & Environment Auto-Detection
- Warm-Up Phase (stabilizes disk cache & JIT overhead before recording)
- Dedicated Isolated SQLite Test Fixtures (never touches demo or production DBs)
- Fast Deterministic CI Smoke Mode (--smoke flag)
- Machine-Readable JSON Export (benchmarks/results/latency_results.json)

Usage:
    # Full research load test (concurrency 1, 10, 25, 50):
    python benchmarks/latency_concurrency_benchmark.py

    # Deterministic CI smoke test:
    python benchmarks/latency_concurrency_benchmark.py --smoke
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    import psutil  # type: ignore[import-untyped]
except ImportError:
    psutil = None

from action_gateway.gateway import ActionGateway
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker


def get_machine_specs() -> dict[str, Any]:
    """Inspects and returns underlying hardware and environment specs."""
    cores_logical = os.cpu_count() or 1
    cores_physical = None
    ram_gb = None
    if psutil:
        try:
            cores_physical = psutil.cpu_count(logical=False)
            ram_gb = round(psutil.virtual_memory().total / (1024**3), 2)
        except Exception:
            pass

    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_cores": cores_logical,
        "physical_cpu_cores": cores_physical,
        "total_ram_gb": ram_gb,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation()
    }


def compute_latency_percentiles(latencies_ms: list[float]) -> dict[str, float]:
    """Computes exact statistical percentiles from a list of latency measurements."""
    if not latencies_ms:
        return {
            "count": 0.0,
            "mean": 0.0,
            "stddev": 0.0,
            "min": 0.0,
            "max": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0
        }

    sorted_lat = sorted(latencies_ms)
    n = len(sorted_lat)

    def get_percentile(p: float) -> float:
        k = (n - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= n:
            return sorted_lat[-1]
        if f <= 0:
            return sorted_lat[0]
        d0 = sorted_lat[f] * (c - k)
        d1 = sorted_lat[c] * (k - f)
        return d0 + d1

    return {
        "count": float(n),
        "mean": round(statistics.mean(sorted_lat), 3),
        "stddev": round(statistics.stdev(sorted_lat), 3) if n > 1 else 0.0,
        "min": round(min(sorted_lat), 3),
        "max": round(max(sorted_lat), 3),
        "p50": round(get_percentile(50.0), 3),
        "p90": round(get_percentile(90.0), 3),
        "p95": round(get_percentile(95.0), 3),
        "p99": round(get_percentile(99.0), 3)
    }


class LatencyConcurrencyBenchmark:
    """
    Executes controlled concurrency load tests against an isolated ActionGateway instance.
    """

    def __init__(self, temp_dir: str):
        self.temp_dir = temp_dir
        self.db_path = os.path.join(temp_dir, "bench_latency.db")
        self.fencing_path = os.path.join(temp_dir, "bench_fencing.db")

        self.persistent_db = PersistentStorageEngine(db_path=self.db_path)
        self.cert_manager = CertificateManager(db_path=self.db_path)
        self.identity_store = IdentityStore(db_path=self.db_path)
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)
        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.replay_tracker = RequestTracker(300, persistent_db=self.persistent_db)
        self.finance_api = ProtectedFinanceAPI(persistent_db_path=self.fencing_path)
        self.approval_manager = HumanApprovalManager(db_path=self.db_path)
        self.evidence_store = EvidenceStore(db_path=self.db_path)
        self.fabric_client = FabricClient()
        self.chain_writer = AuditChainWriter()

        self.gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=self.replay_tracker,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            chain_writer=self.chain_writer,
            persistent_db=self.persistent_db
        )

        self._agent_keys: dict[str, str] = {}

    def setup_agent(self, agent_id: str) -> str:
        """Registers an agent with certificate and private key, returning private key PEM."""
        if agent_id in self._agent_keys:
            return self._agent_keys[agent_id]

        priv = KeyManager.generate_key_pair(2048)
        pub_pem = KeyManager.public_key_to_pem(priv.public_key())
        priv_pem = KeyManager.private_key_to_pem(priv)

        policy_id = f"POL-{agent_id}"
        policy = PolicyRecord(
            policy_id=policy_id,
            agent_id=agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER"],
            allowed_resource="*",
            maximum_amount=25000.0,
            human_approval_above=10000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0"
        )
        self.policy_loader.save_policy(policy)

        self.registry.register_agent(
            agent_id=agent_id,
            agent_name=f"Agent-{agent_id}",
            owner="BenchOps",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER"],
            policy_id=policy_id,
            public_key_pem=pub_pem
        )

        self._agent_keys[agent_id] = priv_pem
        return priv_pem

    def warm_up(self, num_requests: int = 15) -> None:
        """Pre-heats Python modules, cryptographic curves, and SQLite caches."""
        priv_pem = self.setup_agent("WARMUP-AGENT")
        for i in range(num_requests):
            payload = {
                "request_id": f"REQ-WARMUP-{i:04d}",
                "agent_id": "WARMUP-AGENT",
                "action": "TRANSFER_FUNDS",
                "resource": "BANK_RESERVE_IN",
                "amount": 100.0,
                "currency": "USD",
                "parameters": {"recipient": "AWS", "amount": 100.0},
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                "nonce": f"NONCE-WARMUP-{i:04d}",
                "key_version": 1
            }
            payload["signature"] = SignatureManager.sign_request(payload, priv_pem)
            self.gateway.process_request(payload)

    def benchmark_concurrency_tier(
        self,
        concurrency: int,
        requests_per_worker: int,
        timeout_seconds: float | None = None
    ) -> dict[str, Any]:
        """
        Runs a load test at a specific concurrency level using ThreadPoolExecutor.
        """
        total_requests = concurrency * requests_per_worker
        if timeout_seconds is None:
            timeout_seconds = max(240.0, float(total_requests) * 2.0)

        # Pre-register agents for each worker thread
        worker_agents = []
        for w in range(concurrency):
            ag_id = f"AG-CONC-{concurrency}-W{w:03d}"
            pk = self.setup_agent(ag_id)
            worker_agents.append((ag_id, pk))

        latencies_ms: list[float] = []
        errors = 0
        timeouts = 0
        lock = threading.Lock()

        start_mem_mb = (
            psutil.Process().memory_info().rss / (1024 * 1024) if psutil else 0.0
        )

        t_wall_start = time.perf_counter()

        def worker_task(worker_idx: int) -> None:
            nonlocal errors, timeouts
            ag_id, pk = worker_agents[worker_idx]

            for r in range(requests_per_worker):
                req_id = f"REQ-C{concurrency}-W{worker_idx}-R{r:04d}"
                nonce = f"NONCE-C{concurrency}-W{worker_idx}-R{r:04d}"
                amount = 500.0 + (r * 10.0)

                payload = {
                    "request_id": req_id,
                    "agent_id": ag_id,
                    "action": "TRANSFER_FUNDS",
                    "resource": "BANK_RESERVE_IN",
                    "amount": amount,
                    "currency": "USD",
                    "parameters": {"recipient": "Enterprise SaaS Cloud", "amount": amount},
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                    "nonce": nonce,
                    "key_version": 1
                }
                payload["signature"] = SignatureManager.sign_request(payload, pk)

                t_req_start = time.perf_counter()
                try:
                    res = self.gateway.process_request(payload)
                    t_req_end = time.perf_counter()
                    lat = (t_req_end - t_req_start) * 1000.0

                    with lock:
                        latencies_ms.append(lat)
                        if res.get("decision") != "ALLOWED":
                            errors += 1
                except TimeoutError:
                    with lock:
                        timeouts += 1
                        errors += 1
                except Exception:
                    with lock:
                        errors += 1

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker_task, w) for w in range(concurrency)]
            try:
                for fut in as_completed(futures, timeout=timeout_seconds):
                    try:
                        fut.result()
                    except Exception:
                        with lock:
                            errors += 1
            except TimeoutError:
                with lock:
                    timeouts += (total_requests - len(latencies_ms))
                    errors += (total_requests - len(latencies_ms))

        t_wall_end = time.perf_counter()
        total_wall_time = t_wall_end - t_wall_start
        total_requests = concurrency * requests_per_worker
        successful_requests = len(latencies_ms)
        rps = (successful_requests / total_wall_time) if total_wall_time > 0 else 0.0
        error_rate = (errors / total_requests) if total_requests > 0 else 0.0
        timeout_rate = (timeouts / total_requests) if total_requests > 0 else 0.0

        end_mem_mb = (
            psutil.Process().memory_info().rss / (1024 * 1024) if psutil else 0.0
        )

        stats = compute_latency_percentiles(latencies_ms)

        return {
            "concurrency": concurrency,
            "requests_per_worker": requests_per_worker,
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "errors": errors,
            "timeouts": timeouts,
            "error_rate_pct": round(error_rate * 100, 2),
            "timeout_rate_pct": round(timeout_rate * 100, 2),
            "wall_time_seconds": round(total_wall_time, 3),
            "throughput_rps": round(rps, 2),
            "memory_start_mb": round(start_mem_mb, 2),
            "memory_end_mb": round(end_mem_mb, 2),
            "memory_delta_mb": round(end_mem_mb - start_mem_mb, 2),
            "latency_ms": stats
        }

    def close(self) -> None:
        try:
            self.persistent_db.close()
        except Exception:
            pass


def run_latency_benchmark(
    concurrency_tiers: list[int],
    requests_per_worker: int,
    output_json: str | None = None
) -> dict[str, Any]:
    """Runs complete latency and concurrency evaluation across specified tiers."""
    machine_specs = get_machine_specs()
    temp_dir = tempfile.mkdtemp()
    bench = LatencyConcurrencyBenchmark(temp_dir=temp_dir)

    try:
        # Pre-heat runtime
        bench.warm_up(num_requests=15)

        tier_results: list[dict[str, Any]] = []
        for conc in concurrency_tiers:
            res = bench.benchmark_concurrency_tier(
                concurrency=conc,
                requests_per_worker=requests_per_worker
            )
            tier_results.append(res)

        benchmark_data = {
            "title": "AgentTrust Gateway Latency & Concurrency Evaluation",
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "machine_specs": machine_specs,
            "warm_up_requests": 15,
            "tier_results": tier_results
        }

        if output_json:
            os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(benchmark_data, f, indent=2)

        return benchmark_data
    finally:
        bench.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def print_latency_report(data: dict[str, Any]) -> None:
    """Prints publication-grade terminal report of concurrency and latency scaling."""
    specs = data["machine_specs"]
    tiers = data["tier_results"]

    print("=" * 92)
    print("      AGENTTRUST GATEWAY LATENCY & CONCURRENCY BENCHMARK REPORT")
    print("=" * 92)
    print(f"Host Platform:       {specs['platform']}")
    print(f"Processor:           {specs['processor']} ({specs['logical_cpu_cores']} logical cores)")
    print(f"RAM Installed:       {specs['total_ram_gb']} GB" if specs['total_ram_gb'] else "RAM: N/A")
    print(f"Python Environment:  Python {specs['python_version']} ({specs['python_implementation']})")
    print(f"Warm-Up Condition:   {data['warm_up_requests']} requests executed before measurement")
    print("-" * 92)
    print(f"{'Clients':<9} | {'Reqs':<6} | {'RPS':<8} | {'p50 (ms)':<9} | {'p90 (ms)':<9} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'Err %':<7}")
    print("-" * 92)

    for t in tiers:
        lat = t["latency_ms"]
        print(
            f"{t['concurrency']:<9} | "
            f"{t['total_requests']:<6} | "
            f"{t['throughput_rps']:<8.1f} | "
            f"{lat['p50']:<9.2f} | "
            f"{lat['p90']:<9.2f} | "
            f"{lat['p95']:<9.2f} | "
            f"{lat['p99']:<9.2f} | "
            f"{t['error_rate_pct']:<7.1f}"
        )

    print("=" * 92)
    print("LATENCY PERCENTILE ANALYSIS:")
    p50_single = tiers[0]['latency_ms']['p50'] if tiers else 0.0
    p95_max = max(t['latency_ms']['p95'] for t in tiers) if tiers else 0.0
    rps_max = max(t['throughput_rps'] for t in tiers) if tiers else 0.0
    print(f"  Single-client baseline median latency (p50): {p50_single:.2f} ms")
    print(f"  Peak multi-client 95th percentile latency:   {p95_max:.2f} ms")
    print(f"  Maximum achieved end-to-end throughput:     {rps_max:.1f} req/sec")
    print("=" * 92)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentTrust Gateway Latency Benchmark")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run fast deterministic CI smoke benchmark with 1 and 5 workers"
    )
    args = parser.parse_args()

    results_dir = os.path.join(os.path.dirname(__file__), "results")
    out_file = os.path.join(results_dir, "latency_results.json")

    if args.smoke:
        print("[SMOKE MODE] Running fast CI latency verification...")
        data = run_latency_benchmark(
            concurrency_tiers=[1, 5],
            requests_per_worker=5,
            output_json=out_file
        )
    else:
        print("[FULL BENCHMARK] Running comprehensive concurrency scaling (1, 10, 25, 50)...")
        data = run_latency_benchmark(
            concurrency_tiers=[1, 10, 25, 50],
            requests_per_worker=5,
            output_json=out_file
        )

    print_latency_report(data)
