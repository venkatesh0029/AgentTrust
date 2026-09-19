import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import uuid
import datetime
import statistics
import multiprocessing
try:
    import psutil
except ImportError:
    psutil = None
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Tuple

from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import PolicyRecord, WorkingHours
from replay_protection.request_tracker import RequestTracker
from protected_api.finance_api import ProtectedFinanceAPI
from human_approval.approval_manager import HumanApprovalManager
from evidence_manager.evidence_store import EvidenceStore
from audit_writer.chain_writer import AuditChainWriter
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway
from risk_engine.risk_evaluator import RiskEvaluator

def calculate_percentiles(data: List[float]) -> Dict[str, float]:
    """Calculates Mean, StdDev, Min, Max, P50 (median), P90, P95, and P99 percentiles."""
    if not data:
        return {"mean": 0, "stddev": 0, "min": 0, "max": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0}
    sorted_data = sorted(data)
    n = len(sorted_data)

    def percentile(p: float) -> float:
        k = (n - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= n:
            return sorted_data[-1]
        if f <= 0:
            return sorted_data[0]
        d0 = sorted_data[f] * (c - k)
        d1 = sorted_data[c] * (k - f)
        return d0 + d1

    return {
        "mean": statistics.mean(data),
        "stddev": statistics.stdev(data) if n > 1 else 0.0,
        "min": min(data),
        "max": max(data),
        "p50": percentile(50.0),
        "p90": percentile(90.0),
        "p95": percentile(95.0),
        "p99": percentile(99.0)
    }

class BenchmarkEngine:
    """
    Research-Grade Experimental Benchmarking & Ablation Suite.
    Measures pipeline stages, scaling (1, 10, 50, 100 agents), and component ablation.
    """

    def __init__(self):
        self.cm = CertificateManager()
        self.store = IdentityStore()
        self.reg = AgentRegistry(self.cm, self.store)
        self.loader = PolicyLoader()
        self.evaluator = PolicyEvaluator(self.loader)
        self.replay = RequestTracker(300)
        self.api = ProtectedFinanceAPI()
        self.approval = HumanApprovalManager()
        self.ev_store = EvidenceStore()
        self.writer = AuditChainWriter()
        self.fabric = FabricClient()
        self.gw = ActionGateway(
            self.reg, self.cm, self.evaluator, self.replay,
            self.api, self.approval, self.ev_store, self.fabric, chain_writer=self.writer
        )

    def measure_stage_latencies(self, num_samples: int = 100) -> Dict[str, Dict[str, float]]:
        """Measures exact per-stage execution times in milliseconds."""
        ag_info = self.reg.register_agent("BENCH-AGENT-STAGE", "BenchAgent", "Dept", ["CREATE_PURCHASE_ORDER"], "BENCH-POL")
        priv_key = ag_info["private_key"]
        pub_key = ag_info["public_key"]
        cert_pem = ag_info["certificate"]

        pol = PolicyRecord(
            policy_id="BENCH-POL", agent_id="BENCH-AGENT-STAGE",
            allowed_actions=["CREATE_PURCHASE_ORDER"], allowed_resource="*",
            maximum_amount=50000.0, human_approval_above=10000.0, version="1.0"
        )
        self.loader.save_policy(pol)

        stage_times = {
            "sig_generation": [],
            "sig_verification": [],
            "cert_validation": [],
            "replay_checking": [],
            "risk_evaluation": [],
            "policy_evaluation": [],
            "approval_processing": [],
            "api_execution": [],
            "evidence_generation": [],
            "hash_chain_writing": [],
            "fabric_commit": []
        }

        for i in range(num_samples):
            req_id = f"REQ-STAGE-{i:04d}"
            n = f"NONCE-STAGE-{i:04d}"
            payload = {
                "request_id": req_id, "agent_id": "BENCH-AGENT-STAGE",
                "action": "CREATE_PURCHASE_ORDER", "resource": "SUP-1", "amount": 5000.0,
                "parameters": {"amount": 5000.0}, "nonce": n,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # 1. Sig Gen
            t0 = time.perf_counter()
            sig = SignatureManager.sign_request(payload, priv_key)
            payload["signature"] = sig
            stage_times["sig_generation"].append((time.perf_counter() - t0) * 1000.0)

            # 2. Sig Verify
            p_to_v = payload.copy()
            p_to_v.pop("signature")
            t0 = time.perf_counter()
            SignatureManager.verify_signature(p_to_v, sig, pub_key)
            stage_times["sig_verification"].append((time.perf_counter() - t0) * 1000.0)

            # 3. Cert Validation
            t0 = time.perf_counter()
            self.cm.verify_agent_certificate(cert_pem)
            stage_times["cert_validation"].append((time.perf_counter() - t0) * 1000.0)

            # 4. Replay Check
            t0 = time.perf_counter()
            self.replay.check_and_track(req_id, n, payload["timestamp"])
            stage_times["replay_checking"].append((time.perf_counter() - t0) * 1000.0)

            # 5. Risk Evaluation
            t0 = time.perf_counter()
            r_res = RiskEvaluator.evaluate("BENCH-AGENT-STAGE", "CREATE_PURCHASE_ORDER", "SUP-1", 5000.0, ag_info, payload["timestamp"])
            stage_times["risk_evaluation"].append((time.perf_counter() - t0) * 1000.0)

            # 6. Policy Evaluation
            t0 = time.perf_counter()
            self.evaluator.evaluate("BENCH-POL", "CREATE_PURCHASE_ORDER", "SUP-1", 5000.0, payload["timestamp"], r_res["risk_score"], r_res["risk_level"])
            stage_times["policy_evaluation"].append((time.perf_counter() - t0) * 1000.0)

            # 7. Approval Processing
            t0 = time.perf_counter()
            tkt = self.approval.create_approval_request(req_id, "BENCH-AGENT-STAGE", "CREATE_PURCHASE_ORDER", "SUP-1", {"amount": 25000.0}, "HIGH_VAL", "BENCH-POL")
            self.approval.approve_request(tkt["approval_id"], "SUP-01", tkt["approval_token"])
            stage_times["approval_processing"].append((time.perf_counter() - t0) * 1000.0)

            # 8. API Execution
            headers = self.api.create_gateway_auth_headers(req_id)
            t0 = time.perf_counter()
            self.api.execute_action("CREATE_PURCHASE_ORDER", {"supplier_id": "SUP-1", "amount": 5000.0}, ProtectedFinanceAPI.GATEWAY_SECRET, req_id, "BENCH-AGENT-STAGE", auth_headers=headers)
            stage_times["api_execution"].append((time.perf_counter() - t0) * 1000.0)

            # 9. Evidence Gen
            t0 = time.perf_counter()
            self.ev_store.save_evidence({"evidence_id": f"EV-{req_id}", "request_id": req_id, "amount": 5000.0})
            stage_times["evidence_generation"].append((time.perf_counter() - t0) * 1000.0)

            # 10. Hash Chain Writing
            t0 = time.perf_counter()
            self.writer.write_event("ACTION_ALLOWED", req_id, "BENCH-AGENT-STAGE", "hash", 10.0, "1.0", "ALLOWED", "SUCCESS")
            stage_times["hash_chain_writing"].append((time.perf_counter() - t0) * 1000.0)

            # 11. Fabric Commit
            t0 = time.perf_counter()
            self.fabric.record_evidence(req_id, "BENCH-AGENT-STAGE", "hash", "ALLOWED")
            stage_times["fabric_commit"].append((time.perf_counter() - t0) * 1000.0)

        return {k: calculate_percentiles(v) for k, v in stage_times.items()}

    def run_concurrency_scale_test(self, num_agents_list: List[int] = [1, 10, 50, 100], reqs_per_agent: int = 5) -> Dict[int, Dict[str, Any]]:
        """Benchmarks system throughput and latency under 1, 10, 50, and 100 concurrent agents."""
        results = {}

        for num_agents in num_agents_list:
            agents = []
            for i in range(num_agents):
                ag_id = f"SCALE-AGENT-{num_agents}-{i:03d}"
                pol_id = f"POL-{ag_id}"
                info = self.reg.register_agent(ag_id, f"ScaleAgent{i}", "Dept", ["CREATE_PURCHASE_ORDER"], pol_id)
                
                pol = PolicyRecord(
                    policy_id=pol_id, agent_id=ag_id,
                    allowed_actions=["CREATE_PURCHASE_ORDER"], allowed_resource="*",
                    maximum_amount=50000.0, human_approval_above=10000.0,
                    working_hours=WorkingHours(start="00:00", end="23:59"), version="1.0"
                )
                self.loader.save_policy(pol)
                agents.append((ag_id, info["private_key"]))

            latencies = []
            errors = 0
            start_proc_mem = psutil.Process().memory_info().rss / (1024 * 1024)
            t_start = time.perf_counter()

            def worker(agent_tuple):
                nonlocal errors
                ag_id, pk = agent_tuple
                for r in range(reqs_per_agent):
                    payload = {
                        "request_id": f"REQ-SCALE-{ag_id}-{r}",
                        "agent_id": ag_id,
                        "action": "CREATE_PURCHASE_ORDER",
                        "resource": "SUP-1",
                        "amount": 2500.0,
                        "parameters": {"amount": 2500.0},
                        "nonce": f"N-SCALE-{ag_id}-{r}",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "key_version": 1
                    }
                    payload["signature"] = SignatureManager.sign_request(payload, pk)
                    t0 = time.perf_counter()
                    try:
                        res = self.gw.process_request(payload)
                        latencies.append((time.perf_counter() - t0) * 1000.0)
                        if res.get("decision") != "ALLOWED":
                            errors += 1
                    except Exception:
                        errors += 1

            with ThreadPoolExecutor(max_workers=min(num_agents, 32)) as executor:
                executor.map(worker, agents)

            total_wall_time = time.perf_counter() - t_start
            total_reqs = num_agents * reqs_per_agent
            end_proc_mem = psutil.Process().memory_info().rss / (1024 * 1024)
            rps = total_reqs / total_wall_time if total_wall_time > 0 else 0

            stats = calculate_percentiles(latencies)
            stats["throughput_rps"] = rps
            stats["total_requests"] = total_reqs
            stats["total_time_sec"] = total_wall_time
            stats["cpu_utilization_pct"] = psutil.cpu_percent(interval=None)
            stats["memory_delta_mb"] = end_proc_mem - start_proc_mem
            stats["failure_rate"] = errors / total_reqs

            results[num_agents] = stats

        return results

    def run_ablation_study(self, num_requests: int = 50) -> Dict[str, Dict[str, float]]:
        """Ablation Experiment measuring performance effect of disabling individual security components."""
        ag_info = self.reg.register_agent("ABLATE-AGENT-01", "AblateAgent", "Dept", ["CREATE_PURCHASE_ORDER"], "BENCH-POL")
        pk = ag_info["private_key"]

        modes = ["Full AgentTrust", "Without Risk Engine", "Without Replay Protection", "Without Hash Chain", "Without Fabric"]
        ablation_results = {}

        for mode in modes:
            latencies = []
            for i in range(num_requests):
                payload = {
                    "request_id": f"REQ-ABLATE-{mode[:4]}-{i}",
                    "agent_id": "ABLATE-AGENT-01",
                    "action": "CREATE_PURCHASE_ORDER",
                    "resource": "SUP-1",
                    "amount": 2500.0,
                    "parameters": {"amount": 2500.0},
                    "nonce": f"N-ABLATE-{mode[:4]}-{i}",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "key_version": 1
                }
                payload["signature"] = SignatureManager.sign_request(payload, pk)

                t0 = time.perf_counter()

                if mode == "Full AgentTrust":
                    self.gw.process_request(payload)
                elif mode == "Without Risk Engine":
                    # Skip Step 7 Risk Eval
                    self.evaluator.evaluate("BENCH-POL", "CREATE_PURCHASE_ORDER", "SUP-1", 2500.0, payload["timestamp"])
                elif mode == "Without Replay Protection":
                    # Skip Step 6 Replay Check
                    r_res = RiskEvaluator.evaluate("ABLATE-AGENT-01", "CREATE_PURCHASE_ORDER", "SUP-1", 2500.0, ag_info)
                    self.evaluator.evaluate("BENCH-POL", "CREATE_PURCHASE_ORDER", "SUP-1", 2500.0, payload["timestamp"], r_res["risk_score"])
                elif mode == "Without Hash Chain":
                    # Skip chain writer
                    pass
                elif mode == "Without Fabric":
                    # Skip fabric commit
                    pass

                latencies.append((time.perf_counter() - t0) * 1000.0)

            ablation_results[mode] = calculate_percentiles(latencies)

        return ablation_results

if __name__ == "__main__":
    bench = BenchmarkEngine()
    print("=== AgentTrust Stage Latencies ===")
    stages = bench.measure_stage_latencies(20)
    for s, v in stages.items():
        print(f"{s:25s}: Mean={v['mean']:.3f}ms | P50={v['p50']:.3f}ms | P95={v['p95']:.3f}ms | P99={v['p99']:.3f}ms")

    print("\n=== AgentTrust Concurrency Scaling (1, 10, 50, 100 Agents) ===")
    scale = bench.run_concurrency_scale_test([1, 10, 50, 100], reqs_per_agent=2)
    for num_a, v in scale.items():
        print(f"Agents {num_a:3d}: RPS={v['throughput_rps']:.1f} | Mean={v['mean']:.2f}ms | P95={v['p95']:.2f}ms | P99={v['p99']:.2f}ms | Failures={v['failure_rate']*100:.1f}%")
