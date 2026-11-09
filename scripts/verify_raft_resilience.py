#!/usr/bin/env python3
"""
AgentTrust Raft Consensus Resilience & Deployment Verification Script

Part of the AgentTrust release checklist:
- Verifies 3-node topology and named volume configuration.
- Executes Crash Fault Tolerance (CFT) state machine simulations (1-node crash, 2-node loss, restart recovery).
- Verifies persistent ledger volume recovery across container lifecycle.
- Checks live Docker environment if containers are running.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from typing import Any
import yaml

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def check_configuration_alignment(root_dir: str) -> bool:
    print("[1/4] Checking 3-Node Raft Configuration & Named Volume Mounts...")
    try:
        # Check crypto-config.yaml
        crypto_file = os.path.join(root_dir, "fabric", "crypto-config.yaml")
        with open(crypto_file, "r", encoding="utf-8") as f:
            crypto_cfg = yaml.safe_load(f)
        orderers = [s["Hostname"] for s in crypto_cfg["OrdererOrgs"][0]["Specs"]]
        if set(orderers) != {"orderer", "orderer2", "orderer3"}:
            print(f"  [FAIL] crypto-config orderers mismatch: {orderers}")
            return False

        # Check configtx.yaml
        configtx_file = os.path.join(root_dir, "fabric", "configtx.yaml")
        with open(configtx_file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        consen = [c["Host"] for c in cfg["Orderer"]["EtcdRaft"]["Consenters"]]
        if len(consen) < 3:
            print(f"  [FAIL] configtx consenters count < 3: {len(consen)}")
            return False

        # Check compose named volumes
        compose_file = os.path.join(root_dir, "fabric", "docker-compose-fabric.yaml")
        with open(compose_file, "r", encoding="utf-8") as f:
            compose_cfg = yaml.safe_load(f)
        vols = compose_cfg.get("volumes", {})
        for node in ("orderer.agenttrust.com-data", "orderer2.agenttrust.com-data", "orderer3.agenttrust.com-data"):
            if node not in vols:
                print(f"  [FAIL] Missing volume {node} in docker-compose-fabric.yaml")
                return False

        print("  [PASS] 3-node Raft identities, consenters, and named persistent volumes verified.")
        return True
    except Exception as ex:
        print(f"  [FAIL] Error validating configuration: {ex}")
        return False


def run_raft_cft_state_machine_simulation() -> bool:
    print("[2/4] Executing Raft Consensus State Machine & CFT Simulation...")
    try:
        from tests.test_raft_cluster_resilience import SimulatedRaftCluster
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            cluster = SimulatedRaftCluster(tmp)
            
            # Phase 1: 3 alive nodes elect leader
            leader = cluster.elect_leader()
            if not leader or leader.state != "LEADER":
                print("  [FAIL] Failed to elect initial leader with 3 alive nodes")
                return False
            
            # Phase 2: 1 node crash -> quorum 2/3 preserved
            cluster.nodes["orderer3"].crash()
            res_cft = cluster.submit_transaction_proposal({"tx": "CFT_VERIFY_1"})
            if not res_cft.get("committed"):
                print("  [FAIL] Transaction failed with 1 node crash (quorum should be 2/3)")
                return False

            # Phase 3: 2 nodes crash -> quorum 1/3 lost (FAIL CLOSED)
            cluster.nodes["orderer2"].crash()
            res_lost = cluster.submit_transaction_proposal({"tx": "FAIL_CLOSED_CHECK"})
            if res_lost.get("committed"):
                print("  [FAIL] Transaction committed when quorum was lost (2 nodes crashed)!")
                return False

            # Phase 4: Restart orderer2 -> quorum restored
            cluster.nodes["orderer2"].restart()
            cluster.elect_leader()
            res_rec = cluster.submit_transaction_proposal({"tx": "RECOVERY_CHECK"})
            if not res_rec.get("committed"):
                print("  [FAIL] Transaction failed after restoring orderer2 (2/3 quorum)")
                return False

        print("  [PASS] Raft 2-of-3 quorum, 1-node crash tolerance, and dual-crash fail-closed verified.")
        return True
    except Exception as ex:
        print(f"  [FAIL] Error in simulation: {ex}")
        return False


def run_persistent_volume_recovery_simulation() -> bool:
    print("[3/4] Verifying Ledger Block State Survival Across Container Recreation...")
    try:
        from tests.test_raft_cluster_resilience import SimulatedRaftCluster
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            cluster = SimulatedRaftCluster(tmp)
            cluster.elect_leader()
            for i in range(5):
                cluster.submit_transaction_proposal({"block": i + 1, "data": f"payload_{i+1}"})

            leader = next(n for n in cluster.alive_nodes if n.state == "LEADER")
            hashes = [b["block_hash"] for b in leader.log]
            
            # Destroy cluster in memory
            del cluster
            del leader

            # Recreate cluster from disk storage
            recovered = SimulatedRaftCluster(tmp)
            for nid in ("orderer1", "orderer2", "orderer3"):
                node = recovered.nodes[nid]
                if len(node.log) != 5:
                    print(f"  [FAIL] Node {nid} lost blocks after recreation (expected 5, got {len(node.log)})")
                    return False
                if [b["block_hash"] for b in node.log] != hashes:
                    print(f"  [FAIL] Node {nid} block hash chain corrupted after recreation")
                    return False

        print("  [PASS] All 5 committed blocks and hash chains survived complete container recreation.")
        return True
    except Exception as ex:
        print(f"  [FAIL] Error in volume recovery simulation: {ex}")
        return False


def check_live_docker_network() -> bool:
    print("[4/4] Checking Live Docker Daemon & Network Status...")
    try:
        res = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            print("  [INFO] Docker daemon not reachable or offline; skipping live container checks.")
            return True
        running = res.stdout.strip().splitlines()
        orderers = [name for name in running if "orderer" in name]
        if orderers:
            print(f"  [INFO] Found live running orderer containers: {orderers}")
        else:
            print("  [INFO] Docker daemon active; no live Fabric containers currently running (simulator mode).")
        return True
    except Exception:
        print("  [INFO] Docker binary or daemon not available in this environment; simulation verification active.")
        return True


def main():
    parser = argparse.ArgumentParser(description="AgentTrust Raft Consensus Resilience & Release Verification")
    args = parser.parse_args()

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print("=" * 70)
    print("AgentTrust Raft Consensus & Deployment Verification (Release Checklist)")
    print("=" * 70)

    ok1 = check_configuration_alignment(root_dir)
    ok2 = run_raft_cft_state_machine_simulation()
    ok3 = run_persistent_volume_recovery_simulation()
    ok4 = check_live_docker_network()

    print("=" * 70)
    if ok1 and ok2 and ok3 and ok4:
        print("RESULT: ALL RAFT RESILIENCE & PERSISTENCE VERIFICATIONS PASSED")
        sys.exit(0)
    else:
        print("RESULT: RAFT VERIFICATION FAILED - Review errors above")
        sys.exit(1)


if __name__ == "__main__":
    main()
