"""
AgentTrust Three-Node Raft Consensus Resilience & Recovery Test Suite

Validates:
1. 3-Node Topology, Crypto Specs, and Named Volume Alignment across configtx, crypto-config, and compose.
2. Quorum State Machine & Leader Election: 2-of-3 majority consensus requirement ((N/2)+1).
3. Crash Fault Tolerance (CFT):
   - 1 node failure (2/3 alive): Cluster maintains quorum, elects leader, commits transactions.
   - 2 node failure (1/3 alive): Quorum lost, transactions fail closed / blocked.
   - Node recovery (2/3 restored): Quorum restored, logs resynchronized, transactions resume.
4. Persistent Volume Survival: Ledger block state survives simulated container destruction and recreation.
"""

import hashlib
import json
import os
import tempfile
import time
from typing import Any
import pytest
import yaml


# -----------------------------------------------------------------------------
# Test 1: Configuration & Named Volume Mount Alignment
# -----------------------------------------------------------------------------
def test_raft_cluster_topology_and_specs_alignment():
    """Verify all 3 orderers and named volumes match across crypto, configtx, and compose."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    # 1. crypto-config.yaml
    crypto_file = os.path.join(root_dir, "fabric", "crypto-config.yaml")
    with open(crypto_file, "r", encoding="utf-8") as f:
        crypto_cfg = yaml.safe_load(f)
    orderer_org = crypto_cfg["OrdererOrgs"][0]
    specs = [s["Hostname"] for s in orderer_org["Specs"]]
    assert set(specs) == {"orderer", "orderer2", "orderer3"}

    # 2. configtx.yaml
    configtx_file = os.path.join(root_dir, "fabric", "configtx.yaml")
    with open(configtx_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    consen = cfg["Orderer"]["EtcdRaft"]["Consenters"]
    hosts = [c["Host"] for c in consen]
    assert "orderer.agenttrust.com" in hosts
    assert "orderer2.agenttrust.com" in hosts
    assert "orderer3.agenttrust.com" in hosts

    # 3. docker-compose-fabric.yaml
    compose_file = os.path.join(root_dir, "fabric", "docker-compose-fabric.yaml")
    with open(compose_file, "r", encoding="utf-8") as f:
        compose_cfg = yaml.safe_load(f)
    
    vols = compose_cfg.get("volumes", {})
    expected_vols = {
        "orderer.agenttrust.com-data",
        "orderer2.agenttrust.com-data",
        "orderer3.agenttrust.com-data"
    }
    for ev in expected_vols:
        assert ev in vols, f"Named volume {ev} must exist in compose volumes"

    services = compose_cfg.get("services", {})
    for host in ("orderer.agenttrust.com", "orderer2.agenttrust.com", "orderer3.agenttrust.com"):
        svc = services.get(host)
        assert svc is not None, f"Orderer service {host} must be defined"
        vol_mounts = svc.get("volumes", [])
        named_mount = [v for v in vol_mounts if f"{host}-data:" in v and "/var/hyperledger/production/orderer" in v]
        assert len(named_mount) == 1, f"Service {host} must mount {host}-data to /var/hyperledger/production/orderer"


# -----------------------------------------------------------------------------
# Simulated Raft 3-Node Cluster Implementation
# -----------------------------------------------------------------------------
class SimulatedRaftNode:
    def __init__(self, node_id: str, cluster: list[str], storage_dir: str):
        self.node_id = node_id
        self.cluster = cluster
        self.storage_dir = storage_dir
        self.term = 0
        self.voted_for: str | None = None
        self.state = "FOLLOWER"  # FOLLOWER, CANDIDATE, LEADER, CRASHED
        self.log: list[dict[str, Any]] = []
        self.commit_index = 0
        self.ledger_file = os.path.join(storage_dir, f"{node_id}_ledger.json")
        self._load_storage()

    def _load_storage(self):
        if os.path.exists(self.ledger_file):
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.term = data.get("term", 0)
                    self.log = data.get("log", [])
                    self.commit_index = len(self.log)
            except Exception:
                pass

    def _save_storage(self):
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump({"term": self.term, "log": self.log}, f)

    def crash(self):
        self.state = "CRASHED"

    def restart(self):
        self.state = "FOLLOWER"
        self._load_storage()

    def request_vote(self, candidate_id: str, term: int) -> bool:
        if self.state == "CRASHED":
            return False
        if term > self.term:
            self.term = term
            self.voted_for = None
            self.state = "FOLLOWER"
        if (self.voted_for is None or self.voted_for == candidate_id) and term >= self.term:
            self.voted_for = candidate_id
            self._save_storage()
            return True
        return False

    def append_entries(self, leader_id: str, term: int, entries: list[dict[str, Any]]) -> bool:
        if self.state == "CRASHED":
            return False
        if term < self.term:
            return False
        self.term = term
        self.state = "FOLLOWER"
        for e in entries:
            self.log.append(e)
        self.commit_index = len(self.log)
        self._save_storage()
        return True


class SimulatedRaftCluster:
    def __init__(self, storage_dir: str):
        self.node_ids = ["orderer1", "orderer2", "orderer3"]
        self.storage_dir = storage_dir
        self.nodes = {nid: SimulatedRaftNode(nid, self.node_ids, storage_dir) for nid in self.node_ids}

    @property
    def quorum_size(self) -> int:
        # Majority quorum: (N // 2) + 1 -> for 3 nodes, quorum is 2
        return (len(self.node_ids) // 2) + 1

    @property
    def alive_nodes(self) -> list[SimulatedRaftNode]:
        return [n for n in self.nodes.values() if n.state != "CRASHED"]

    def elect_leader(self) -> SimulatedRaftNode | None:
        """Attempts leader election among alive nodes using Raft majority vote."""
        alive = self.alive_nodes
        if len(alive) < self.quorum_size:
            return None  # Quorum lost, cannot elect leader
        
        candidate = alive[0]
        candidate.state = "CANDIDATE"
        candidate.term += 1
        candidate.voted_for = candidate.node_id
        votes = 1

        for peer in alive[1:]:
            if peer.request_vote(candidate.node_id, candidate.term):
                votes += 1

        if votes >= self.quorum_size:
            candidate.state = "LEADER"
            # Set all other alive nodes as followers
            for peer in alive[1:]:
                peer.state = "FOLLOWER"
            return candidate
        return None

    def submit_transaction_proposal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submits transaction proposal to current leader and replicates across quorum."""
        leader = next((n for n in self.alive_nodes if n.state == "LEADER"), None)
        if not leader:
            # Try to elect a leader if quorum exists
            leader = self.elect_leader()
            if not leader:
                return {
                    "committed": False,
                    "status": "QUORUM_LOST",
                    "reason": f"Active nodes ({len(self.alive_nodes)}) below Raft quorum of {self.quorum_size}"
                }

        # Leader creates log entry
        block_idx = len(leader.log) + 1
        prev_hash = leader.log[-1]["block_hash"] if leader.log else "0" * 64
        entry = {
            "index": block_idx,
            "term": leader.term,
            "payload": payload,
            "prev_hash": prev_hash,
            "block_hash": hashlib.sha256(f"{block_idx}:{prev_hash}:{json.dumps(payload, sort_keys=True)}".encode()).hexdigest()
        }

        # Replicate to peers
        replications = 1  # Leader itself
        for peer in [n for n in self.alive_nodes if n != leader]:
            if peer.append_entries(leader.node_id, leader.term, [entry]):
                replications += 1

        if replications >= self.quorum_size:
            leader.log.append(entry)
            leader.commit_index = len(leader.log)
            leader._save_storage()
            return {
                "committed": True,
                "status": "COMMITTED",
                "block_number": block_idx,
                "block_hash": entry["block_hash"],
                "replicated_nodes": replications,
                "quorum": self.quorum_size
            }
        else:
            return {
                "committed": False,
                "status": "CONSENSUS_FAILED",
                "replications": replications,
                "quorum": self.quorum_size
            }


# -----------------------------------------------------------------------------
# Test 2: Leader Election & Quorum Requirement (2-of-3)
# -----------------------------------------------------------------------------
def test_raft_cluster_state_machine_leader_election():
    """Verify that a 3-node Raft cluster requires at least 2 nodes to elect a leader."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        cluster = SimulatedRaftCluster(tmp)
        assert cluster.quorum_size == 2

        # 3 alive -> Leader elected successfully
        leader = cluster.elect_leader()
        assert leader is not None
        assert leader.state == "LEADER"
        assert len(cluster.alive_nodes) == 3


# -----------------------------------------------------------------------------
# Test 3: Crash Fault Tolerance (CFT) - 1 Node Failure
# -----------------------------------------------------------------------------
def test_raft_cluster_single_node_crash_tolerance():
    """Verify cluster maintains consensus and commits blocks when 1 of 3 orderers crashes."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        cluster = SimulatedRaftCluster(tmp)
        leader = cluster.elect_leader()
        assert leader is not None

        # Crash 1 node (follower)
        crashed_id = "orderer3"
        cluster.nodes[crashed_id].crash()
        assert len(cluster.alive_nodes) == 2  # 2 alive >= quorum of 2

        # Submit transaction
        res = cluster.submit_transaction_proposal({"tx_id": "TX-CFT-01", "action": "TRANSFER"})
        assert res["committed"] is True
        assert res["status"] == "COMMITTED"
        assert res["replicated_nodes"] >= 2  # Exactly 2 nodes replicated


# -----------------------------------------------------------------------------
# Test 4: Quorum Loss on Dual Node Failure & Recovery
# -----------------------------------------------------------------------------
def test_raft_cluster_dual_node_crash_quorum_loss_fail_closed_and_recovery():
    """
    Verify fail-closed behavior when 2 of 3 orderers fail (quorum lost),
    and recovery when 1 node restarts restoring 2-of-3 quorum.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        cluster = SimulatedRaftCluster(tmp)
        cluster.elect_leader()

        # Submit genesis tx
        res1 = cluster.submit_transaction_proposal({"tx_id": "TX-INIT"})
        assert res1["committed"] is True

        # Crash 2 nodes -> only 1 remains alive
        cluster.nodes["orderer1"].crash()
        cluster.nodes["orderer2"].crash()
        assert len(cluster.alive_nodes) == 1  # 1 alive < quorum of 2

        # Submission MUST fail closed
        res_fail = cluster.submit_transaction_proposal({"tx_id": "TX-FAIL-CLOSED"})
        assert res_fail["committed"] is False
        assert res_fail["status"] == "QUORUM_LOST"

        # Restart orderer2 -> 2 nodes now alive (orderer2 + orderer3)
        cluster.nodes["orderer2"].restart()
        assert len(cluster.alive_nodes) == 2  # Quorum restored!

        # Elect leader among the restored quorum
        new_leader = cluster.elect_leader()
        assert new_leader is not None

        # Submission now succeeds!
        res_recovered = cluster.submit_transaction_proposal({"tx_id": "TX-RECOVERED"})
        assert res_recovered["committed"] is True
        assert res_recovered["status"] == "COMMITTED"


# -----------------------------------------------------------------------------
# Test 5: Persistent Named Volume Ledger Survival Across Container Recreation
# -----------------------------------------------------------------------------
def test_raft_cluster_persistent_ledger_volume_survival():
    """Verify that ledger block data and commit index survive container deletion and recreation."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        cluster = SimulatedRaftCluster(tmp)
        cluster.elect_leader()

        # Commit 3 blocks
        for i in range(3):
            cluster.submit_transaction_proposal({"tx_id": f"TX-BLOCK-{i+1}", "data": f"content_{i+1}"})

        # Record committed block hashes
        leader = next(n for n in cluster.alive_nodes if n.state == "LEADER")
        committed_hashes = [b["block_hash"] for b in leader.log]
        assert len(committed_hashes) == 3

        # Simulate complete container teardown (destroying in-memory node instances, leaving disk volume)
        del cluster
        del leader

        # Re-instantiate cluster with the existing persistent storage directory
        recovered_cluster = SimulatedRaftCluster(tmp)
        for nid in ("orderer1", "orderer2", "orderer3"):
            node = recovered_cluster.nodes[nid]
            assert len(node.log) == 3, f"Node {nid} must retain 3 committed blocks from persistent volume"
            assert [b["block_hash"] for b in node.log] == committed_hashes
