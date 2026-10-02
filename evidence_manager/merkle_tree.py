"""
Merkle Tree Computation Module for AgentTrust Framework.
Calculates Merkle Root over block transactions and generates cryptographic inclusion proofs.
"""

import hashlib


class MerkleTree:
    """
    Computes binary Merkle tree over evidence transaction hashes and produces inclusion proofs.
    """

    def __init__(self, hashes: list[str]):
        self.leaves = [h.lower() for h in hashes] if hashes else [hashlib.sha256(b"EMPTY_BLOCK").hexdigest()]
        self.tree = self._build_tree(self.leaves)

    def _hash_pair(self, left: str, right: str) -> str:
        return hashlib.sha256(f"{left}:{right}".encode()).hexdigest()

    def _build_tree(self, leaves: list[str]) -> list[list[str]]:
        tree = [leaves]
        current_layer = leaves
        while len(current_layer) > 1:
            if len(current_layer) % 2 != 0:
                current_layer.append(current_layer[-1]) # Duplicate last element if odd count

            next_layer = []
            for i in range(0, len(current_layer), 2):
                next_layer.append(self._hash_pair(current_layer[i], current_layer[i+1]))
            tree.append(next_layer)
            current_layer = next_layer
        return tree

    def get_root(self) -> str:
        """Returns hex Merkle root hash string."""
        return self.tree[-1][0]

    def get_inclusion_proof(self, leaf_hash: str) -> list[dict[str, str]] | None:
        """
        Generates Merkle audit inclusion proof for a target leaf hash.
        Returns list of proof steps: [{"position": "right"/"left", "hash": "..."}]
        """
        target = leaf_hash.lower()
        if target not in self.leaves:
            return None

        index = self.leaves.index(target)
        proof = []

        for layer in self.tree[:-1]:
            is_right = (index % 2 == 1)
            sibling_index = index - 1 if is_right else index + 1
            if sibling_index < len(layer):
                proof.append({
                    "position": "left" if is_right else "right",
                    "hash": layer[sibling_index]
                })
            else:
                proof.append({
                    "position": "right",
                    "hash": layer[index]
                })
            index = index // 2

        return proof

    @staticmethod
    def verify_inclusion_proof(leaf_hash: str, proof: list[dict[str, str]], expected_root: str) -> bool:
        """
        Verifies a Merkle inclusion proof independently.
        """
        current_hash = leaf_hash.lower()
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "left":
                current_hash = hashlib.sha256(f"{sibling}:{current_hash}".encode()).hexdigest()
            else:
                current_hash = hashlib.sha256(f"{current_hash}:{sibling}".encode()).hexdigest()
        return current_hash.lower() == expected_root.lower()
