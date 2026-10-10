"""
Audit Chain, Evidence Store & Merkle Proof Router.
Provides cryptographic evidence lookup, Merkle inclusion proofs, and ledger audit verification.
"""

from typing import Any
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/audit", tags=["Tamper-Evident Audit & Merkle Proofs"])


def get_evidence_store():
    from server import evidence_store
    return evidence_store


def get_chain_writer():
    from server import chain_writer
    return chain_writer


def get_fabric_client():
    from server import fabric_client
    return fabric_client


@router.get("/logs", summary="Get Hashed Local Audit Log Events")
def get_audit_logs(limit: int = Query(50, ge=1, le=500)):
    writer = get_chain_writer()
    chain = writer.get_chain()
    return {"chain": chain[-limit:], "total_blocks": len(chain)}


@router.get("/evidence/{request_id}", summary="Fetch Off-Chain SHA-256 Evidence Payload")
def get_evidence(request_id: str):
    store = get_evidence_store()
    ev = store.get_evidence(request_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence for request '{request_id}' not found.")
    return ev


@router.get("/merkle-proof/{request_id}", summary="Generate Merkle Inclusion Proof for Independent Auditor")
def generate_merkle_proof(request_id: str):
    store = get_evidence_store()
    proof_data = store.generate_merkle_proof(request_id)
    if not proof_data:
        raise HTTPException(status_code=404, detail=f"Merkle inclusion proof for request '{request_id}' could not be generated.")
    return proof_data


@router.get("/ledger/blocks", summary="Fetch Permissioned Ledger Commit History")
def get_ledger_blocks():
    client = get_fabric_client()
    blocks = client.ledger_service.get_blocks()
    return {"blocks": blocks, "total_blocks": len(blocks)}
