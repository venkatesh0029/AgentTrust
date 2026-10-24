import urllib.request
import json
import time
import datetime

BASE_URL = "http://127.0.0.1:8000"

def get(path, headers=None):
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def post(path, data=None, headers=None):
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    encoded = json.dumps(data).encode() if data is not None else b""
    req = urllib.request.Request(f"{BASE_URL}{path}", data=encoded, headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def test_checklist():
    results = {}

    print("=" * 60)
    print("STEP 17: END-TO-END DEMO VERIFICATION")
    print("=" * 60)

    # 1. Dashboard and Ledger
    print("\n--- 1. Dashboard and Ledger ---")
    st, chain_status = get("/audit/chain/verify")
    print(f"Audit chain verify status: {st}, result: {chain_status.get('status')}")
    st_blocks, blocks_data = get("/audit/blockchain/blocks")
    print(f"Blockchain blocks count: {len(blocks_data.get('blocks', []))}")
    assert st == 200 and chain_status.get("valid") is True
    results["1. Dashboard and Ledger"] = "VERIFIED"

    # 2. Agent registration and policies
    print("\n--- 2. Agent registration and policies ---")
    # Unauthorized test
    unauth_st, _ = post("/agents/register", {
        "agent_id": "TEST-UNAUTH-01",
        "agent_name": "UnauthAgent",
        "owner": "Finance",
        "organization": "OrgA",
        "role": "finance_agent",
        "policy_id": "FIN-POL-001"
    })
    print(f"Unauthenticated agent registration rejected with status: {unauth_st}")
    assert unauth_st in (401, 403)

    # Authorized test
    auth_st, reg_data = post("/agents/register", {
        "agent_id": "E2E-AGENT-999",
        "agent_name": "E2E Verification Agent",
        "owner": "Enterprise User",
        "organization": "FinanceOrg",
        "role": "finance_agent",
        "policy_id": "FIN-POLICY-001",
        "agent_version": "1.0",
        "capabilities": ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS"]
    }, headers={"X-Admin-Role": "SYSTEM_ADMIN"})
    print(f"Authorized agent registration status: {auth_st}, agent: {reg_data.get('agent', {}).get('agent_id')}")
    assert auth_st == 200

    # Policy creation
    pol_st, pol_data = post("/policies", {
        "policy_id": "E2E-POL-999",
        "agent_id": "E2E-AGENT-999",
        "allowed_actions": ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS"],
        "allowed_resource": "*",
        "maximum_amount": 100000.0,
        "human_approval_above": 10000.0,
        "working_hours_start": "00:00",
        "working_hours_end": "23:59",
        "version": "1.0"
    }, headers={"X-Admin-Role": "POLICY_ADMIN"})
    print(f"Policy creation status: {pol_st}, policy: {pol_data.get('policy', {}).get('policy_id')}")
    assert pol_st == 200
    results["2. Agent registration and policies"] = "VERIFIED"

    # 3. Gateway and evidence
    print("\n--- 3. Gateway and evidence ---")
    gw_st, gw_data = post("/actions/submit", {
        "request_id": f"REQ-E2E-{int(time.time())}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "SUPPLIER-TECH-01",
        "amount": 2500.0,
        "parameters": {"item": "Server", "quantity": 1, "total_amount": 2500.0},
        "nonce": f"N-E2E-{int(time.time())}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "signature": "AUTO_SIGN"
    })
    req_id = gw_data.get("request_id")
    print(f"Gateway submission: {gw_st}, decision: {gw_data.get('decision')}, request_id: {req_id}")
    assert gw_st == 200 and gw_data.get("decision") == "ALLOWED"

    if req_id:
        prov_st, prov_data = get(f"/evidence/provenance/{req_id}")
        print(f"Provenance fetch status: {prov_st}, root_agent: {prov_data.get('provenance', {}).get('root_agent_id')}")
        assert prov_st == 200

        merkle_st, merkle_data = get(f"/audit/merkle-proof/{req_id}")
        print(f"Merkle proof fetch status: {merkle_st}, has proof: {'proof' in merkle_data}")
        assert merkle_st == 200
    results["3. Gateway and evidence"] = "VERIFIED"

    # 4. Identity and delegation
    print("\n--- 4. Identity and delegation ---")
    cert_st, certs = get("/identity/certificates")
    print(f"Certificates list status: {cert_st}, count: {len(certs.get('certificates', []))}")
    assert cert_st == 200

    del_st, del_data = post("/identity/delegation/issue", {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "PROCUREMENT-AGENT-002",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 50000.0,
        "ttl_seconds": 3600
    }, headers={"X-Admin-Role": "SYSTEM_ADMIN"})
    print(f"Delegation token issuance status: {del_st}, token_id: {del_data.get('token_id')}")
    assert del_st == 200

    # Test unauthorized delegation (bad role)
    bad_del_st, _ = post("/identity/delegation/issue", {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "PROCUREMENT-AGENT-002",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 50000.0,
        "ttl_seconds": 3600
    }, headers={"X-Admin-Role": "AUDITOR"})
    print(f"Auditor delegation attempt rejected with status: {bad_del_st}")
    assert bad_del_st in (401, 403)
    results["4. Identity and delegation"] = "VERIFIED"

    # 5. Benchmarks
    print("\n--- 5. Benchmarks ---")
    bm_st, bm_data = post("/benchmark/run")
    bm_results = bm_data.get('benchmark_results') or bm_data.get('ablation_study', {})
    print(f"Benchmark run status: {bm_st}, modes measured: {list(bm_results.keys())}")
    assert bm_st == 200
    results["5. Benchmarks"] = "VERIFIED"

    # 6. Attack Lab
    print("\n--- 6. Attack Lab ---")
    att1_st, att1_data = post("/scenarios/attack-matrix/run-all")
    tot1 = att1_data.get('total_scenarios') or att1_data.get('summary', {}).get('total')
    blk1 = att1_data.get('attacks_blocked') or att1_data.get('summary', {}).get('passed')
    print(f"Attack Lab Run 1 status: {att1_st}, total: {tot1}, blocked: {blk1}")
    assert att1_st == 200 and tot1 == 20

    att2_st, att2_data = post("/scenarios/attack-matrix/run-all")
    tot2 = att2_data.get('total_scenarios') or att2_data.get('summary', {}).get('total')
    blk2 = att2_data.get('attacks_blocked') or att2_data.get('summary', {}).get('passed')
    print(f"Attack Lab Run 2 status: {att2_st}, total: {tot2}, blocked: {blk2}")
    assert att2_st == 200 and tot2 == 20
    results["6. Attack Lab"] = "VERIFIED"

    # 7. Operational Sandbox
    print("\n--- 7. Operational Sandbox ---")
    rq_st, rq_data = get("/gateway/retry-queue")
    print(f"Retry queue status: {rq_st}, size: {rq_data.get('queue_size')}")
    assert rq_st == 200

    rc_st, rc_data = get("/replay/cache")
    print(f"Replay cache status: {rc_st}, nonces_cached: {rc_data.get('nonces_cached')}")
    assert rc_st == 200

    mcp_st, mcp_data = post("/gateway/mcp/call", {
        "tool_name": "fetch_account_balance",
        "arguments": {"account_id": "ACC-01"}
    })
    print(f"MCP tool call status: {mcp_st}, result: {mcp_data.get('status')}")
    assert mcp_st == 200

    # Mode switch
    mode_st, mode_data = post("/mode", {"mode": "MODE_C_AGENTTRUST_NO_FABRIC"}, headers={"X-Admin-Role": "SYSTEM_ADMIN"})
    print(f"Mode switch to MODE_C status: {mode_st}, current_mode: {mode_data.get('current_mode')}")
    assert mode_st == 200 and mode_data.get("current_mode") == "MODE_C_AGENTTRUST_NO_FABRIC"

    mode_reset_st, mode_reset_data = post("/mode", {"mode": "MODE_D_AGENTTRUST_FABRIC"}, headers={"X-Admin-Role": "SYSTEM_ADMIN"})
    print(f"Mode switch reset to MODE_D status: {mode_reset_st}, current_mode: {mode_reset_data.get('current_mode')}")
    assert mode_reset_st == 200 and mode_reset_data.get("current_mode") == "MODE_D_AGENTTRUST_FABRIC"
    results["7. Operational Sandbox"] = "VERIFIED"

    print("\n" + "=" * 60)
    print("ALL 7 DEMO CHECKLIST WORKFLOWS VERIFIED SUCCESSFULLY!")
    print("=" * 60)
    for k, v in results.items():
        print(f"[x] {k}: {v}")

if __name__ == "__main__":
    test_checklist()
