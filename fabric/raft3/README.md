# AgentTrust Isolated Three-Orderer Raft Lab

This is a **separate test network** for distributed-resilience work. It deliberately does not edit or reuse the running single-orderer topology in `fabric/docker-compose-fabric.yaml`, its generated crypto, its channel artifacts, its named volumes, or `agenttrust_persistent.db`.

## Topology

- Three etcdraft ordering nodes: `orderer1.agenttrust.com`, `orderer2.agenttrust.com`, and `orderer3.agenttrust.com` (internal port 7050; host loopback ports 17050, 18050, 19050).
- One CouchDB-backed peer for Org1 and one for Org2, each with fresh identities generated under this directory.
- Distinct Compose project `agenttrust-raft3`, network `agenttrust-raft3-net`, and project-prefixed named volumes.
- Host ports bind to `127.0.0.1`; the lab is not published on all host interfaces.

Three consenters permit quorum with two orderers online and can tolerate one orderer unavailable. That is a topology property, not a guarantee until leader failover and transaction behavior are tested.

## Commands

Run these from the repository root on branch `feat/fabric-resilience`:

```powershell
py -3.11 scripts\fabric_raft3.py validate
py -3.11 scripts\fabric_raft3.py bootstrap
py -3.11 scripts\fabric_raft3.py up --timeout 240
py -3.11 scripts\fabric_raft3.py channel-setup
py -3.11 scripts\fabric_raft3.py status
```

`bootstrap` uses the official `hyperledger/fabric-tools:2.5.4` image to create fresh crypto under `fabric/raft3/crypto-config`, then creates the system-channel genesis block and application-channel create transaction under `fabric/raft3/channel-artifacts`. Generated identities and artifacts are ignored by Git.

`channel-setup` creates the `agenttrust-raft3` application channel and joins the two peers. Chaincode deployment and gateway integration are intentionally deferred to a follow-up step; a joined channel alone does not validate application transactions.

Normal teardown preserves all volumes:

```powershell
py -3.11 scripts\fabric_raft3.py down
```

Destruction is deliberately explicit and interactive:

```powershell
py -3.11 scripts\fabric_raft3.py down --destroy-volumes
```

The tool requires the exact confirmation phrase `DESTROY RAFT3 VOLUMES`. This deletes only the isolated lab's Compose-managed named volumes. Rebuilding generated crypto is also guarded; if the lab has named volumes, they must be explicitly destroyed first to avoid pairing new identities with old ledgers.

## Important boundaries

- Do not point the existing application's live gateway at this test network until a separate gateway/chaincode configuration has been reviewed.
- Do not copy existing release crypto into this directory. Bootstrap generates independent development identities.
- The current release-candidate network remains the system defined in `fabric/docker-compose-fabric.yaml`.
- `up` does not remove containers or volumes on timeout. Inspect `status` and service logs before retrying.
- The Compose file mounts the Docker socket into peers for future external-chaincode use; treat the lab as a local developer environment, not a production security boundary.
