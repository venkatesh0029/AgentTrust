# AgentTrust Configuration Contract

## Authoritative Source
AgentTrust runtime configuration is supplied exclusively through process environment variables. The application does not load `config/settings.yaml` or automatically parse a local `.env` file.

`config/settings.example.yaml` is reference material only and has no runtime effect.

---

## Configuration Responsibilities

| Variable | Purpose |
| :--- | :--- |
| `AGENTTRUST_ENV` | Selects the runtime environment profile (`development` vs. `production`). |
| `AGENTTRUST_MODE` | Selects the AgentTrust operational mode (`MODE_A_NO_GOVERNANCE`, `MODE_B_POLICY_ENFORCEMENT_LOCAL`, `MODE_C_AGENTTRUST_NO_FABRIC`, `MODE_D_AGENTTRUST_FABRIC`). |
| `GATEWAY_SECRET` | Configures the gateway secret HMAC token; never commit its value. |
| `CORS_ORIGINS` | Explicit list of allowed browser origins. Production requires valid HTTPS origins. |
| `FABRIC_GATEWAY_MODE` | Selects the Fabric gateway mode (`simulator` vs. `live`). |
| `FABRIC_GATEWAY_URL` | Specifies the live Fabric gateway endpoint (e.g. Go bridge HTTP URL). |
| `AGENTTRUST_DB_PATH` | SQLite database file path. Compose defaults to `/app/data/agenttrust_persistent.db`, persisted through the `agenttrust_data` named volume. |
| `REDIS_HOST` / `REDIS_PORT` | Configure Redis connection coordinates when Redis is used. |

---

## Development and Production Profiles

- **Development (`AGENTTRUST_ENV=development`):**
  May use the configured localhost CORS defaults (`http://localhost:3000,http://127.0.0.1:3000`), default or auto-generated gateway secrets, and simulator ledger mode.
- **Production (`AGENTTRUST_ENV=production`):**
  Must explicitly configure:
  1. `AGENTTRUST_ENV=production`
  2. A secure, non-default `GATEWAY_SECRET`
  3. Valid HTTPS `CORS_ORIGINS` (no wildcards, paths, credentials, or localhost addresses)
  4. In Mode D: `FABRIC_GATEWAY_MODE=live` and an explicit `FABRIC_GATEWAY_URL`

  Server startup must fail closed (`RuntimeError`) if any mandatory production configuration is missing or unsafe. Runtime mode changes (`POST /mode`) are also validated against this rule.

---

## Storage and Persistence

AgentTrust relies on SQLite for persistent storage of Root CA credentials, CRL revocations, registered agent profiles, off-chain evidence digests, human approval tickets, and retry reconciliation queues:

- **Shared Resolver:** All default database-backed modules (`PersistentStorageEngine`, `IdentityStore`, `EvidenceStore`, `HumanApprovalManager`, `CertificateManager`, `ProtectedFinanceAPI`) resolve their database path via `resolve_database_path()`. Explicit constructor arguments always override the `AGENTTRUST_DB_PATH` environment variable, which defaults to `agenttrust_persistent.db` when unset.
- **Named Volume Persistence:** In Docker Compose deployments, `AGENTTRUST_DB_PATH` is configured as `/app/data/agenttrust_persistent.db` and backed by the `agenttrust_data` Docker-managed named volume mounted at `/app/data`. The database path must remain inside `/app/data` to ensure durability across container recreation and routine `docker compose down` cycles.

### Database Migration into Named Volume

When upgrading from an older deployment or migrating an existing host database into the Docker-managed `agenttrust_data` named volume:

1. **Ensure a Consistent Backup:**
   Stop the running application before copying its database, or use SQLite's backup API (`sqlite3.Connection.backup()`) to create a consistent, uncorrupted copy while the server is active:
   ```bash
   # Offline copy:
   docker compose stop agenttrust-server
   cp agenttrust_persistent.db /absolute/path/to/backup.db
   ```

2. **Supply Required Compose Variables:**
   Ensure `AGENTTRUST_ENV` and `GATEWAY_SECRET` are exported in your environment or configured in `.env` before invoking `docker compose run`.

3. **Copy into the Named Volume:**
   Mount the source database file read-only into a temporary migration container and copy it using the Python entrypoint to ensure proper non-root file ownership:
   ```bash
   docker compose run --rm --no-deps \
     -v /absolute/path/to/backup.db:/tmp/source.db:ro \
     --entrypoint python \
     agenttrust-server \
     -c "import shutil; shutil.copy2('/tmp/source.db', '/app/data/agenttrust_persistent.db')"
   ```

4. **Fresh Deployments:**
   If no existing database is imported, `PersistentStorageEngine` automatically initializes a clean database schema inside `/app/data/agenttrust_persistent.db` upon initial container startup.

---

## Docker Compose and Local Environment Files
Docker Compose may read `.env` values for variable interpolation. Each required value must be explicitly forwarded through the service's `environment:` mapping in `docker-compose.yml`. The Python application does not load `.env` by itself.

---

## Redis
A static YAML field such as `redis.enabled` does not enable or provision Redis. Redis remains an optional, temporary metadata cache for agent lookups. This Compose deployment does not provision a Redis container; when Redis is unreachable, `CacheManager` automatically falls back to low-latency in-memory dictionary caching.

Cache contents are not durable application state. A process restart may clear them without affecting records stored in SQLite. Deploying Redis is optional and only serves to accelerate repeated query lookups across multiple worker instances.

---

## Secrets
Never store live gateway secrets in source-controlled YAML, Compose files, documentation, or test fixtures. Supply them through the deployment environment or a properly protected secret-management mechanism (e.g., KMS, HashiCorp Vault, Kubernetes Secrets).
