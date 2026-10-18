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

## Docker Compose and Local Environment Files
Docker Compose may read `.env` values for variable interpolation. Each required value must be explicitly forwarded through the service's `environment:` mapping in `docker-compose.yml`. The Python application does not load `.env` by itself.

---

## Redis
A static YAML field such as `redis.enabled` does not enable or provision Redis. Redis availability depends on the application's actual environment-driven client configuration (`REDIS_HOST`, `REDIS_PORT`) and deployment topology. The current `docker-compose.yml` does not provision a Redis container; when Redis is unreachable, `CacheManager` automatically falls back to an in-memory dictionary cache.

---

## Secrets
Never store live gateway secrets in source-controlled YAML, Compose files, documentation, or test fixtures. Supply them through the deployment environment or a properly protected secret-management mechanism (e.g., KMS, HashiCorp Vault, Kubernetes Secrets).
