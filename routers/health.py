"""
Health Check & Enterprise Prometheus Metrics Router.
"""

import time
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

router = APIRouter(tags=["Health & Telemetry"])

_SERVER_START_TIME = time.time()
_REQUEST_COUNTER = 0
_BLOCKED_COUNTER = 0
_ALLOWED_COUNTER = 0


def increment_request_metrics(decision: str):
    global _REQUEST_COUNTER, _BLOCKED_COUNTER, _ALLOWED_COUNTER
    _REQUEST_COUNTER += 1
    if decision in ("ALLOWED", "ALLOWED_AFTER_APPROVAL"):
        _ALLOWED_COUNTER += 1
    else:
        _BLOCKED_COUNTER += 1


@router.get("/healthz", summary="Liveness & Readiness Health Probe")
@router.get("/readyz", summary="Readiness Probe")
@router.get("/livez", summary="Liveness Probe")
def health_check():
    """Returns operational status of the AgentTrust Action Gateway."""
    uptime = time.time() - _SERVER_START_TIME
    return {
        "status": "UP",
        "service": "AgentTrust-13Stage-ActionGateway",
        "version": "2.5.0-Enterprise",
        "uptime_seconds": round(uptime, 2),
        "security_invariants_enforced": 12,
        "attack_scenarios_active": 20
    }


@router.get("/metrics", summary="Prometheus Enterprise Metrics Endpoint")
def get_prometheus_metrics():
    """Exposes Prometheus text format metrics for observability dashboards."""
    uptime = time.time() - _SERVER_START_TIME
    metrics = f"""# HELP agenttrust_uptime_seconds Total uptime of AgentTrust gateway in seconds.
# TYPE agenttrust_uptime_seconds counter
agenttrust_uptime_seconds {uptime:.2f}

# HELP agenttrust_requests_total Total number of agent requests processed by the 13-stage gateway.
# TYPE agenttrust_requests_total counter
agenttrust_requests_total {_REQUEST_COUNTER}

# HELP agenttrust_requests_allowed_total Total number of allowed agent requests.
# TYPE agenttrust_requests_allowed_total counter
agenttrust_requests_allowed_total {_ALLOWED_COUNTER}

# HELP agenttrust_requests_blocked_total Total number of blocked/denied agent requests.
# TYPE agenttrust_requests_blocked_total counter
agenttrust_requests_blocked_total {_BLOCKED_COUNTER}

# HELP agenttrust_security_invariants Total security invariants enforced.
# TYPE agenttrust_security_invariants gauge
agenttrust_security_invariants 12.0
"""
    return Response(content=metrics, media_type="text/plain")
