"""
Adversarial Attack Lab & Benchmark Execution Router.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/scenarios", tags=["Adversarial Attack Lab & Benchmarks"])


def get_attack_lab():
    from attack_lab.test_attack_lab import run_attack_lab_matrix
    return run_attack_lab_matrix


def get_benchmark_engine():
    from benchmarks.benchmark_engine import BenchmarkEngine
    return BenchmarkEngine


@router.post("/attack-matrix/run-all", summary="Run Full 20-Scenario Adversarial Attack Lab")
def run_attack_matrix():
    runner = get_attack_lab()
    results = runner()
    return results


@router.post("/benchmark/run", summary="Run Multi-Mode Performance & Security Benchmark")
def run_benchmark():
    engine_cls = get_benchmark_engine()
    engine = engine_cls()
    summary = engine.run_all_modes(num_requests=100)
    return summary
