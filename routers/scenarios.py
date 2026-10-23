"""
Adversarial Attack Lab & Benchmark Execution Router.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/scenarios", tags=["Adversarial Attack Lab & Benchmarks"])


def get_attack_lab():
    from server import run_all_attack_scenarios
    return run_all_attack_scenarios


def get_benchmark_runner():
    from server import run_performance_benchmarks
    return run_performance_benchmarks


@router.post("/attack-matrix/run-all", summary="Run Full 20-Scenario Adversarial Attack Lab")
def run_attack_matrix():
    runner = get_attack_lab()
    return runner()


@router.post("/benchmark/run", summary="Run Multi-Mode Performance & Security Benchmark")
def run_benchmark():
    runner = get_benchmark_runner()
    return runner()
