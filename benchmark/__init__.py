"""
Benchmark Framework for Multi-Agent SIEM
LLM-as-Judge evaluation system
"""

from benchmark.benchmark_base import (
    BaseBenchmark,
    BenchmarkMetric,
    BenchmarkResult,
    EvaluationResult,
    MetricCategory
)

from benchmark.llm_judge import LLMJudge

from benchmark.attackgen_benchmark import AttackGenBenchmark

# RuleGen benchmark is placeholder for now
# from benchmark.rulegen_benchmark import RuleGenBenchmark

__version__ = "1.0.0"

__all__ = [
    # Base classes
    "BaseBenchmark",
    "BenchmarkMetric",
    "BenchmarkResult",
    "EvaluationResult",
    "MetricCategory",
    
    # Evaluator
    "LLMJudge",
    
    # Agent-specific benchmarks
    "AttackGenBenchmark",
    # "RuleGenBenchmark",  # TODO
]