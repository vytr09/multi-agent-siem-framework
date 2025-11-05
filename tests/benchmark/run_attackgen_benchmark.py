#!/usr/bin/env python3
"""
AttackGen Benchmark Test Script
Evaluates AttackGen agent outputs using LLM-as-Judge
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmark.attackgen_benchmark import AttackGenBenchmark


async def load_attackgen_results(filepath: str) -> dict:
    """Load AttackGen results from JSON file"""
    
    print(f"[LOAD] Loading AttackGen results from: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Count commands - check both root and nested locations
    commands = data.get('attack_commands', [])
    if not commands and 'execution_result' in data:
        commands = data['execution_result'].get('attack_commands', [])
    
    print(f"[OK] Loaded {len(commands)} commands")
    
    return data


async def run_benchmark():
    """Run AttackGen benchmark evaluation"""
    
    print("\n" + "="*80)
    print("[BENCHMARK] ATTACKGEN AGENT BENCHMARK")
    print("="*80)
    
    # Configuration
    config = {
        "llm_judge": {
            "enabled": True,
            "api_key": os.getenv("GEMINI_API_KEY"),
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3,
            "max_tokens": 2000,
            "persona": "expert cybersecurity researcher specializing in offensive security and red team operations",
            "detailed_feedback": True,
            "confidence_scores": True
        }
    }
    
    # Check API key
    if not config["llm_judge"]["api_key"]:
        print("[ERROR] GEMINI_API_KEY not set")
        print("   Set it with: export GEMINI_API_KEY='your-api-key'")
        return
    
    # Initialize benchmark
    print("\n[INIT] Initializing benchmark...")
    benchmark = AttackGenBenchmark(config)
    
    print(f"[OK] Initialized with {len(benchmark.metrics)} metrics")
    print("\n[METRICS] Metrics:")
    for metric in benchmark.metrics:
        print(f"   - {metric.name} ({metric.category.value}) - weight: {metric.weight}")
    
    # Load AttackGen results
    project_root = Path(__file__).resolve().parents[2]
    
    # Use real results by default (now small with hybrid extraction), or test sample if specified
    use_test_sample = os.getenv("USE_TEST_SAMPLE", "false").lower() == "true"
    
    if use_test_sample:
        results_path = project_root / "data" / "attackgen" / "test_sample.json"
        print("\n[FILE] Using TEST SAMPLE file")
    else:
        results_path = project_root / "data" / "attackgen" / "real_attackgen_results.json"
        print("\n[FILE] Using REAL results file (generated from hybrid extraction)")
        print("   [TIP] Set USE_TEST_SAMPLE=true to use the minimal test sample instead")
    
    if not results_path.exists():
        print(f"\n[ERROR] AttackGen results not found at {results_path}")
        print("   Run AttackGen agent first to generate results")
        return
    
    attackgen_data = await load_attackgen_results(str(results_path))
    
    # Extract commands - they might be at root level or nested in execution_result
    commands = attackgen_data.get("attack_commands", [])
    if not commands and "execution_result" in attackgen_data:
        commands = attackgen_data["execution_result"].get("attack_commands", [])
    
    if not commands:
        print("[ERROR] No commands found in results")
        return
    
    # Evaluate commands
    print(f"\n[RUN] Evaluating {len(commands)} commands...")
    print("="*80)
    
    results = []
    
    for i, command in enumerate(commands, 1):
        print(f"\n[{i}/{len(commands)}] {command.get('name', 'Unknown')}")
        print(f"   Technique: {command.get('mitre_attack_id')} - {command.get('technique_name')}")
        print(f"   Platform: {command.get('platform')}")
        
        try:
            result = await benchmark.evaluate_item(command)
            results.append(result)
            benchmark.results.append(result)  # Store in benchmark for statistics
            
            # Print result summary
            print(f"\n   [RESULTS] Results:")
            print(f"      Overall Score: {result.overall_score:.3f}")
            print(f"      Category Scores:")
            for category, score in result.category_scores.items():
                print(f"         - {category}: {score:.3f}")
            
        except Exception as e:
            print(f"   [ERROR] Evaluation failed: {e}")
            import traceback
            traceback.print_exc()
    
    # Print statistics
    print("\n" + "="*80)
    print("[STATS] BENCHMARK STATISTICS")
    print("="*80)
    
    if not results:
        print("\n[WARN] No results to display")
        return
    
    stats = benchmark.get_statistics()
    
    print(f"\nTotal Evaluations: {stats['total_evaluations']}")
    print(f"Average Score: {stats['average_score']:.3f}")
    
    print("\nCategory Averages:")
    for category, avg in sorted(stats.get('category_averages', {}).items(), key=lambda x: x[1], reverse=True):
        print(f"   - {category}: {avg:.3f}")
    
    print("\nMetric Averages:")
    for metric, avg in sorted(stats.get('metric_averages', {}).items(), key=lambda x: x[1], reverse=True):
        print(f"   - {metric}: {avg:.3f}")
    
    print("\nScore Distribution:")
    for bucket, count in stats.get('score_distribution', {}).items():
        bar = "#" * count
        print(f"   {bucket:20s} {bar} ({count})")
    
    # Top performers
    print("\n[TOP] TOP PERFORMERS:")
    top = benchmark.get_top_performers(n=3)
    for i, result in enumerate(top, 1):
        print(f"\n{i}. {result.metadata.get('technique_name', 'Unknown')}")
        print(f"   Score: {result.overall_score:.3f}")
        print(f"   Platform: {result.metadata.get('platform')}")
        print(f"   Attack ID: {result.metadata.get('attack_id')}")
    
    # Bottom performers
    print("\n[WARN] BOTTOM PERFORMERS:")
    bottom = benchmark.get_bottom_performers(n=3)
    for i, result in enumerate(bottom, 1):
        print(f"\n{i}. {result.metadata.get('technique_name', 'Unknown')}")
        print(f"   Score: {result.overall_score:.3f}")
        print(f"   Platform: {result.metadata.get('platform')}")
        print(f"   Attack ID: {result.metadata.get('attack_id')}")
    
    # Export results
    output_dir = project_root / "data" / "benchmark_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"attackgen_benchmark_{timestamp}.json"
    
    benchmark.export_results(str(output_path))
    
    print("\n" + "="*80)
    print(f"[OK] BENCHMARK COMPLETE")
    print("="*80)
    print(f"[FILE] Results saved to: {output_path}")
    print(f"[INFO] File size: {output_path.stat().st_size / 1024:.2f} KB")
    
    # Detailed report for top command
    if results:
        print("\n" + "="*80)
        print("[DETAIL] DETAILED REPORT - TOP COMMAND")
        print("="*80)
        
        top_result = top[0] if top else results[0]
        
        print(f"\nCommand: {top_result.metadata.get('technique_name')}")
        print(f"Score: {top_result.overall_score:.3f}")
        print(f"\nMetric Details:")
        
        for metric_result in top_result.metric_results:
            print(f"\n- {metric_result.metric_name}")
            print(f"  Score: {metric_result.score:.1f}/10 (normalized: {metric_result.normalized_score:.3f})")
            print(f"  Confidence: {metric_result.confidence:.2f}")
            print(f"  Explanation: {metric_result.explanation[:200]}...")
            
            if metric_result.metadata.get("strengths"):
                print(f"  Strengths:")
                for strength in metric_result.metadata["strengths"][:2]:
                    print(f"     + {strength}")
            
            if metric_result.metadata.get("weaknesses"):
                print(f"  Weaknesses:")
                for weakness in metric_result.metadata["weaknesses"][:2]:
                    print(f"     - {weakness}")
        
        print(f"\nSummary:")
        print(top_result.summary)


if __name__ == "__main__":
    try:
        asyncio.run(run_benchmark())
    except KeyboardInterrupt:
        print("\n\n[WARN] Benchmark interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)