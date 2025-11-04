"""
Run RuleGen Benchmark Evaluation
Usage: python tests/benchmark/test_rulegen_benchmark.py
"""

import asyncio
import json
import os
from pathlib import Path
import sys

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmark.rulegen_benchmark import RuleGenBenchmark


async def main():
    """Run RuleGen benchmark evaluation"""
    
    print("\n" + "="*80)
    print("🎯 RULEGEN BENCHMARK EVALUATION")
    print("="*80)
    
    # Load RuleGen output
    output_file = Path("data/generated_rules/rulegen_llm_output.json")
    
    if not output_file.exists():
        print(f"❌ Output file not found: {output_file}")
        print("   Please run RuleGen agent first")
        return
    
    print(f"\n📂 Loading RuleGen output: {output_file}")
    
    with open(output_file, 'r', encoding='utf-8') as f:
        rulegen_output = json.load(f)
    
    # Extract rules to evaluate
    rules = rulegen_output.get("rule_generation_results", [])
    
    print(f"   Found {len(rules)} rules to evaluate")
    
    # Configure benchmark
    config = {
        "platforms": ["splunk", "elasticsearch"],
        "evaluate_sigma": True,
        "evaluate_platforms": True,
        "syntactic_validation": True,
        "llm_judge": {
            "enabled": True,
            "api_key": os.getenv("GEMINI_API_KEY"),
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3,
            "max_tokens": 2000,
            "persona": "expert SIEM engineer and threat detection specialist",
            "detailed_feedback": True,
            "confidence_scores": True
        }
    }
    
    # Check API key
    if not config["llm_judge"]["api_key"]:
        print("\n⚠️  Warning: GEMINI_API_KEY not found")
        print("   Falling back to heuristic evaluation (lower quality)")
        config["llm_judge"]["enabled"] = False
    
    # Initialize benchmark
    print("\n🔧 Initializing RuleGen Benchmark...")
    benchmark = RuleGenBenchmark(config)
    
    print(f"   ✓ Initialized with {len(benchmark.metrics)} metrics")
    print(f"   ✓ LLM Judge: {'Enabled' if benchmark.use_llm_judge else 'Disabled'}")
    
    # Evaluate all rules
    print("\n🚀 Starting evaluation...")
    print("-" * 80)
    
    results = await benchmark.evaluate_batch(rules)
    
    # Print results summary
    print("\n" + "="*80)
    print("📊 EVALUATION RESULTS")
    print("="*80)
    
    # Overall statistics
    stats = benchmark.get_statistics()
    
    print(f"\n📈 Overall Statistics:")
    print(f"   Total Evaluations:     {stats['total_evaluations']}")
    print(f"   Average Score:         {stats['average_score']:.3f}/1.0 ({get_grade(stats['average_score'])})")
    
    # Category scores
    print(f"\n📊 Category Averages:")
    for category, score in sorted(stats['category_averages'].items(), key=lambda x: x[1], reverse=True):
        bar = create_bar(score, 40)
        print(f"   {category:20} {score:.3f} {bar}")
    
    # Top metrics
    print(f"\n🎯 Metric Averages (Top 10):")
    sorted_metrics = sorted(
        stats['metric_averages'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]
    
    for metric, score in sorted_metrics:
        bar = create_bar(score, 40)
        print(f"   {metric:35} {score:.3f} {bar}")
    
    # Score distribution
    print(f"\n📊 Score Distribution:")
    for label, count in stats['score_distribution'].items():
        percentage = (count / stats['total_evaluations'] * 100) if stats['total_evaluations'] > 0 else 0
        bar = create_bar(percentage / 100, 40)
        print(f"   {label:20} {count:3} rules ({percentage:5.1f}%) {bar}")
    
    # Top and bottom performers
    print(f"\n🏆 Top 3 Rules:")
    for i, result in enumerate(benchmark.get_top_performers(3), 1):
        print(f"   {i}. {result.metadata['attack_id']:12} Score: {result.overall_score:.3f} - {result.metadata['technique_name']}")
    
    print(f"\n⚠️  Bottom 3 Rules (Need Improvement):")
    for i, result in enumerate(benchmark.get_bottom_performers(3), 1):
        print(f"   {i}. {result.metadata['attack_id']:12} Score: {result.overall_score:.3f} - {result.metadata['technique_name']}")
    
    # Individual rule summaries
    print(f"\n📝 Individual Rule Summaries:")
    print("-" * 80)
    for result in results:
        print(f"\n{result.metadata['attack_id']} - {result.metadata['technique_name']}")
        print(f"Score: {result.overall_score:.3f}/1.0 ({get_grade(result.overall_score)})")
        print(f"Summary: {result.summary}")
        
        # Show weakest metrics
        weak_metrics = [
            mr for mr in result.metric_results 
            if mr.normalized_score < 0.6
        ]
        if weak_metrics:
            print(f"Issues:")
            for mr in weak_metrics[:3]:
                print(f"  • {mr.metric_name}: {mr.score:.1f}/10 - {mr.explanation[:80]}...")
    
    # Save detailed results
    output_dir = Path("data/benchmark")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results_file = output_dir / "rulegen_benchmark_results.json"
    benchmark.export_results_with_recommendations(str(results_file))
    
    print(f"\n" + "="*80)
    print(f"✅ BENCHMARK COMPLETE")
    print("="*80)
    print(f"\n📁 Detailed results saved to: {results_file}")
    print(f"📊 File size: {results_file.stat().st_size / 1024:.2f} KB")
    
    # Final grade
    final_grade = get_grade(stats['average_score'])
    grade_emoji = {
        "A": "🌟",
        "B": "✨",
        "C": "⭐",
        "D": "💫",
        "F": "⚠️"
    }.get(final_grade[0], "📊")
    
    print(f"\n{grade_emoji} Final Grade: {final_grade}")
    print(f"🎯 Overall Score: {stats['average_score']:.3f}/1.0")
    
    print("\n✨ Evaluation complete!")


def get_grade(score: float) -> str:
    """Convert score to letter grade"""
    if score >= 0.9:
        return "A (Excellent)"
    elif score >= 0.8:
        return "B (Good)"
    elif score >= 0.7:
        return "C (Fair)"
    elif score >= 0.6:
        return "D (Below Average)"
    else:
        return "F (Poor)"


def create_bar(value: float, length: int = 40) -> str:
    """Create a visual progress bar"""
    filled = int(value * length)
    bar = "█" * filled + "░" * (length - filled)
    return f"[{bar}]"


if __name__ == "__main__":
    asyncio.run(main())