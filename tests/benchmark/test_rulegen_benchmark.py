# """
# Run RuleGen Benchmark Evaluation
# Usage: python tests/benchmark/test_rulegen_benchmark.py
# """

# from dotenv import load_dotenv
# load_dotenv()

# import asyncio
# import json
# import os
# from pathlib import Path
# import sys

# # Add project root
# sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# from benchmark.rulegen_benchmark import RuleGenBenchmark


# async def main():
#     """Run RuleGen benchmark evaluation"""
    
#     print("\n" + "="*80)
#     print("RULEGEN BENCHMARK EVALUATION")
#     print("="*80)
    
#     # Load RuleGen output
#     output_file = Path("data/generated_rules/rulegen_llm_test_output.json")
    
#     if not output_file.exists():
#         print(f"Output file not found: {output_file}")
#         print("   Please run RuleGen agent first")
#         return
    
#     print(f"\nLoading RuleGen output: {output_file}")
    
#     with open(output_file, 'r', encoding='utf-8') as f:
#         rulegen_output = json.load(f)
    
#     # Extract rules to evaluate
#     rules = rulegen_output.get("rule_generation_results", [])
    
#     print(f"   Found {len(rules)} rules to evaluate")
    
#     # Configure benchmark
#     config = {
#         "platforms": ["splunk", "elasticsearch"],
#         "evaluate_sigma": True,
#         "evaluate_platforms": True,
#         "syntactic_validation": True,
#         "llm_judge": {
#             "enabled": True,
#             "api_key": os.getenv("GEMINI_API_KEY"),
#             "model": "gemini-2.0-flash-lite",
#             "temperature": 0.3,
#             "max_tokens": 2000,
#             "persona": "expert SIEM engineer and threat detection specialist",
#             "detailed_feedback": True,
#             "confidence_scores": True
#         }
#     }
    
#     # Check API key
#     if not config["llm_judge"]["api_key"]:
#         print("\n Warning: GEMINI_API_KEY not found")
#         print("   Falling back to heuristic evaluation (lower quality)")
#         config["llm_judge"]["enabled"] = False
    
#     # Initialize benchmark
#     print("\nInitializing RuleGen Benchmark...")
#     benchmark = RuleGenBenchmark(config)
    
#     print(f"   Initialized with {len(benchmark.metrics)} metrics")
#     print(f"   LLM Judge: {'Enabled' if benchmark.use_llm_judge else 'Disabled'}")
    
#     # Evaluate all rules
#     print("\nStarting evaluation...")
#     print("-" * 80)
    
#     results = await benchmark.evaluate_batch(rules)
    
#     # Print results summary
#     print("\n" + "="*80)
#     print("EVALUATION RESULTS")
#     print("="*80)
    
#     # Overall statistics
#     stats = benchmark.get_statistics()
    
#     print(f"\nOverall Statistics:")
#     print(f"   Total Evaluations:     {stats['total_evaluations']}")
#     print(f"   Average Score:         {stats['average_score']:.3f}/1.0 ({get_grade(stats['average_score'])})")
    
#     # Category scores
#     print(f"\nCategory Averages:")
#     for category, score in sorted(stats['category_averages'].items(), key=lambda x: x[1], reverse=True):
#         bar = create_bar(score, 40)
#         print(f"   {category:20} {score:.3f} {bar}")
    
#     # Top metrics
#     print(f"\nMetric Averages (Top 10):")
#     sorted_metrics = sorted(
#         stats['metric_averages'].items(), 
#         key=lambda x: x[1], 
#         reverse=True
#     )[:10]
    
#     for metric, score in sorted_metrics:
#         bar = create_bar(score, 40)
#         print(f"   {metric:35} {score:.3f} {bar}")
    
#     # Score distribution
#     print(f"\nScore Distribution:")
#     for label, count in stats['score_distribution'].items():
#         percentage = (count / stats['total_evaluations'] * 100) if stats['total_evaluations'] > 0 else 0
#         bar = create_bar(percentage / 100, 40)
#         print(f"   {label:20} {count:3} rules ({percentage:5.1f}%) {bar}")
    
#     # Top and bottom performers
#     print(f"\nTop 3 Rules:")
#     for i, result in enumerate(benchmark.get_top_performers(3), 1):
#         print(f"   {i}. {result.metadata['attack_id']:12} Score: {result.overall_score:.3f} - {result.metadata['technique_name']}")
    
#     print(f"\n Bottom 3 Rules (Need Improvement):")
#     for i, result in enumerate(benchmark.get_bottom_performers(3), 1):
#         print(f"   {i}. {result.metadata['attack_id']:12} Score: {result.overall_score:.3f} - {result.metadata['technique_name']}")
    
#     # Individual rule summaries
#     print(f"\nIndividual Rule Summaries:")
#     print("-" * 80)
#     for result in results:
#         print(f"\n{result.metadata['attack_id']} - {result.metadata['technique_name']}")
#         print(f"Score: {result.overall_score:.3f}/1.0 ({get_grade(result.overall_score)})")
#         print(f"Summary: {result.summary}")
        
#         # Show weakest metrics
#         weak_metrics = [
#             mr for mr in result.metric_results 
#             if mr.normalized_score < 0.6
#         ]
#         if weak_metrics:
#             print(f"Issues:")
#             for mr in weak_metrics[:3]:
#                 print(f"  • {mr.metric_name}: {mr.score:.1f}/10 - {mr.explanation[:80]}...")
    
#     # Save detailed results
#     output_dir = Path("data/benchmark")
#     output_dir.mkdir(parents=True, exist_ok=True)
    
#     results_file = output_dir / "rulegen_benchmark_results.json"
#     benchmark.export_results_with_recommendations(str(results_file))
    
#     print(f"\n" + "="*80)
#     print(f"BENCHMARK COMPLETE")
#     print("="*80)
#     print(f"\nDetailed results saved to: {results_file}")
#     print(f"File size: {results_file.stat().st_size / 1024:.2f} KB")
    
#     # Final grade
#     final_grade = get_grade(stats['average_score'])
#     grade_emoji = {
#         "A": "A",
#         "B": "B",
#         "C": "C",
#         "D": "D",
#         "F": "F"
#     }.get(final_grade[0], "Score")
    
#     print(f"\n{grade_emoji} Final Grade: {final_grade}")
#     print(f"Overall Score: {stats['average_score']:.3f}/1.0")
    
#     print("\nEvaluation complete!")


# def get_grade(score: float) -> str:
#     """Convert score to letter grade"""
#     if score >= 0.9:
#         return "A (Excellent)"
#     elif score >= 0.8:
#         return "B (Good)"
#     elif score >= 0.7:
#         return "C (Fair)"
#     elif score >= 0.6:
#         return "D (Below Average)"
#     else:
#         return "F (Poor)"


# def create_bar(value: float, length: int = 40) -> str:
#     """Create a visual progress bar"""
#     filled = int(value * length)
#     bar = "█" * filled + "░" * (length - filled)
#     return f"[{bar}]"


# if __name__ == "__main__":
#     asyncio.run(main())



"""
Run RuleGen Benchmark Evaluation
Usage: python tests/benchmark/test_rulegen_benchmark.py
"""

from dotenv import load_dotenv
load_dotenv()

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
    print("RULEGEN BENCHMARK EVALUATION")
    print("="*80)
    
    # Load RuleGen output
    output_file = Path("data/generated_rules/rulegen_llm_test_output.json")
    
    if not output_file.exists():
        print(f"Output file not found: {output_file}")
        print("   Please run RuleGen agent first")
        return
    
    print(f"\nLoading RuleGen output: {output_file}")
    
    with open(output_file, 'r', encoding='utf-8') as f:
        rulegen_output = json.load(f)
    
    # FIXED: Extract rules from correct location
    # The structure has "results" not "rule_generation_results"
    rules = rulegen_output.get("results", [])
    
    # Filter only successful rules that have sigma_rule
    valid_rules = [r for r in rules if r.get('status') == 'success' and 'sigma_rule' in r]
    
    print(f"   Found {len(rules)} total results")
    print(f"   Valid rules to evaluate: {len(valid_rules)}")
    
    if not valid_rules:
        print("\nNo valid rules found to evaluate!")
        print("   Check that RuleGen output contains 'sigma_rule' field")
        return
    
    # Configure benchmark
    config = {
        "platforms": ["splunk", "elasticsearch"],
        "evaluate_sigma": True,
        "evaluate_platforms": False,  # We don't have platform conversions yet
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
        print("\n Warning: GEMINI_API_KEY not found")
        print("   Falling back to heuristic evaluation (lower quality)")
        config["llm_judge"]["enabled"] = False
    else:
        print(f"\nAPI Key configured: {config['llm_judge']['api_key'][:10]}...")
    
    # Initialize benchmark
    print("\nInitializing RuleGen Benchmark...")
    benchmark = RuleGenBenchmark(config)
    
    print(f"   Initialized with {len(benchmark.metrics)} metrics")
    print(f"   LLM Judge: {'Enabled' if benchmark.use_llm_judge else 'Disabled'}")
    
    # Evaluate all rules
    print("\nStarting evaluation...")
    print("-" * 80)
    
    results = await benchmark.evaluate_batch(valid_rules)
    
    # Print results summary
    print("\n" + "="*80)
    print("EVALUATION RESULTS")
    print("="*80)
    
    # Overall statistics
    stats = benchmark.get_statistics()
    
    print(f"\nOverall Statistics:")
    print(f"   Total Evaluations:     {stats['total_evaluations']}")
    print(f"   Average Score:         {stats['average_score']:.3f}/1.0 ({get_grade(stats['average_score'])})")
    
    # Category scores
    if stats.get('category_averages'):
        print(f"\nCategory Averages:")
        for category, score in sorted(stats['category_averages'].items(), key=lambda x: x[1], reverse=True):
            bar = create_bar(score, 40)
            print(f"   {category:20} {score:.3f} {bar}")
    
    # Top metrics
    if stats.get('metric_averages'):
        print(f"\nMetric Averages (Top 10):")
        sorted_metrics = sorted(
            stats['metric_averages'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        for metric, score in sorted_metrics:
            bar = create_bar(score, 40)
            print(f"   {metric:35} {score:.3f} {bar}")
    
    # Score distribution
    if stats.get('score_distribution'):
        print(f"\nScore Distribution:")
        for label, count in stats['score_distribution'].items():
            percentage = (count / stats['total_evaluations'] * 100) if stats['total_evaluations'] > 0 else 0
            bar = create_bar(percentage / 100, 40)
            print(f"   {label:20} {count:3} rules ({percentage:5.1f}%) {bar}")
    
    # Top and bottom performers
    if results:
        print(f"\nTop 3 Rules:")
        for i, result in enumerate(benchmark.get_top_performers(3), 1):
            attack_id = result.metadata.get('attack_id', 'UNKNOWN')
            technique = result.metadata.get('technique_name', 'Unknown')
            print(f"   {i}. {attack_id:12} Score: {result.overall_score:.3f} - {technique}")
        
        print(f"\n Bottom 3 Rules (Need Improvement):")
        for i, result in enumerate(benchmark.get_bottom_performers(3), 1):
            attack_id = result.metadata.get('attack_id', 'UNKNOWN')
            technique = result.metadata.get('technique_name', 'Unknown')
            print(f"   {i}. {attack_id:12} Score: {result.overall_score:.3f} - {technique}")
    
    # Individual rule summaries
    print(f"\nIndividual Rule Summaries:")
    print("-" * 80)
    for result in results[:5]:  # Show first 5
        attack_id = result.metadata.get('attack_id', 'UNKNOWN')
        technique = result.metadata.get('technique_name', 'Unknown')
        print(f"\n{attack_id} - {technique}")
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
                explanation = mr.explanation[:80] if mr.explanation else "No explanation"
                print(f"  • {mr.metric_name}: {mr.score:.1f}/10 - {explanation}...")
    
    if len(results) > 5:
        print(f"\n... and {len(results) - 5} more rules")
    
    # Save detailed results
    output_dir = Path("data/benchmark")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results_file = output_dir / "rulegen_benchmark_results.json"
    benchmark.export_results_with_recommendations(str(results_file))
    
    print(f"\n" + "="*80)
    print(f"BENCHMARK COMPLETE")
    print("="*80)
    print(f"\nDetailed results saved to: {results_file}")
    print(f"File size: {results_file.stat().st_size / 1024:.2f} KB")
    
    # Final grade
    final_grade = get_grade(stats['average_score'])
    grade_emoji = {
        "A": "A",
        "B": "B", 
        "C": "C",
        "D": "D",
        "F": "F"
    }.get(final_grade[0], "Score")
    
    print(f"\n{grade_emoji} Final Grade: {final_grade}")
    print(f"Overall Score: {stats['average_score']:.3f}/1.0")
    
    # Show improvement areas
    if stats.get('metric_averages'):
        weak_metrics = [(m, s) for m, s in stats['metric_averages'].items() if s < 0.6]
        if weak_metrics:
            print(f"\n Areas for Improvement:")
            for metric, score in sorted(weak_metrics, key=lambda x: x[1])[:5]:
                print(f"   • {metric}: {score:.3f}")
    
    print("\nEvaluation complete!")


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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n Evaluation cancelled by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()