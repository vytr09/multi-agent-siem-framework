"""
Working LangChain Integration Test
Demonstrates both traditional and LangChain-powered agents
"""


import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
from datetime import datetime
from typing import Dict, Any

# Traditional agents
from agents.extractor.agent import ExtractorAgent
from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.evaluator.agent import EvaluatorAgent

# LangChain agents
from agents.extractor.langchain_agent import LangChainExtractorAgent
from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent

from core.logging import get_agent_logger
from tests.utils import get_full_agent_config


logger = get_agent_logger("langchain_integration_test")


async def test_traditional_pipeline():
    """Test traditional agent pipeline"""
    print("\n" + "="*80)
    print("TESTING TRADITIONAL PIPELINE (Direct Gemini API)")
    print("="*80)
    
    start_time = datetime.utcnow()
    
    # Sample threat intelligence report
    sample_report = """
    APT29 conducted a spear-phishing campaign targeting government organizations.
    The attack chain involved:
    1. Initial access via malicious email attachment (T1566.001)
    2. Execution of PowerShell scripts for reconnaissance (T1059.001)
    3. Credential dumping using Mimikatz (T1003.001)
    4. Lateral movement via Remote Desktop Protocol (T1021.001)
    5. Data exfiltration to C2 server at 192.168.1.100 (T1041)
    
    The campaign used domain fronting techniques to evade detection.
    """
    
    try:
        # 1. Extractor
        extractor_config = get_full_agent_config("extractor")
        extractor_config.setdefault("llm", {})["enabled"] = False
        extractor_config["use_langchain"] = False
        
        extractor = ExtractorAgent("traditional_extractor", extractor_config)
        await extractor.start()
        
        print("\n[1/3] Extracting TTPs...")
        extractor_result = await extractor.execute({"text": sample_report})
        
        ttps = extractor_result.get("ttps", [])
        print(f"✓ Extracted {len(ttps)} TTPs")
        for ttp in ttps[:3]:
            print(f"  - {ttp.get('technique_id')}: {ttp.get('technique_name')}")
        
        await extractor.stop()
        
        # 2. RuleGen
        rulegen_config = get_full_agent_config("rulegen")
        rulegen_config.setdefault("llm", {})["enabled"] = False
        rulegen_config["use_langchain"] = False
        
        rulegen = RuleGenerationAgentWithLLM("traditional_rulegen", rulegen_config)
        await rulegen.start()
        
        print("\n[2/3] Generating Sigma rules...")
        rulegen_result = await rulegen.execute({"ttps": ttps})
        
        rules = rulegen_result.get("rules", [])
        print(f"✓ Generated {len(rules)} rules")
        for rule in rules[:2]:
            print(f"  - {rule.get('title')}")
        
        await rulegen.stop()
        
        # 3. Evaluator
        evaluator_config = get_full_agent_config("evaluator")
        evaluator_config.setdefault("llm", {})["enabled"] = False
        evaluator_config["use_langchain"] = False
        
        evaluator = EvaluatorAgent("traditional_evaluator", evaluator_config)
        await evaluator.start()
        
        print("\n[3/3] Evaluating rules...")
        evaluator_result = await evaluator.execute({"rules": rules})
        
        summary = evaluator_result.get("summary", {})
        print(f"✓ Evaluated {summary.get('rules_evaluated', 0)} rules")
        print(f"  Average quality: {summary.get('average_quality_score', 0):.2f}")
        
        await evaluator.stop()
        
        elapsed_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        print(f"\n✓ Traditional pipeline completed in {elapsed_ms:.0f}ms")
        
        return {
            "pipeline": "traditional",
            "ttps_extracted": len(ttps),
            "rules_generated": len(rules),
            "avg_quality": summary.get("average_quality_score", 0),
            "time_ms": elapsed_ms
        }
        
    except Exception as e:
        print(f"\n✗ Traditional pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return None


async def test_langchain_pipeline():
    """Test LangChain agent pipeline"""
    print("\n" + "="*80)
    print("TESTING LANGCHAIN PIPELINE (LangChain + Pydantic + Structured Outputs)")
    print("="*80)
    
    start_time = datetime.utcnow()
    
    # Same sample report
    sample_report = """
    APT29 conducted a spear-phishing campaign targeting government organizations.
    The attack chain involved:
    1. Initial access via malicious email attachment (T1566.001)
    2. Execution of PowerShell scripts for reconnaissance (T1059.001)
    3. Credential dumping using Mimikatz (T1003.001)
    4. Lateral movement via Remote Desktop Protocol (T1021.001)
    5. Data exfiltration to C2 server at 192.168.1.100 (T1041)
    
    The campaign used domain fronting techniques to evade detection.
    """
    
    try:
        # 1. LangChain Extractor
        extractor_config = get_full_agent_config("extractor")
        extractor_config["use_langchain"] = True
        extractor_config.setdefault("llm", {})["enabled"] = True
        # Ensure max_output_tokens is set if missing (optional)
        if "max_output_tokens" not in extractor_config["llm"]:
             extractor_config["llm"]["max_output_tokens"] = 2048
        
        extractor = LangChainExtractorAgent("langchain_extractor", extractor_config)
        await extractor.start()
        
        print("\n[1/3] Extracting TTPs with LangChain...")
        extractor_result = await extractor.execute({"text": sample_report})
        
        ttps = extractor_result.get("ttps", [])
        print(f"✓ Extracted {len(ttps)} TTPs (LangChain: {extractor.stats.get('langchain_extractions', 0)})")
        for ttp in ttps[:3]:
            print(f"  - {ttp.get('technique_id')}: {ttp.get('technique_name')}")
            print(f"    Confidence: {ttp.get('confidence_score', 0):.2f}")
        
        await extractor.stop()
        
        # 2. LangChain RuleGen
        rulegen_config = get_full_agent_config("rulegen")
        rulegen_config["use_langchain"] = True
        rulegen_config["use_feedback"] = True
        rulegen_config.setdefault("llm", {})["enabled"] = True
        
        rulegen = LangChainRuleGenAgent("langchain_rulegen", rulegen_config)
        await rulegen.start()
        
        print("\n[2/3] Generating Sigma rules with LangChain...")
        rulegen_result = await rulegen.execute({"ttps": ttps})
        
        rules = rulegen_result.get("rules", [])
        print(f"✓ Generated {len(rules)} rules (LangChain: {rulegen.stats.get('langchain_generations', 0)})")
        for rule in rules[:2]:
            print(f"  - {rule.get('title')}")
            print(f"    Method: {rule.get('generation_method')}")
        
        await rulegen.stop()
        
        # 3. LangChain Evaluator
        evaluator_config = get_full_agent_config("evaluator")
        evaluator_config["use_langchain"] = True
        evaluator_config.setdefault("llm", {})["enabled"] = True
        
        evaluator = LangChainEvaluatorAgent("langchain_evaluator", evaluator_config)
        await evaluator.start()
        
        print("\n[3/3] Evaluating rules with LangChain...")
        evaluator_result = await evaluator.execute({"rules": rules})
        
        summary = evaluator_result.get("summary", {})
        print(f"✓ Evaluated {summary.get('rules_evaluated', 0)} rules (LangChain: {evaluator.stats.get('langchain_evaluations', 0)})")
        print(f"  Average quality: {summary.get('average_quality_score', 0):.2f}")
        print(f"  Passing rules: {summary.get('passing_rules', 0)}/{summary.get('rules_evaluated', 0)}")
        
        # Show feedback
        feedback = evaluator_result.get("feedback", {})
        if feedback.get("actionable_suggestions"):
            print("\n  Feedback for RuleGen:")
            for suggestion in feedback["actionable_suggestions"][:3]:
                print(f"    • {suggestion}")
        
        await evaluator.stop()
        
        elapsed_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        print(f"\n✓ LangChain pipeline completed in {elapsed_ms:.0f}ms")
        
        return {
            "pipeline": "langchain",
            "ttps_extracted": len(ttps),
            "rules_generated": len(rules),
            "avg_quality": summary.get("average_quality_score", 0),
            "time_ms": elapsed_ms,
            "langchain_usage": {
                "extraction": extractor.stats.get("langchain_extractions", 0),
                "generation": rulegen.stats.get("langchain_generations", 0),
                "evaluation": evaluator.stats.get("langchain_evaluations", 0)
            }
        }
        
    except Exception as e:
        print(f"\n✗ LangChain pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return None


async def compare_pipelines():
    """Compare both pipelines"""
    print("\n" + "="*80)
    print("LANGCHAIN INTEGRATION COMPARISON TEST")
    print("="*80)
    print("Testing both traditional and LangChain-powered agent pipelines")
    
    # Run traditional pipeline
    traditional_result = await test_traditional_pipeline()
    
    # Run LangChain pipeline
    langchain_result = await test_langchain_pipeline()
    
    # Compare results
    print("\n" + "="*80)
    print("COMPARISON RESULTS")
    print("="*80)
    
    if traditional_result and langchain_result:
        print("\n┌─────────────────────────┬──────────────┬──────────────┐")
        print("│ Metric                  │ Traditional  │ LangChain    │")
        print("├─────────────────────────┼──────────────┼──────────────┤")
        print(f"│ TTPs Extracted          │ {traditional_result['ttps_extracted']:12} │ {langchain_result['ttps_extracted']:12} │")
        print(f"│ Rules Generated         │ {traditional_result['rules_generated']:12} │ {langchain_result['rules_generated']:12} │")
        print(f"│ Avg Quality Score       │ {traditional_result['avg_quality']:12.3f} │ {langchain_result['avg_quality']:12.3f} │")
        print(f"│ Processing Time (ms)    │ {traditional_result['time_ms']:12.0f} │ {langchain_result['time_ms']:12.0f} │")
        print("└─────────────────────────┴──────────────┴──────────────┘")
        
        if langchain_result.get("langchain_usage"):
            usage = langchain_result["langchain_usage"]
            print("\nLangChain Usage Breakdown:")
            print(f"  • Extraction: {usage['extraction']} LangChain calls")
            print(f"  • Generation: {usage['generation']} LangChain calls")
            print(f"  • Evaluation: {usage['evaluation']} LangChain calls")
        
        print("\nKey Benefits of LangChain Integration:")
        print("  ✓ Structured outputs with Pydantic validation")
        print("  ✓ Automatic output parsing (no manual JSON parsing)")
        print("  ✓ Better error handling with retry logic")
        print("  ✓ Metrics tracking built-in")
        print("  ✓ Feedback-aware prompts")
        print("  ✓ Consistent prompt templates")
        
    else:
        print("\n⚠ Could not complete comparison - one or both pipelines failed")
    
    print("\n" + "="*80)


async def main():
    """Main test function"""
    try:
        await compare_pipelines()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())