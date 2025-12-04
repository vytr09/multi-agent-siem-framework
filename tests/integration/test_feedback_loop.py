#!/usr/bin/env python3
"""
Test Feedback Loop Without SIEM Integration
Tests the complete feedback loop: RuleGen -> Evaluator -> Feedback -> RuleGen (iterative)
Uses configuration from config/agents.yaml
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, Any

from core.orchestrator import HybridOrchestrator
from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.evaluator.agent import EvaluatorAgent
from agents.evaluator.feedback_manager import FeedbackManager
from tests.conftest import get_full_agent_config

async def test_feedback_loop():
    """Test the feedback loop with simulated data"""

    print("="*100)
    print("TESTING FEEDBACK LOOP WITHOUT SIEM INTEGRATION")
    print("="*100)

    # Load test data
    repo_root = Path(__file__).resolve().parents[2]
    base_path = Path(os.getenv("TEST_DATA_ROOT", repo_root))
    data_path = base_path / "data" / "extracted" / "hybrid_extraction_results.json"

    if not data_path.exists():
        print(f"[ERROR] Test data not found: {data_path}")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        extraction_data = json.load(f)

    hybrid_data = extraction_data.get('hybrid', {})

    # Load configurations from agents.yaml
    rulegen_agent_config = get_full_agent_config("rulegen")
    evaluator_agent_config = get_full_agent_config("evaluator")
    
    # Build rulegen config with loaded LLM settings
    rulegen_config = {
        'platforms': ['splunk', 'elasticsearch'],
        'optimize_rules': True,
        'validate_rules': True,
        'min_confidence_threshold': 0.7,
        'use_feedback': True,
        'llm': rulegen_agent_config.get('llm', {}),
        'sigma': rulegen_agent_config.get('sigma', {}),
        'optimizer': {},
        'splunk': {},
        'elasticsearch': {}
    }

    # Build evaluator config with loaded LLM settings
    evaluator_config = {
        'platforms': ['splunk', 'elasticsearch'],
        'benchmark': evaluator_agent_config.get('benchmark', {})
    }
    
    print(f"[CONFIG] RuleGen LLM: {rulegen_config['llm'].get('provider', 'unknown')} / {rulegen_config['llm'].get('model', 'unknown')}")
    print(f"[CONFIG] Evaluator LLM: {evaluator_config['benchmark'].get('llm_judge', {}).get('provider', 'unknown')}")

    # Create orchestrator config
    orchestrator_config = {
        'agents': {
            'rulegen': rulegen_config,
            'evaluator': evaluator_config
        },
        'feedback': {
            'max_iterations': 3,
            'minimum_score': 0.8
        }
    }

    # Save config temporarily
    config_path = repo_root / "config" / "test_feedback_config.yaml"
    import yaml
    with open(config_path, 'w') as f:
        yaml.dump(orchestrator_config, f)

    orchestrator = None
    try:
        print("   • Initializing RuleGen agent...")
        rulegen = RuleGenerationAgentWithLLM("rulegen", rulegen_config)
        await rulegen.initialize()
        
        print("   • Initializing Evaluator agent...")
        evaluator = EvaluatorAgent("evaluator", evaluator_config)
        await evaluator.start()
        
        # Create a simple test orchestrator
        class TestOrchestrator:
            def __init__(self, rulegen, evaluator, config):
                self.rulegen = rulegen
                self.evaluator = evaluator
                self.config = config
                self.output_dir = Path("data/output/")
                self.output_dir.mkdir(parents=True, exist_ok=True)
            
            async def run_test_pipeline(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
                """Run test pipeline with pre-extracted data"""
                print("   • Running test pipeline with pre-extracted data...")
                
                # Stage 1: Generate Rules
                print("   • Stage 1: Generating rules...")
                rulegen_result = await self.rulegen.process(extraction_data)
                
                if rulegen_result['status'] != 'success':
                    return rulegen_result
                
                # Write rulegen output
                rulegen_file = self.output_dir / 'rulegen' / 'generated_rules.json'
                rulegen_file.parent.mkdir(parents=True, exist_ok=True)
                with open(rulegen_file, 'w') as f:
                    json.dump(rulegen_result, f, indent=2)
                
                # Stage 2: Evaluate Rules
                print("   • Stage 2: Evaluating rules...")
                rules_to_evaluate = rulegen_result.get('rule_generation_results', [])
                evaluation_result = await self.evaluator.execute({
                    'rules': rules_to_evaluate
                })
                
                # Check if feedback loop needed
                score = evaluation_result.get('metrics', {}).get('average_score', 0)
                iteration = 1
                max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
                min_score = self.config.get('feedback', {}).get('minimum_score', 0.8)
                
                while score < min_score and iteration < max_iterations:
                    print(f"   • Score {score:.3f} < {min_score}, re-running (iteration {iteration+1})...")
                    rulegen_result = await self.rulegen.process(extraction_data)
                    rules_to_evaluate = rulegen_result.get('rule_generation_results', [])
                    evaluation_result = await self.evaluator.execute({'rules': rules_to_evaluate})
                    score = evaluation_result.get('metrics', {}).get('average_score', 0)
                    iteration += 1
                
                print(f"   • Test pipeline completed (final score: {score:.3f}, iterations: {iteration})")
                
                return {
                    'status': 'success',
                    'rules': rulegen_result,
                    'evaluation': evaluation_result,
                    'iterations': iteration,
                    'final_score': score
                }
            
            async def cleanup(self):
                await self.rulegen.shutdown()
                await self.evaluator.stop()
        
        orchestrator = TestOrchestrator(rulegen, evaluator, orchestrator_config)

        print("\n[START] Starting feedback loop test...")
        print("   • Max iterations: 3")
        print("   • Minimum score threshold: 0.8")
        print("   • Feedback enabled: Yes")

        result = await orchestrator.run_test_pipeline(hybrid_data)

        print("\n" + "="*100)
        print("FEEDBACK LOOP TEST COMPLETE")
        print("="*100)

        print(f"\n[RESULTS] Results:")
        print(f"   • Status: {result['status']}")
        print(f"   • Final Score: {result.get('final_score', 'N/A')}")
        print(f"   • Iterations: {result.get('iterations', 1)}")

        if 'evaluation' in result:
            eval_result = result['evaluation']
            if 'metrics' in eval_result:
                metrics = eval_result['metrics']
                print(f"   • Average Score: {metrics.get('average_score', 'N/A')}")
                print(f"   • Rules Evaluated: {metrics.get('total_rules', 'N/A')}")

        # Check feedback history
        feedback_manager = FeedbackManager()
        feedback_history = feedback_manager.get_feedback_history("rulegen")
        print(f"   • Feedback Entries: {len(feedback_history)}")

        # Save test results
        output_dir = repo_root / "data" / "benchmark_results"
        output_dir.mkdir(parents=True, exist_ok=True)

        test_result = {
            'test_type': 'feedback_loop_test',
            'timestamp': result.get('timestamp', ''),
            'iterations': result.get('iterations', 1),
            'final_score': result.get('final_score', 0),
            'feedback_applied': len(feedback_history) > 0,
            'evaluation_metrics': result.get('evaluation', {}).get('metrics', {}),
            'rule_generation_summary': result.get('rules', {}).get('summary', {})
        }

        output_path = output_dir / "feedback_loop_test_results.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(test_result, f, indent=2, ensure_ascii=False)

        print(f"\n[OUTPUT] Test results saved to: {output_path}")

    finally:
        if orchestrator:
            await orchestrator.cleanup()
        if config_path.exists():
            config_path.unlink()

if __name__ == "__main__":
    asyncio.run(test_feedback_loop())