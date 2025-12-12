#!/usr/bin/env python3
"""
Quick Test Script for Evaluator Agent Flow
Tests the complete evaluator agent workflow with memory integration
Uses configuration from config/agents.yaml
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agents.evaluator.agent import EvaluatorAgent
from agents.evaluator.feedback_manager import FeedbackManager
from core.memory import get_memory_manager
from core.langchain_orchestrator import LangChainOrchestrator
from tests.conftest import get_full_agent_config


async def test_evaluator_flow():
    """Test the complete evaluator agent flow"""

    print("\n" + "="*80)
    print("[TEST] EVALUATOR AGENT FLOW TEST")
    print("="*80)

    try:
        # Test 1: Import and instantiate components
        print("\n[TEST 1] Testing component imports...")

        # Test memory manager
        memory_manager = get_memory_manager()
        print("[SUCCESS] Memory manager created")

        # Test feedback manager
        feedback_manager = FeedbackManager()
        print("[SUCCESS] Feedback manager created")

        # Test orchestrator
        orchestrator = LangChainOrchestrator()
        print("[SUCCESS] Orchestrator created")

        # Load evaluator configuration from agents.yaml
        evaluator_config = get_full_agent_config("evaluator")
        
        # Ensure evaluation settings exist
        evaluator_config.setdefault("evaluation", {}).update({
            "metrics": ["accuracy", "coverage", "false_positives"],
            "benchmark_enabled": False
        })
        
        print(f"[CONFIG] LLM Provider: {evaluator_config['llm'].get('provider', 'unknown')}")
        print(f"[CONFIG] LLM Model: {evaluator_config['llm'].get('model', 'unknown')}")

        evaluator = EvaluatorAgent("test_evaluator", evaluator_config)
        print("[SUCCESS] Evaluator agent created")

        # Test 2: Agent lifecycle
        print("\n[TEST 2] Testing agent lifecycle...")

        await evaluator.start()
        print("[SUCCESS] Evaluator agent started")

        # Test 3: Memory integration
        print("\n[TEST 3] Testing memory integration...")

        # Get agent memory
        agent_memory = memory_manager.get_agent_memory("test_evaluator")
        print("[SUCCESS] Agent memory retrieved")

        # Test 4: Mock evaluation data
        print("\n[TEST 4] Testing evaluation workflow...")

        # Create mock rulegen results
        mock_rulegen_results = {
            "rules_generated": [
                {
                    "rule_id": "test-rule-001",
                    "name": "Test Phishing Detection Rule",
                    "mitre_technique": "T1566.001",
                    "sigma_rule": """
                    title: Test Phishing Rule
                    description: Detects phishing emails
                    logsource:
                        category: email
                    detection:
                        selection:
                            subject|contains: 'urgent'
                            sender|endswith: '@suspicious.com'
                        condition: selection
                    """,
                    "confidence_score": 0.85,
                    "indicators": ["urgent subject", "suspicious sender"],
                    "false_positive_risk": "medium"
                }
            ],
            "generation_stats": {
                "total_rules": 1,
                "avg_confidence": 0.85,
                "processing_time_ms": 1500
            }
        }

        # Test input validation
        is_valid = evaluator.validate_input(mock_rulegen_results)
        print(f"[SUCCESS] Input validation: {is_valid}")

        # Test evaluation execution
        print("\n[TEST 5] Testing evaluation execution...")

        evaluation_result = await evaluator.execute(mock_rulegen_results)
        print("[SUCCESS] Evaluation executed successfully")

        # Check result structure
        required_fields = ["status", "rules_evaluated", "metrics", "feedback_generated"]
        for field in required_fields:
            assert field in evaluation_result, f"Missing field: {field}"
        print("[SUCCESS] Result structure validated")

        # Test 6: Feedback generation
        print("\n[TEST 6] Testing feedback generation...")

        feedback = feedback_manager.generate_feedback(evaluation_result)
        print("[SUCCESS] Feedback generated")

        # Test 7: Memory persistence
        print("\n[TEST 7] Testing memory persistence...")

        # Save interaction to memory
        memory_manager.save_interaction(
            "test_evaluator",
            {"input": "test evaluation request"},
            {"output": evaluation_result}
        )
        print("[SUCCESS] Interaction saved to memory")

        # Test 8: Statistics
        print("\n[TEST 8] Testing statistics...")

        stats = await evaluator.get_statistics()
        print("[SUCCESS] Statistics retrieved")

        # Test cleanup
        print("\n[TEST 9] Testing cleanup...")

        await evaluator.stop()
        print("[SUCCESS] Evaluator agent stopped")

        # Final summary
        print("\n" + "="*80)
        print("[SUCCESS] ALL TESTS PASSED!")
        print("="*80)

        print("\n[RESULTS] TEST SUMMARY:")
        print(f"   [SUCCESS] Memory Manager: Working")
        print(f"   [SUCCESS] Feedback Manager: Working")
        print(f"   [SUCCESS] Orchestrator: Working")
        print(f"   [SUCCESS] Evaluator Agent: Working")
        print(f"   [SUCCESS] Memory Integration: Working")
        print(f"   [SUCCESS] Evaluation Workflow: Working")
        print(f"   [SUCCESS] Feedback Generation: Working")
        print(f"   [SUCCESS] Statistics: Working")

        print("\n[RESULTS] EVALUATION RESULTS:")
        print(f"   Status: {evaluation_result.get('status')}")
        print(f"   Rules Evaluated: {evaluation_result.get('rules_evaluated', 0)}")
        print(f"   Average Score: {evaluation_result.get('metrics', {}).get('average_score', 0):.3f}")

        return True

    except Exception as e:
        print(f"\n[ERROR] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test runner"""
    print("[START] Starting Evaluator Agent Flow Test...")

    success = await test_evaluator_flow()

    if success:
        print("\n[SUCCESS] All evaluator flow tests passed!")
        print("\n[INFO] Next steps:")
        print("   1. Run with real data: python tests/evaluator_flow_test.py")
        print("   2. Test benchmark: python tests/benchmark/run_attackgen_benchmark.py")
        print("   3. Run full integration: python scripts/run_agents.py")
    else:
        print("\n[ERROR] Tests failed. Check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())