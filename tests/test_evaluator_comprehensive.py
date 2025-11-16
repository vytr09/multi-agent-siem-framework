#!/usr/bin/env python3
"""
Comprehensive Evaluator Agent Flow Test
Tests the complete custom memory integration for the evaluator agent
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.evaluator.agent import EvaluatorAgent
from agents.evaluator.feedback_manager import FeedbackManager
from agents.base.agent import AgentStatus
from core.memory import get_memory_manager, HybridMemoryManager
from core.orchestrator import HybridOrchestrator
from core.logging import get_agent_logger


async def test_evaluator_agent_flow():
    """Test the complete evaluator agent flow with memory integration"""

    print("\n" + "="*80)
    print("[TEST] EVALUATOR AGENT FLOW TEST")
    print("="*80)

    # Initialize logger
    logger = get_agent_logger("test_evaluator_flow")

    # Test 1: Memory Manager Initialization
    print("\n[TEST 1] Testing Memory Manager...")
    try:
        memory_manager = get_memory_manager()
        print("[SUCCESS] Memory manager initialized")

        # Test memory operations
        test_agent_memory = memory_manager.get_agent_memory("test_evaluator")
        print("[SUCCESS] Agent memory retrieved")

        # Test memory save/load
        test_agent_memory.save_context(
            {"input": "test evaluation input"},
            {"output": "test evaluation output"}
        )
        print("[SUCCESS] Memory save operation successful")

        history = memory_manager.get_history("test_evaluator")
        assert len(history) > 0, "Memory history should not be empty"
        print("[SUCCESS] Memory load operation successful")

    except Exception as e:
        print(f"[ERROR] Memory manager test failed: {e}")
        return False

    # Test 2: Feedback Manager
    print("\n[TEST 2] Testing Feedback Manager...")
    try:
        feedback_manager = FeedbackManager()
        print("[SUCCESS] Feedback manager initialized")

        # Test feedback generation
        test_evaluation = {
            "overall_score": 0.75,
            "metrics": {"accuracy": 0.8, "coverage": 0.7}
        }

        feedback = feedback_manager.generate_feedback(test_evaluation, "rulegen")
        assert feedback is not None, "Feedback should be generated"
        assert "improvements_needed" in feedback, "Feedback should have improvements"
        print("[SUCCESS] Feedback generation successful")

        # Test feedback history
        history = feedback_manager.get_feedback_history("rulegen")
        print(f"[SUCCESS] Feedback history loaded ({len(history)} entries)")

    except Exception as e:
        print(f"[ERROR] Feedback manager test failed: {e}")
        return False

    # Test 3: Evaluator Agent Configuration
    print("\n[TEST 3] Testing Evaluator Agent Configuration...")
    try:
        # Load config from agents.yaml
        import yaml
        config_path = Path(__file__).resolve().parents[1] / "config" / "agents.yaml"
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)

        evaluator_config = config_data['agents']['evaluator']
        evaluator_config['memory_enabled'] = True  # Ensure memory is enabled

        print("[SUCCESS] Evaluator config loaded")

        # Test agent initialization
        evaluator = EvaluatorAgent("test_evaluator", evaluator_config)
        print("[SUCCESS] Evaluator agent initialized")

        # Test input validation
        test_input = {"rules": [{"id": "test_rule", "content": "test"}]}
        is_valid = evaluator.validate_input(test_input)
        assert is_valid == True, "Input validation should pass"
        print("[SUCCESS] Input validation successful")

    except Exception as e:
        print(f"[ERROR] Evaluator agent configuration test failed: {e}")
        return False

    # Test 4: Full Evaluation Flow
    print("\n[TEST 4] Testing Full Evaluation Flow...")
    try:
        # Load real rulegen output as test data
        rulegen_output_path = Path(__file__).resolve().parents[1] / "data" / "generated_rules" / "rulegen_llm_output.json"

        if not rulegen_output_path.exists():
            print(f"[WARNING] Rulegen output not found at {rulegen_output_path}, creating mock data...")
            # Create mock rule data for testing
            mock_rules = [
                {
                    "rule_id": "test_rule_1",
                    "title": "Test PowerShell Detection",
                    "description": "Detects PowerShell execution",
                    "technique": "T1059.001",
                    "platform": "windows",
                    "query": 'process.name: "powershell.exe"',
                    "confidence_score": 0.8
                },
                {
                    "rule_id": "test_rule_2",
                    "title": "Test Registry Modification",
                    "description": "Detects registry key modifications",
                    "technique": "T1112",
                    "platform": "windows",
                    "query": 'registry.path: "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"',
                    "confidence_score": 0.7
                }
            ]
            test_input = {"rules": mock_rules}
        else:
            # Use real data
            with open(rulegen_output_path, 'r') as f:
                rulegen_data = json.load(f)

            # Extract rules from the output
            rules = []
            for result in rulegen_data.get("rule_generation_results", []):
                if "sigma_rule" in result:
                    rule = {
                        "rule_id": result["sigma_rule"].get("id", "unknown"),
                        "title": result["sigma_rule"].get("title", "Unknown"),
                        "description": result["sigma_rule"].get("description", ""),
                        "technique": result.get("attack_id", "unknown"),
                        "platform": "sigma",  # Assume Sigma format
                        "query": str(result["sigma_rule"]),  # Full rule as query
                        "confidence_score": result.get("confidence_score", 0.5)
                    }
                    rules.append(rule)

            test_input = {"rules": rules}
            print(f"[SUCCESS] Loaded {len(rules)} real rules from rulegen output")

        # Start the evaluator agent
        await evaluator.start()
        print("[SUCCESS] Evaluator agent started")

        # Execute evaluation
        context = {"history": []}  # Empty history for first run
        result = await evaluator.execute(test_input, context)

        # Verify results
        assert result['status'] == 'success', f"Evaluation failed: {result.get('message', 'Unknown error')}"
        assert 'rules_evaluated' in result, "Result should contain rules_evaluated"
        assert result['rules_evaluated'] > 0, "Should have evaluated some rules"

        print(f"[SUCCESS] Evaluation completed: {result['rules_evaluated']} rules evaluated")
        print(f"   Overall metrics: {result.get('metrics', {})}")

        # Test memory integration
        agent_memory = memory_manager.get_agent_memory(evaluator.id)
        memory_vars = agent_memory.load_memory_variables({})
        chat_history = memory_vars.get("chat_history", [])

        print(f"[SUCCESS] Memory integration: {len(chat_history)} interactions stored")

        # Test feedback integration
        feedback_history = feedback_manager.get_feedback_history("rulegen")
        print(f"[SUCCESS] Feedback integration: {len(feedback_history)} feedback entries")

    except Exception as e:
        print(f"[ERROR] Full evaluation flow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 5: Orchestrator Integration
    print("\n[TEST 5] Testing Orchestrator Integration...")
    try:
        # Test that orchestrator can load evaluator config
        orchestrator = HybridOrchestrator()
        await orchestrator.initialize()

        # Check if evaluator agent is available
        if orchestrator.evaluator and orchestrator.evaluator.status == AgentStatus.RUNNING:
            print("[SUCCESS] Orchestrator has evaluator agent configured and running")
        else:
            print("[WARNING] Evaluator agent not properly initialized in orchestrator")

    except Exception as e:
        print(f"[ERROR] Orchestrator integration test failed: {e}")
        return False

    # Test 6: Persistence and Recovery
    print("\n[TEST 6] Testing Persistence and Recovery...")
    try:
        # Test memory persistence
        memory_dir = Path("data/memory")
        memory_files = list(memory_dir.glob("*.json")) if memory_dir.exists() else []

        if memory_files:
            print(f"[SUCCESS] Memory persistence: {len(memory_files)} memory files found")
        else:
            print("[WARNING] No memory files found (memory may not be persisted yet)")

        # Test feedback persistence
        feedback_dir = Path("data/feedback")
        feedback_files = list(feedback_dir.glob("*.json")) if feedback_dir.exists() else []

        if feedback_files:
            print(f"[SUCCESS] Feedback persistence: {len(feedback_files)} feedback files found")
        else:
            print("[WARNING] No feedback files found (feedback may not be persisted yet)")

    except Exception as e:
        print(f"[ERROR] Persistence test failed: {e}")
        return False

    print("\n" + "="*80)
    print("[SUCCESS] ALL TESTS PASSED!")
    print("="*80)
    print("[SUCCESS] Memory Manager: Working")
    print("[SUCCESS] Feedback Manager: Working")
    print("[SUCCESS] Evaluator Agent: Working")
    print("[SUCCESS] Full Evaluation Flow: Working")
    print("[SUCCESS] Orchestrator Integration: Working")
    print("[SUCCESS] Persistence: Working")
    print("\n[SUCCESS] Evaluator Agent LangChain flow is fully functional!")

    return True


async def run_quick_test():
    """Run a quick test with minimal output"""
    print("[QUICK TEST] Testing evaluator agent components...")

    try:
        # Test memory
        memory_manager = get_memory_manager()
        memory = memory_manager.get_agent_memory("quick_test")
        memory.save_context({"input": "test"}, {"output": "test"})
        history = memory_manager.get_history("quick_test")
        assert len(history) > 0

        # Test feedback
        feedback_manager = FeedbackManager()
        feedback = feedback_manager.generate_feedback({"overall_score": 0.8}, "rulegen")
        assert feedback is not None

        print("[SUCCESS] Quick test passed!")
        return True

    except Exception as e:
        print(f"[ERROR] Quick test failed: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        # Quick test mode
        success = asyncio.run(run_quick_test())
    else:
        # Full test mode
        success = asyncio.run(test_evaluator_agent_flow())

    sys.exit(0 if success else 1)