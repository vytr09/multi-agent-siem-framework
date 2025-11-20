#!/usr/bin/env python3
"""
Test LangChain Replacement - Memory System Integration Test
Tests that our custom memory implementation works correctly
"""


import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.memory import get_memory_manager, HybridMemoryManager
from agents.evaluator.feedback_manager import FeedbackManager
from core.logging import get_agent_logger


async def test_memory_system():
    """Test the complete memory system integration"""

    print("\n" + "="*80)
    print("[TEST] MEMORY SYSTEM INTEGRATION TEST")
    print("="*80)

    # Test 1: Memory Manager Initialization
    print("\n[TEST 1] Testing Memory Manager...")
    try:
        memory_manager = get_memory_manager()
        print("[SUCCESS] Memory manager initialized")

        # Test agent memory creation
        agent_memory = memory_manager.get_agent_memory("test_agent")
        print("[SUCCESS] Agent memory created")

        # Test memory operations
        agent_memory.save_context(
            {"input": "test input 1"},
            {"output": "test output 1"}
        )
        print("[SUCCESS] Memory save operation successful")

        # Test memory retrieval
        variables = agent_memory.load_memory_variables({})
        chat_history = variables.get("chat_history", [])
        assert len(chat_history) > 0, "Chat history should not be empty"
        print("[SUCCESS] Memory retrieval successful")

    except Exception as e:
        print(f"[ERROR] Memory manager test failed: {e}")
        return False

    # Test 2: Memory Persistence
    print("\n[TEST 2] Testing Memory Persistence...")
    try:
        # Save interaction through manager
        memory_manager.save_interaction(
            "test_agent",
            {"action": "test_action", "data": "test_data"},
            {"result": "success", "score": 0.85}
        )
        print("[SUCCESS] Memory persistence successful")

        # Test history retrieval
        history = memory_manager.get_history("test_agent")
        assert len(history) > 0, "History should not be empty"
        print("[SUCCESS] History retrieval successful")

        # Verify file was created
        memory_file = Path("data/memory/test_agent_memory.json")
        assert memory_file.exists(), "Memory file should exist"
        print("[SUCCESS] Memory file persistence verified")

    except Exception as e:
        print(f"[ERROR] Memory persistence test failed: {e}")
        return False

    # Test 3: Feedback Manager Integration
    print("\n[TEST 3] Testing Feedback Manager Integration...")
    try:
        feedback_manager = FeedbackManager()
        print("[SUCCESS] Feedback manager initialized")

        # Test feedback generation
        test_evaluation = {
            "overall_score": 0.75,
            "metrics": {
                "accuracy": 0.8,
                "coverage": 0.7,
                "performance": 0.6
            }
        }

        feedback = feedback_manager.generate_feedback(test_evaluation, "test_agent")
        assert feedback is not None, "Feedback should be generated"
        assert "improvements_needed" in feedback, "Feedback should have improvements"
        print("[SUCCESS] Feedback generation successful")

        # Write feedback to file (this is what actually persists it)
        feedback_manager.write_feedback("test_agent", feedback)
        print("[SUCCESS] Feedback persistence successful")

        # Test feedback history
        history = feedback_manager.get_feedback_history("test_agent")
        assert len(history) > 0, "Feedback history should not be empty"
        print("[SUCCESS] Feedback history retrieval successful")

        # Verify feedback file was created
        feedback_file = Path("data/feedback/test_agent_feedback.json")
        assert feedback_file.exists(), "Feedback file should exist"
        print("[SUCCESS] Feedback file persistence verified")

    except Exception as e:
        print(f"[ERROR] Feedback manager test failed: {e}")
        return False

    # Test 4: Memory Window Functionality
    print("\n[TEST 4] Testing Memory Window Functionality...")
    try:
        # Test windowed memory in feedback manager
        feedback_memory = feedback_manager.feedback_memory

        # Add multiple feedbacks to test windowing
        for i in range(7):  # More than window size of 5
            test_eval = {
                "overall_score": 0.7 + (i * 0.02),
                "metrics": {"accuracy": 0.8}
            }
            feedback = feedback_manager.generate_feedback(test_eval, "window_test")
            feedback_manager.write_feedback("window_test", feedback)

        # Check that only last 5 are kept in memory
        memory_vars = feedback_memory.load_memory_variables({})
        messages = memory_vars.get("feedback_history", [])
        # Should be 10 messages (5 pairs of input/output)
        assert len(messages) == 10, f"Expected 10 messages, got {len(messages)}"
        print("[SUCCESS] Memory windowing working correctly")

    except Exception as e:
        print(f"[ERROR] Memory window test failed: {e}")
        return False

    # Test 5: Cross-Agent Memory Isolation
    print("\n[TEST 5] Testing Cross-Agent Memory Isolation...")
    try:
        # Create memories for different agents
        agent1_memory = memory_manager.get_agent_memory("agent1")
        agent2_memory = memory_manager.get_agent_memory("agent2")

        # Save different data
        agent1_memory.save_context(
            {"input": "agent1 input"},
            {"output": "agent1 output"}
        )
        agent2_memory.save_context(
            {"input": "agent2 input"},
            {"output": "agent2 output"}
        )

        # Verify isolation
        agent1_vars = agent1_memory.load_memory_variables({})
        agent2_vars = agent2_memory.load_memory_variables({})

        agent1_history = agent1_vars.get("chat_history", [])
        agent2_history = agent2_vars.get("chat_history", [])

        assert len(agent1_history) == 2, "Agent1 should have 2 messages"
        assert len(agent2_history) == 2, "Agent2 should have 2 messages"

        # Check content isolation
        agent1_content = agent1_history[0].get("content", "")
        agent2_content = agent2_history[0].get("content", "")
        assert "agent1" in agent1_content, "Agent1 memory should contain agent1 data"
        assert "agent2" in agent2_content, "Agent2 memory should contain agent2 data"

        print("[SUCCESS] Cross-agent memory isolation verified")

    except Exception as e:
        print(f"[ERROR] Memory isolation test failed: {e}")
        return False

    # Test 6: Memory Cleanup
    print("\n[TEST 6] Testing Memory Cleanup...")
    try:
        # Clear agent memory
        memory_manager.clear_agent_memory("test_agent")

        # Verify cleanup
        test_agent_memory = memory_manager.get_agent_memory("test_agent")
        test_vars = test_agent_memory.load_memory_variables({})
        test_history = test_vars.get("chat_history", [])
        assert len(test_history) == 0, "Memory should be empty after cleanup"

        # Verify file was deleted
        memory_file = Path("data/memory/test_agent_memory.json")
        assert not memory_file.exists(), "Memory file should be deleted"

        print("[SUCCESS] Memory cleanup successful")

    except Exception as e:
        print(f"[ERROR] Memory cleanup test failed: {e}")
        return False

    print("\n" + "="*80)
    print("[SUCCESS] ALL MEMORY SYSTEM TESTS PASSED!")
    print("="*80)
    print("[SUCCESS] Memory Manager: Working")
    print("[SUCCESS] Memory Persistence: Working")
    print("[SUCCESS] Feedback Integration: Working")
    print("[SUCCESS] Memory Windowing: Working")
    print("[SUCCESS] Agent Isolation: Working")
    print("[SUCCESS] Memory Cleanup: Working")
    print("\n[SUCCESS] Custom Memory System is fully functional!")
    print("   (LangChain replacement working correctly)")

    return True


async def test_langchain_comparison():
    """Compare our custom memory with what LangChain would provide"""

    print("\n" + "="*80)
    print("[COMPARISON] CUSTOM MEMORY VS LANGCHAIN")
    print("="*80)

    try:
        # Test our custom memory
        memory_manager = get_memory_manager()
        custom_memory = memory_manager.get_agent_memory("comparison_test")

        # Simulate LangChain-like usage
        custom_memory.save_context(
            {"input": "What is the capital of France?"},
            {"output": "The capital of France is Paris."}
        )

        custom_memory.save_context(
            {"input": "What about Germany?"},
            {"output": "The capital of Germany is Berlin."}
        )

        # Get memory variables (like LangChain does)
        variables = custom_memory.load_memory_variables({})
        messages = variables.get("chat_history", [])

        print(f"[SUCCESS] Custom memory stored {len(messages)} messages")

        # Show message structure
        for i, msg in enumerate(messages):
            msg_type = msg.get("type", "Unknown")
            content = msg.get("content", "")[:50]
            print(f"   {i+1}. {msg_type}: {content}...")

        # Test persistence
        memory_manager.save_interaction(
            "comparison_test",
            {"query": "test query"},
            {"response": "test response"}
        )

        print("[SUCCESS] Custom memory persistence working")

        return True

    except Exception as e:
        print(f"[ERROR] Comparison test failed: {e}")
        return False


if __name__ == "__main__":
    async def main():
        # Run comprehensive memory test
        success1 = await test_memory_system()

        # Run comparison test
        success2 = await test_langchain_comparison()

        if success1 and success2:
            print("\n[RESULT] RESULT: Custom memory system is working perfectly!")
            print("   LangChain replacement is successful and fully functional.")
        else:
            print("\n[ERROR] RESULT: Memory system has issues that need fixing.")
            sys.exit(1)

    asyncio.run(main())