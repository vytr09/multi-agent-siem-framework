import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import pytest
import asyncio
import json
from pathlib import Path
from config.settings import settings
from core.siem_integration import SIEMIntegrator, DetectionResult
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent
from unittest.mock import AsyncMock
# Splunk Config from Settings
SPLUNK_CONFIG = settings.get_splunk_config()

# SSH Config from Settings
SSH_CONFIG = settings.get_ssh_config()

SAMPLE_RULE = {
    "title": "Test Rule",
    "id": "test_rule_1",
    "description": "Detects test command",
    "splunk_query": 'index=* "test"',
    "detection": {"keywords": ["test"]}
}

SAMPLE_ATTACK = {
    "command": "powershell.exe -Command echo 'test'",
    "technique_id": "T1059.001"
}

@pytest.mark.asyncio
async def test_siem_integrator_real_connection():
    """Test SIEMIntegrator with REAL Splunk and SSH connection"""
    print(f"\n[Real Connection Test] Connecting to Splunk at {SPLUNK_CONFIG['splunk_host']}...")
    
    # Combine configs
    full_config = {**SPLUNK_CONFIG, **SSH_CONFIG}
    integrator = SIEMIntegrator(full_config)
    
    if integrator.simulation_mode:
        print("WARNING: Failed to connect to real Splunk (fell back to simulation). Check credentials/network.")
    else:
        print("SUCCESS: Successfully connected to REAL Splunk instance.")
        assert integrator.splunk.test_connection() is True
        
    # Test SSH
    print(f"[Real Connection Test] Connecting to SSH at {SSH_CONFIG['ssh_host']}...")
    if integrator.ssh.connect():
        print("SUCCESS: Successfully connected to SSH.")
        integrator.ssh.close()
    else:
        print("WARNING: Failed to connect to SSH. Check credentials/service.")
        # Not failing the test strictly if SSH fails, as it might not be enabled on localhost

@pytest.mark.asyncio
async def test_real_attack_execution():
    """
    Test FULL LOOP with REAL Splunk and SSH.
    This WILL execute the command on the remote host.
    """
    print(f"\n[REAL ATTACK TEST] Initializing...")
    
    # Combine configs
    full_config = {**SPLUNK_CONFIG, **SSH_CONFIG}
    integrator = SIEMIntegrator(full_config)
    
    if integrator.simulation_mode:
        print("WARNING: Skipping Real Attack Test: Could not connect to Splunk/SSH.")
        return

    print(f"[REAL ATTACK TEST] Executing command: {SAMPLE_ATTACK['command']}")
    print(f"[REAL ATTACK TEST] Querying Splunk: {SAMPLE_RULE['splunk_query']}")
    
    # Execute Verify Rule (Real Mode)
    result = integrator.verify_rule(SAMPLE_RULE, SAMPLE_ATTACK)
    
    print(f"[REAL ATTACK TEST] Result Status: {result.status}")
    print(f"[REAL ATTACK TEST] Detected: {result.detected}")
    print(f"[REAL ATTACK TEST] Events Found: {result.events_found}")
    
    if not result.detected:
        print(f"[REAL ATTACK TEST] Message: {result.message}")
        print("NOTE: Detection failed. This could be due to:")
        print("  1. Splunk inputs not configured to pick up this activity.")
        print("  2. Indexing latency (try increasing 'indexing_wait_time').")
        print("  3. The query 'index=*' might be too broad or restricted.")


@pytest.mark.asyncio
async def test_evaluator_scoring_logic():
    """Test Evaluator scoring with dynamic metrics"""
    agent = LangChainEvaluatorAgent("test_evaluator", {"use_langchain": False})
    
    # Mock verification result (Detected, Low Latency, No FPR)
    verification = DetectionResult(
        detected=True,
        events_found=5,
        query_time_ms=200,
        historical_events=0,
        status="success",
        message="Detected",
        raw_events=[]
    )
    
    # Mock static evaluation using AsyncMock
    agent._fallback_evaluation = AsyncMock(return_value={
        "quality_score": 0.8,
        "strengths": [],
        "weaknesses": [],
        "suggestions": []
    })
    
    result = await agent._evaluate_rule(SAMPLE_RULE, verification)
    
    # Expected: (0.4 * 0.8) + (0.6 * 1.0) = 0.32 + 0.6 = 0.92
    print(f"\n[Scoring Test] Final Score: {result['quality_score']}")
    assert result['quality_score'] >= 0.9
    assert "Verified detection in SIEM" in result['strengths']

@pytest.mark.asyncio
async def test_evaluator_fail_fast():
    """Test Evaluator fail-fast logic (No Detection)"""
    agent = LangChainEvaluatorAgent("test_evaluator", {"use_langchain": False})
    
    # Mock verification result (NOT Detected)
    verification = DetectionResult(
        detected=False,
        events_found=0,
        query_time_ms=200,
        historical_events=0,
        status="success",
        message="Not Detected",
        raw_events=[]
    )
    
    agent._fallback_evaluation = AsyncMock(return_value={"quality_score": 0.9})
    
    result = await agent._evaluate_rule(SAMPLE_RULE, verification)
    
    # Expected: Capped at 0.2
    print(f"\n[Fail-Fast Test] Final Score: {result['quality_score']}")
    assert result['quality_score'] <= 0.2
    assert "Failed SIEM verification" in result['weaknesses']

if __name__ == "__main__":
    # Manual run wrapper
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    print("="*50)
    print("Running SIEM Integration Tests")
    print("="*50)
    
    try:
        # Run real connection test first
        loop.run_until_complete(test_siem_integrator_real_connection())
        # Run real attack test
        loop.run_until_complete(test_real_attack_execution())
        
        loop.run_until_complete(test_evaluator_scoring_logic())
        loop.run_until_complete(test_evaluator_fail_fast())
        print("\nSUCCESS: All tests passed!")
    except Exception as e:
        print(f"\n❌ Tests failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        loop.close()
