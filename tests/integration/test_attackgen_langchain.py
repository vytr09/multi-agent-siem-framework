#!/usr/bin/env python3
"""
Test LangChain AttackGen Agent
Uses configuration from config/agents.yaml
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
import os
from dotenv import load_dotenv
from agents.attackgen.langchain_agent import LangChainAttackGenAgent
from tests.conftest import get_full_agent_config

async def test_attackgen_langchain():
    print("="*80)
    print("TESTING LANGCHAIN ATTACKGEN AGENT")
    print("="*80)
    
    # Load environment variables
    load_dotenv()
    
    # Load configuration from agents.yaml
    config = get_full_agent_config("attackgen")
    
    if not config:
        print("[ERROR] attackgen configuration not found in agents.yaml")
        return
    
    llm_config = config.get("llm", {})
    print(f"[CONFIG] Using provider: {llm_config.get('provider', 'unknown')}")
    print(f"[CONFIG] Using model: {llm_config.get('model', 'unknown')}")
    
    # Initialize Agent
    agent = LangChainAttackGenAgent("test_agent", config)
    await agent.start()
    
    # VERIFICATION: Check if using real LLM
    if agent.langchain_enabled and agent.attack_chain:
        llm = agent.attack_chain.llm
        print(f"\n[VERIFICATION] Agent initialized with LLM: {type(llm).__name__}")
        if hasattr(llm, 'model'):
             print(f"[VERIFICATION] Model Name: {llm.model}")
        else:
             print(f"[VERIFICATION] Model Name: {getattr(llm, 'model_name', 'Unknown')}")
        
        print(f"[VERIFICATION] LLM type confirmed: {type(llm).__name__}")
    
    # Test Data
    test_ttps = [
        {
            "ttp_id": "T1059.001",
            "technique_name": "PowerShell",
            "technique_id": "T1059.001",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "confidence_score": 0.9
        }
    ]
    
    # Execute
    print("\nExecuting Attack Generation...")
    result = await agent.execute({"extracted_ttps": test_ttps})
    
    # Verify Results
    print("\nRESULTS:")
    print(f"Status: {result['status']}")
    
    if result['status'] == 'success':
        commands = result.get('attack_commands', [])
        print(f"Generated {len(commands)} commands")
        
        for i, cmd in enumerate(commands):
            print(f"\nCommand {i+1}:")
            print(f"  Name: {cmd['name']}")
            print(f"  Platform: {cmd['platform']}")
            print(f"  Command: {cmd['command']}")
            print(f"  Source: {cmd['source']}")
            
            # Validation
            if cmd['source'] != 'langchain':
                print("  [WARNING] Source is not langchain!")
            if not cmd.get('validated'):
                print("  [WARNING] Command not validated!")
    else:
        print(f"Error: {result.get('error')}")
        
    await agent.stop()

if __name__ == "__main__":
    asyncio.run(test_attackgen_langchain())