"""
Verification script for RuleGen Refactoring
Tests both LangChainRuleGenAgent and RuleGenerationAgentWithLLM
"""


import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import os
import json
from pathlib import Path
from dotenv import load_dotenv

from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from tests.utils import get_full_agent_config

# Load environment variables
load_dotenv()

async def test_refactoring():
    print("\n" + "="*80)
    print("VERIFYING RULEGEN REFACTORING")
    print("="*80)
    
    # Sample TTP Data
    sample_data = {
        "extraction_results": [{
            "extracted_ttps": [{
                "ttp_id": "T1059.001",
                "attack_id": "T1059.001",
                "technique_name": "PowerShell",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "confidence_score": 0.9,
                "tools": ["powershell.exe"],
                "iocs": {
                    "command_line": ["-encodedCommand"]
                }
            }]
        }]
    }
    
    config = get_full_agent_config("rulegen")
    config['optimize_rules'] = True
    config['validate_rules'] = True
    # config['min_confidence_threshold'] = 0.7 # Already in yaml?
    config.setdefault('llm', {})['enabled'] = True
    
    # 1. Test RuleGenerationAgentWithLLM (Traditional)
    print("\n1. Testing RuleGenerationAgentWithLLM (Traditional)...")
    try:
        agent_trad = RuleGenerationAgentWithLLM("test_trad", config)
        await agent_trad.start()
        result_trad = await agent_trad.execute(sample_data)
        
        if result_trad['status'] == 'success':
            print("   [SUCCESS] Traditional agent execution successful")
            print(f"   Generated {result_trad['summary']['total_rules_generated']} rules")
            # Check if platform rules exist
            if result_trad['rule_generation_results'][0]['platform_rules']['splunk']['status'] == 'success':
                print("   [SUCCESS] Splunk conversion successful")
            else:
                print("   [FAILED] Splunk conversion failed")
        else:
            print(f"   [FAILED] Traditional agent execution failed: {result_trad.get('error')}")
            
        await agent_trad.stop()
    except Exception as e:
        print(f"   [ERROR] Traditional agent test crashed: {e}")

    # 2. Test LangChainRuleGenAgent (LangChain)
    print("\n2. Testing LangChainRuleGenAgent (LangChain)...")
    try:
        agent_lc = LangChainRuleGenAgent("test_lc", config)
        await agent_lc.start()
        result_lc = await agent_lc.execute(sample_data)
        
        if result_lc['status'] == 'success':
            print("   [SUCCESS] LangChain agent execution successful")
            print(f"   Generated {result_lc['summary']['total_rules_generated']} rules")
            
            # Verify optimization and conversion (New features!)
            rule_result = result_lc['rule_generation_results'][0]
            
            if rule_result['metadata']['optimized']:
                print("   [SUCCESS] Optimization applied")
            else:
                print("   [FAILED] Optimization NOT applied")
                
            if rule_result['platform_rules']['splunk']['status'] == 'success':
                print("   [SUCCESS] Splunk conversion successful")
            else:
                print("   [FAILED] Splunk conversion failed")
        else:
            print(f"   [FAILED] LangChain agent execution failed: {result_lc.get('error')}")
            
        await agent_lc.stop()
    except Exception as e:
        print(f"   [ERROR] LangChain agent test crashed: {e}")

if __name__ == "__main__":
    asyncio.run(test_refactoring())