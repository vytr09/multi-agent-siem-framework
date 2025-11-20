"""
Diagnostic test for RuleGen Refactoring
Captures detailed output and errors
"""


import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import os
import sys
import traceback
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_traditional_agent():
    """Test RuleGenerationAgentWithLLM"""
    print("\n" + "="*80)
    print("TEST 1: RuleGenerationAgentWithLLM (Traditional)")
    print("="*80)
    
    try:
        from agents.rulegen.agent import RuleGenerationAgentWithLLM
        print("✓ Import successful")
        
        config = {
            'platforms': ['splunk'],
            'optimize_rules': True,
            'validate_rules': False,  # Disable to speed up test
            'min_confidence_threshold': 0.7,
            'llm': {
                'enabled': False,  # Use fallback for faster test
            }
        }
        
        sample_data = {
            "extraction_results": [{
                "extracted_ttps": [{
                    "ttp_id": "T1059.001",
                    "attack_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "description": "Test TTP",
                    "confidence_score": 0.9,
                    "tools": ["powershell.exe"]
                }]
            }]
        }
        
        agent = RuleGenerationAgentWithLLM("test_trad", config)
        print("✓ Agent created")
        
        await agent.start()
        print("✓ Agent started")
        
        result = await agent.execute(sample_data)
        print(f"✓ Execution completed: {result['status']}")
        
        if result['status'] == 'success':
            print(f"✓ Generated {result['summary']['total_rules_generated']} rules")
            
            # Check platform conversion
            rule_result = result['rule_generation_results'][0]
            if 'platform_rules' in rule_result:
                if 'splunk' in rule_result['platform_rules']:
                    splunk_status = rule_result['platform_rules']['splunk']['status']
                    print(f"✓ Splunk conversion: {splunk_status}")
                else:
                    print("✗ Splunk platform not found")
            else:
                print("✗ No platform_rules in result")
        else:
            print(f"✗ Execution failed: {result.get('error', 'Unknown error')}")
        
        await agent.stop()
        print("✓ Agent stopped")
        
        return True
        
    except Exception as e:
        print(f"\n✗ ERROR: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        return False

async def test_langchain_agent():
    """Test LangChainRuleGenAgent"""
    print("\n" + "="*80)
    print("TEST 2: LangChainRuleGenAgent (LangChain)")
    print("="*80)
    
    try:
        from agents.rulegen.langchain_agent import LangChainRuleGenAgent
        print("✓ Import successful")
        
        config = {
            'platforms': ['splunk'],
            'optimize_rules': True,
            'validate_rules': False,
            'min_confidence_threshold': 0.7,
            'use_langchain': True,
            'llm': {
                'enabled': True,
                'api_key': os.getenv('GEMINI_API_KEY', 'dummy_key'),
                'model': 'gemini-2.0-flash-lite'
            }
        }
        
        sample_data = {
            "extraction_results": [{
                "extracted_ttps": [{
                    "ttp_id": "T1059.001",
                    "attack_id": "T1059.001",
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "description": "Test TTP",
                    "confidence_score": 0.9,
                    "tools": ["powershell.exe"]
                }]
            }]
        }
        
        agent = LangChainRuleGenAgent("test_lc", config)
        print("✓ Agent created")
        
        await agent.start()
        print("✓ Agent started")
        
        result = await agent.execute(sample_data)
        print(f"✓ Execution completed: {result['status']}")
        
        if result['status'] == 'success':
            print(f"✓ Generated {result['summary']['total_rules_generated']} rules")
            
            # Check platform conversion (NEW FEATURE)
            rule_result = result['rule_generation_results'][0]
            if 'platform_rules' in rule_result:
                if 'splunk' in rule_result['platform_rules']:
                    splunk_status = rule_result['platform_rules']['splunk']['status']
                    print(f"✓ Splunk conversion: {splunk_status} (NEW FEATURE!)")
                else:
                    print("✗ Splunk platform not found")
            else:
                print("✗ No platform_rules in result")
                
            # Check optimization (NEW FEATURE)
            if rule_result['metadata'].get('optimized'):
                print("✓ Optimization applied (NEW FEATURE!)")
            else:
                print("✗ Optimization not applied")
        else:
            print(f"✗ Execution failed: {result.get('error', 'Unknown error')}")
        
        await agent.stop()
        print("✓ Agent stopped")
        
        return True
        
    except Exception as e:
        print(f"\n✗ ERROR: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        return False

async def main():
    print("\n" + "="*80)
    print("RULEGEN REFACTORING - DIAGNOSTIC TEST")
    print("="*80)
    
    test1_passed = await test_traditional_agent()
    test2_passed = await test_langchain_agent()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Traditional Agent: {'✓ PASSED' if test1_passed else '✗ FAILED'}")
    print(f"LangChain Agent:   {'✓ PASSED' if test2_passed else '✗ FAILED'}")
    print("="*80)
    
    if test1_passed and test2_passed:
        print("\n✓ ALL TESTS PASSED")
        sys.exit(0)
    else:
        print("\n✗ SOME TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())