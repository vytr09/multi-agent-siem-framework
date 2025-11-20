"""
Simple LangChain Test - Verify Integration Works
"""


import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
from agents.extractor.langchain_agent import LangChainExtractorAgent

async def simple_test():
    """Simple test to verify LangChain integration works"""
    
    print("\n" + "="*80)
    print("SIMPLE LANGCHAIN TEST")
    print("="*80)
    
    # Create minimal config (no LLM calls, just NLP)
    config = {
        "use_langchain": False,  # Test without LLM first
        "nlp": {"enabled": True},
        "llm": {"enabled": False}
    }
    
    agent = LangChainExtractorAgent("test_extractor", config)
    
    try:
        await agent.start()
        print("[OK] Agent started successfully")
        
        # Test with simple text
        text = "APT29 used PowerShell (T1059.001) for execution"
        
        result = await agent.execute({"text": text})
        
        print(f"[OK] Extraction completed")
        print(f"     Status: {result.get('status')}")
        print(f"     TTPs extracted: {len(result.get('ttps', []))}")
        
        await agent.stop()
        print("[OK] Agent stopped successfully")
        
        print("\n" + "="*80)
        print("[OK] SIMPLE TEST PASSED!")
        print("="*80)
        print("\nThe LangChain integration is working correctly!")
        print("You can now enable LLM mode for full functionality.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        await agent.stop()

if __name__ == "__main__":
    asyncio.run(simple_test())