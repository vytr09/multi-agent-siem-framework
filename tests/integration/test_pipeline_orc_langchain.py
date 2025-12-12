#!/usr/bin/env python3
"""
Test Feedback Loop with LangChain
Shows how to use the new LangChain implementation
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
from pathlib import Path

# NEW: Use LangChainOrchestrator instead of HybridOrchestrator
from core.langchain_orchestrator import LangChainOrchestrator
from agents.evaluator.feedback_manager import FeedbackManager


async def test_feedback_loop_langchain():
    """Test feedback loop using LangChain agents"""

    print("="*100)
    print("TESTING FEEDBACK LOOP WITH LANGCHAIN")
    print("="*100)

    # Load test data (same as before)
    project_root = Path(__file__).resolve().parent
    data_path = project_root / "data" / "extracted" / "hybrid_extraction_results.json"

    if not data_path.exists():
        print(f"[ERROR] Test data not found: {data_path}")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        extraction_data = json.load(f)

    hybrid_data = extraction_data.get('hybrid', {})
    
    # Extract TTPs from the test data format
    # The data has structure: {extraction_results: [{extracted_ttps: [...]}]}
    ttps = []
    if 'extraction_results' in hybrid_data:
        for result in hybrid_data['extraction_results']:
            ttps.extend(result.get('extracted_ttps', []))
    
    # Convert to format expected by RuleGen agent
    test_data = {'ttps': ttps}
    
    print(f"\n[DATA] Loaded {len(ttps)} TTPs from test data")

    # Option 1: Use existing config file
    print("\n[OPTION 1] Using config file with LangChain mode...")
    
    orchestrator = LangChainOrchestrator(
        config_path="config/agents.yaml",
        mode="langchain"  # Change to "traditional" or "hybrid" as needed
    )
    
    try:
        await orchestrator.initialize()
        print("[SUCCESS] Orchestrator initialized in LangChain mode")
        
        # Run test pipeline (same API as before!)
        result = await orchestrator.run_test_pipeline(test_data)
        
        print("\n" + "="*100)
        print("FEEDBACK LOOP TEST COMPLETE")
        print("="*100)
        
        print(f"\n[RESULTS]")
        print(f"   • Status: {result.get('status', 'unknown')}")
        print(f"   • Mode: {result.get('mode', 'N/A')}")
        
        if result.get('status') == 'success':
            print(f"   • Final Score: {result.get('final_score', 0):.3f}")
            print(f"   • Iterations: {result.get('iterations', 1)}")
        else:
            print(f"   • Message: {result.get('message', 'No message')}")
            print("\n[INFO] Test data might be empty or in wrong format.")
            print("      Expected format: {'ttps': [...]} or {'extracted_ttps': [...]}")
            print(f"      Received: {len(test_data.get('ttps', []))} TTPs")
            return
        
        # Check feedback (same as before)
        feedback_manager = FeedbackManager()
        feedback_history = feedback_manager.get_feedback_history("rulegen")
        print(f"   • Feedback Entries: {len(feedback_history)}")
        
        if feedback_history:
            print(f"\n[FEEDBACK] Latest Feedback:")
            latest = feedback_history[-1]
            print(f"   • Improvements: {len(latest.get('improvements_needed', []))}")
            for imp in latest.get('improvements_needed', [])[:3]:
                print(f"     - {imp.get('suggestion', 'N/A')}")
        
        # Save results
        output_dir = project_root / "data" / "benchmark_results"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / "feedback_loop_langchain_test.json"
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"\n[OUTPUT] Results saved to: {output_path}")
        
    finally:
        await orchestrator.cleanup()


async def test_comparison():
    """Compare traditional vs LangChain modes"""
    
    print("\n" + "="*100)
    print("COMPARING TRADITIONAL VS LANGCHAIN")
    print("="*100)
    
    # Load test data
    project_root = Path(__file__).resolve().parent
    data_path = project_root / "data" / "extracted" / "hybrid_extraction_results.json"
    
    with open(data_path, 'r') as f:
        extraction_data = json.load(f)
    
    # Extract TTPs from the test data format
    ttps = []
    hybrid_data = extraction_data.get('hybrid', {})
    if 'extraction_results' in hybrid_data:
        for result in hybrid_data['extraction_results']:
            ttps.extend(result.get('extracted_ttps', []))
    
    test_data = {'ttps': ttps}
    print(f"\n[DATA] Loaded {len(ttps)} TTPs from test data")
    
    results = {}
    
    # Test both modes
    for mode in ["traditional", "langchain"]:
        print(f"\n[TEST] Running in {mode.upper()} mode...")
        
        orchestrator = LangChainOrchestrator(
            config_path="config/agents.yaml",
            mode=mode
        )
        
        try:
            await orchestrator.initialize()
            result = await orchestrator.run_test_pipeline(test_data)
            results[mode] = result
            
            print(f"[SUCCESS] {mode.title()} mode completed")
            print(f"   • Score: {result.get('final_score', 0):.3f}")
            print(f"   • Iterations: {result.get('iterations', 1)}")
            
        finally:
            await orchestrator.cleanup()
    
    # Compare results
    print("\n" + "="*100)
    print("COMPARISON RESULTS")
    print("="*100)
    
    print("\n┌─────────────────────────┬──────────────┬──────────────┐")
    print("│ Metric                  │ Traditional  │ LangChain    │")
    print("├─────────────────────────┼──────────────┼──────────────┤")
    
    trad_score = results['traditional'].get('final_score', 0)
    lc_score = results['langchain'].get('final_score', 0)
    trad_iter = results['traditional'].get('iterations', 1)
    lc_iter = results['langchain'].get('iterations', 1)
    
    print(f"│ Final Score             │ {trad_score:12.3f} │ {lc_score:12.3f} │")
    print(f"│ Iterations              │ {trad_iter:12} │ {lc_iter:12} │")
    print("└─────────────────────────┴──────────────┴──────────────┘")
    
    if lc_score > trad_score:
        print("\n🏆 LangChain mode achieved higher quality!")
    elif lc_score < trad_score:
        print("\n🏆 Traditional mode achieved higher quality!")
    else:
        print("\n🤝 Both modes achieved equal quality!")


if __name__ == "__main__":
    # Run LangChain test
    asyncio.run(test_feedback_loop_langchain())
    
    # Uncomment to run comparison
    # asyncio.run(test_comparison())