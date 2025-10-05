#!/usr/bin/env python3
"""
Test script for Enhanced Extractor Agent
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from agents.extractor.agent import ExtractorAgent

async def main():
    """Test Enhanced Extractor Agent"""
    
    print("=" * 70)
    print("TESTING ENHANCED EXTRACTOR AGENT")
    print("=" * 70)
    
    # 1. Configuration
    config = {
        "llm": {
            "use_mock": True,
            "model": "gpt-4",
            "max_tokens": 2000,
            "temperature": 0.3
        },
        "min_confidence": 0.5,
        "batch_size": 10,
        "enable_caching": True
    }
    
    # 2. Load test data
    print("\n📥 Loading test data...")
    data_file = Path("data/normalized/cti_reports_20251004_212903.json")
    
    if not data_file.exists():
        print(f"❌ Test data not found: {data_file}")
        return False
    
    with open(data_file, 'r') as f:
        reports = json.load(f)
    
    print(f"✅ Loaded {len(reports)} reports")
    
    # 3. Initialize agent
    print("\n🚀 Initializing Extractor Agent...")
    agent = ExtractorAgent("test-extractor", config)
    await agent.start()
    
    print(f"✅ Agent started - Status: {agent.status.value}")
    
    # 4. Execute extraction
    print(f"\n⚙️  Extracting TTPs...")
    result = await agent.execute({"normalized_reports": reports})
    
    # 5. Display results
    print(f"\n📊 EXTRACTION RESULTS")
    print("-" * 70)
    summary = result['extraction_summary']
    print(f"Status: {result['status']}")
    print(f"Reports processed: {summary['reports_processed']}")
    print(f"Total TTPs extracted: {summary['total_ttps_extracted']}")
    print(f"Avg TTPs/report: {summary['avg_ttps_per_report']:.2f}")
    print(f"Processing time: {summary['processing_time_ms']:.0f}ms")
    
    # 6. Show sample TTPs
    print(f"\n🔍 SAMPLE EXTRACTED TTPs (first report):")
    print("-" * 70)
    first_result = result['extraction_results'][0]
    for i, ttp in enumerate(first_result['extracted_ttps'][:5], 1):
        print(f"\n{i}. {ttp['technique_name']} ({ttp['attack_id']})")
        print(f"   Tactic: {ttp['tactic']}")
        print(f"   Confidence: {ttp['confidence_score']:.2f} ({ttp['confidence_level']})")
        print(f"   Description: {ttp['description'][:80]}...")
    
    # 7. Test health check
    print(f"\n💚 HEALTH CHECK")
    print("-" * 70)
    health = await agent.health_check()
    print(f"Status: {health['status']['current']}")
    print(f"Health Score: {health['health']['score']}/100 ({health['health']['status']})")
    print(f"Success Rate: {health['health']['factors']['success_rate']:.1f}%")
    print(f"Avg Processing Time: {health['performance']['avg_processing_time_ms']:.0f}ms")
    print(f"Cache Hit Rate: {health['performance']['cache_hit_rate']:.1f}%")
    
    # 8. Test pause/resume
    print(f"\n⏸️  Testing Pause/Resume...")
    await agent.pause()
    print(f"Paused - Can execute: {agent._can_execute}")
    
    await agent.resume()
    print(f"Resumed - Can execute: {agent._can_execute}")
    
    # 9. Save results
    print(f"\n💾 Saving extraction results...")
    output_file = Path("data/extracted/ttps_extracted.json")
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    
    print(f"✅ Results saved to: {output_file}")
    
    # 10. Stop agent
    await agent.stop()
    print(f"\n✅ Agent stopped - Status: {agent.status.value}")
    
    print(f"\n🎉 EXTRACTOR AGENT TEST COMPLETED SUCCESSFULLY!")
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)