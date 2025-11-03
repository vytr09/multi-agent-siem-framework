#!/usr/bin/env python3
"""
Test script for the Collector Agent.
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from agents.collector.agent import CollectorAgent
from core.config import get_config

async def test_collector():
    """Test the Collector Agent functionality"""
    print("[TEST] Testing Collector Agent...")
    
    try:
        # Configuration for testing
        collector_config = {
            "sources": {
                "misp": {
                    "url": "http://mock-misp.local",
                    "api_key": "mock-key",
                    "days_back": 1,
                    "use_mock": True  # Use mock data
                }
            },
            "interval": 300,
            "batch_size": 50,
            "max_retries": 3
        }
        
        # Create collector agent
        collector = CollectorAgent("test_collector", collector_config)
        
        # Test agent lifecycle
        print("[INIT] Testing agent startup...")
        await collector.start()
        print(f"  - Status: {collector.status.value}")
        
        # Test collection
        print("[RUN] Testing CTI collection...")
        result = await collector.execute({
            "sources": ["misp"],
            "max_reports": 5
        })
        
        # Display results
        summary = result["collection_summary"]
        print(f"  - Raw reports collected: {summary['raw_reports_collected']}")
        print(f"  - Normalized reports: {summary['normalized_reports']}")
        print(f"  - Total indicators: {summary['total_indicators']}")
        
        # Show sample normalized report
        if result["normalized_reports"]:
            sample = result["normalized_reports"][0]
            print(f"  - Sample report: {sample['title'][:60]}...")
            print(f"  - Confidence: {sample['confidence']}")
            print(f"  - Indicators: {len(sample['indicators'])}")
        
        # Test statistics
        print("[CHECK] Testing statistics...")
        stats = await collector.get_statistics()
        print(f"  - Total reports processed: {stats['statistics']['total_reports_normalized']}")
        
        # Test shutdown
        print("[STOP] Testing agent shutdown...")
        await collector.stop()
        print(f"  - Final status: {collector.status.value}")
        
        print("\n[OK] Collector Agent test completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Collector Agent test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_collector())
    sys.exit(0 if success else 1)
