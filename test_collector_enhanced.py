"""
Enhanced Collector Agent Test - Shows detailed data and saves output files.

This script demonstrates:
1. What data the Collector collects (raw MISP events)
2. How normalization transforms the data  
3. What the Extractor Agent will receive as input
4. Data persistence for pipeline testing
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from agents.collector.agent import CollectorAgent

async def test_collector_detailed():
    """Enhanced test that shows exactly how the Collector works"""
    
    print("🔍 DETAILED COLLECTOR AGENT ANALYSIS")
    print("=" * 60)
    
    # Create data directories
    Path("data").mkdir(exist_ok=True)
    Path("data/raw").mkdir(exist_ok=True)
    Path("data/normalized").mkdir(exist_ok=True)
    
    # Configuration
    collector_config = {
        "sources": {
            "misp": {
                "url": "http://mock-misp.local",
                "api_key": "mock-key",
                "days_back": 1,
                "use_mock": True
            }
        },
        "interval": 300,
        "batch_size": 10,
        "max_retries": 3
    }
    
    # Create and start collector
    collector = CollectorAgent("enhanced_test", collector_config)
    await collector.start()
    
    print("\n📥 STEP 1: COLLECTING RAW CTI DATA")
    print("-" * 40)
    
    # Execute collection with detailed logging
    result = await collector.execute({"max_reports": 3})
    
    # Show summary
    summary = result["collection_summary"]
    print(f"✅ Collection Summary:")
    print(f"   - Sources processed: {summary['sources_processed']}")
    print(f"   - Raw reports collected: {summary['raw_reports_collected']}")
    print(f"   - Normalized reports: {summary['normalized_reports']}")
    print(f"   - Total indicators extracted: {summary['total_indicators']}")
    print(f"   - Errors: {summary['collection_errors']}")
    
    # Get raw data to show transformation
    raw_reports = await collector.misp_client.get_recent_events(days=1)
    raw_reports = raw_reports[:3]  # Limit to 3 for demo
    normalized_reports = result["normalized_reports"]
    
    print(f"\n🔍 STEP 2: ANALYZING RAW MISP DATA")
    print("-" * 40)
    
    for i, raw_report in enumerate(raw_reports):
        event = raw_report.get("Event", raw_report)
        print(f"\n📄 Raw MISP Event #{i+1}:")
        print(f"   ID: {event.get('id', 'N/A')}")
        print(f"   Title: {event.get('info', 'N/A')[:80]}...")
        print(f"   Published: {event.get('published', 'N/A')}")
        print(f"   Date: {event.get('date', 'N/A')}")
        print(f"   Attributes Count: {len(event.get('Attribute', []))}")
        print(f"   Objects Count: {len(event.get('Object', []))}")
        print(f"   Tags Count: {len(event.get('Tag', []))}")
        
        # Show some attributes (IOCs)
        attributes = event.get('Attribute', [])[:3]  # First 3 attributes
        if attributes:
            print(f"   Sample IOCs:")
            for attr in attributes:
                print(f"     - {attr.get('type', 'N/A')}: {attr.get('value', 'N/A')[:50]}")
    
    print(f"\n🔄 STEP 3: NORMALIZATION PROCESS")
    print("-" * 40)
    print("Raw MISP format → Standard CTI format")
    print("✓ Extract threat actors, malware families")  
    print("✓ Parse indicators and calculate confidence")
    print("✓ Map to standard schema for Extractor Agent")
    
    print(f"\n📊 STEP 4: NORMALIZED DATA ANALYSIS") 
    print("-" * 40)
    
    for i, norm_report in enumerate(normalized_reports):
        print(f"\n📋 Normalized Report #{i+1}:")
        print(f"   Report ID: {norm_report['report_id']}")
        print(f"   Title: {norm_report['title'][:80]}")
        print(f"   Source: {norm_report['source']}")
        print(f"   Confidence: {norm_report['confidence']}%")
        print(f"   Severity: {norm_report['severity']}")
        print(f"   Published: {norm_report['published']}")
        
        # Show extracted entities
        print(f"   Threat Actors: {norm_report['threat_actors']}")
        print(f"   Malware Families: {norm_report['malware_families']}")
        print(f"   Attack Patterns: {len(norm_report['attack_patterns'])} patterns")
        print(f"   Indicators: {len(norm_report['indicators'])} IOCs")
        
        # Show sample indicators
        if norm_report['indicators']:
            print(f"   Sample Indicators:")
            for ioc in norm_report['indicators'][:3]:
                print(f"     - {ioc['type']}: {ioc['value'][:50]} (confidence: {ioc['confidence']}%)")
        
        # Show description preview
        desc_lines = norm_report['description'].split('\n')[:3]
        print(f"   Description Preview:")
        for line in desc_lines:
            if line.strip():
                print(f"     {line.strip()[:70]}...")
    
    print(f"\n💾 STEP 5: SAVING DATA FOR EXTRACTOR AGENT")
    print("-" * 40)
    
    # Save raw data
    raw_filename = f"data/raw/misp_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(raw_filename, 'w', encoding='utf-8') as f:
        json.dump(raw_reports, f, indent=2, ensure_ascii=False, default=str)
    print(f"✅ Raw MISP events saved: {raw_filename}")
    
    # Save normalized data (input for Extractor Agent)
    norm_filename = f"data/normalized/cti_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(norm_filename, 'w', encoding='utf-8') as f:
        json.dump(normalized_reports, f, indent=2, ensure_ascii=False, default=str)
    print(f"✅ Normalized reports saved: {norm_filename}")
    
    # Save a pretty-printed sample for inspection
    sample_filename = "data/normalized/SAMPLE_FOR_INSPECTION.json"
    if normalized_reports:
        with open(sample_filename, 'w', encoding='utf-8') as f:
            json.dump(normalized_reports[0], f, indent=2, ensure_ascii=False, default=str)
        print(f"✅ Sample report for inspection: {sample_filename}")
    
    print(f"\n📈 STEP 6: COLLECTOR STATISTICS")
    print("-" * 40)
    
    stats = await collector.get_statistics()
    print(f"Agent Statistics:")
    for key, value in stats['statistics'].items():
        print(f"   {key}: {value}")
    
    print(f"\n🔗 STEP 7: PIPELINE CONNECTION PREVIEW")
    print("-" * 40)
    print("The normalized reports will be fed to the Extractor Agent like this:")
    print(f"")
    print(f"Extractor Agent Input Format:")
    print(f"{{")
    print(f"  'cti_reports': [normalized_reports],  # List of {len(normalized_reports)} reports")
    print(f"  'processing_mode': 'batch',")
    print(f"  'extract_ttps': True,")
    print(f"  'map_to_attack': True")
    print(f"}}")
    
    await collector.stop()
    
    print(f"\n🎯 NEXT STEPS:")
    print("-" * 40)
    print("1. Examine the saved files to understand the data structure")
    print("2. Use SAMPLE_FOR_INSPECTION.json to design Extractor Agent")
    print("3. The normalized data contains everything Extractor needs:")
    print("   - Rich descriptions for LLM processing")
    print("   - Threat actors and malware for context")
    print("   - Indicators for TTP correlation")
    print("   - Confidence scores for filtering")
    
    print(f"\n🎉 COLLECTOR AGENT FULLY ANALYZED!")
    return normalized_reports

def inspect_sample_data():
    """Show how to inspect the collected data"""
    
    print(f"\n🔍 DATA INSPECTION GUIDE")
    print("=" * 40)
    
    try:
        with open("data/normalized/SAMPLE_FOR_INSPECTION.json", 'r') as f:
            sample = json.load(f)
        
        print(f"Sample Report Structure:")
        for key, value in sample.items():
            if key == 'raw_data':
                print(f"  {key}: [original MISP event - large]")
            elif isinstance(value, list):
                print(f"  {key}: [{len(value)} items]")
            elif isinstance(value, str) and len(value) > 50:
                print(f"  {key}: '{value[:47]}...'")
            else:
                print(f"  {key}: {value}")
        
        # Show indicators in detail
        if 'indicators' in sample and sample['indicators']:
            print(f"\n  Indicators Detail:")
            for i, indicator in enumerate(sample['indicators'][:3]):
                print(f"    [{i+1}] Type: {indicator['type']}, Value: {indicator['value'][:30]}...")
        
        # Show threat actors
        if sample.get('threat_actors'):
            print(f"\n  Threat Actors: {', '.join(sample['threat_actors'])}")
            
        # Show malware
        if sample.get('malware_families'):
            print(f"  Malware Families: {', '.join(sample['malware_families'])}")
        
    except FileNotFoundError:
        print("Run the detailed test first to generate sample data")

if __name__ == "__main__":
    print("🔍 ENHANCED COLLECTOR ANALYSIS")
    print("Choose test mode:")
    print("1. Full detailed analysis (recommended)")
    print("2. Inspect existing sample data")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        reports = asyncio.run(test_collector_detailed())
        inspect_sample_data()
    elif choice == "2":
        inspect_sample_data()
    else:
        print("Invalid choice")
        sys.exit(1)
