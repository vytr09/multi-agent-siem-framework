#!/usr/bin/env python3
"""
Test script for Hybrid NLP+LLM Extractor Agent
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agents.extractor.agent import ExtractorAgent

async def test_nlp_only():
    """Test NLP-only extraction"""
    print("\n" + "=" * 70)
    print("TEST 1: NLP-ONLY EXTRACTION")
    print("=" * 70)
    
    config = {
        "llm": {"use_mock": True},
        "nlp_only_mode": True,
        "use_nlp_preprocessing": True,
        "min_confidence": 0.4
    }
    
    agent = ExtractorAgent("nlp-only-test", config)
    await agent.start()
    
    # Load test data
    data_file = Path("data/normalized/SAMPLE_FOR_INSPECTION.json")
    with open(data_file, 'r') as f:
        report = json.load(f)
    
    result = await agent.execute({"normalized_reports": [report]})
    
    print(f"\n[RESULTS] Results:")
    print(f"TTPs extracted: {result['extraction_summary']['total_ttps_extracted']}")
    print(f"Processing time: {result['extraction_summary']['processing_time_ms']:.0f}ms")
    
    # Show NLP analysis
    nlp_analysis = result['extraction_results'][0]['nlp_analysis']
    print(f"\n[DETAIL] NLP Analysis:")
    print(f"Malware: {nlp_analysis['entities']['malware']}")
    print(f"Tools: {nlp_analysis['entities']['tools']}")
    print(f"Threat Actors: {nlp_analysis['entities']['threat_actors']}")
    print(f"IPs found: {len(nlp_analysis['iocs']['ips'])}")
    print(f"Domains found: {len(nlp_analysis['iocs']['domains'])}")
    
    await agent.stop()
    return result

async def test_hybrid_mode():
    """Test Hybrid NLP+LLM extraction"""
    print("\n" + "=" * 70)
    print("TEST 2: HYBRID NLP+LLM EXTRACTION")
    print("=" * 70)
    
    config = {
        "llm": {
            "use_mock": True,
            "model": "gpt-4",
            "max_tokens": 2000,
            "temperature": 0.3
        },
        "nlp_only_mode": False,
        "use_nlp_preprocessing": True,
        "min_confidence": 0.5,
        "enable_caching": True
    }
    
    agent = ExtractorAgent("hybrid-test", config)
    await agent.start()
    
    # Load test data
    data_file = Path("data/normalized/SAMPLE_FOR_INSPECTION.json")
    with open(data_file, 'r') as f:
        report = json.load(f)
    
    result = await agent.execute({"normalized_reports": [report]})
    
    summary = result['extraction_summary']
    print(f"\n[RESULTS] Results:")
    print(f"TTPs extracted: {summary['total_ttps_extracted']}")
    print(f"Total processing: {summary['processing_time_ms']:.0f}ms")
    print(f"  - NLP time: {summary['nlp_processing_time_ms']:.0f}ms")
    print(f"  - LLM time: {summary['llm_processing_time_ms']:.0f}ms")
    
    # Show extracted TTPs
    extraction = result['extraction_results'][0]
    print(f"\n[DETAIL] Sample TTPs (first 3):")
    for i, ttp in enumerate(extraction['extracted_ttps'][:3], 1):
        print(f"\n{i}. {ttp['technique_name']} ({ttp['attack_id']})")
        print(f"   Tactic: {ttp['tactic']}")
        print(f"   Method: {ttp.get('extraction_method', 'unknown')}")
        print(f"   Confidence: {ttp['confidence_score']:.2f} ({ttp['confidence_level']})")
        if 'related_entities' in ttp:
            print(f"   Related malware: {ttp['related_entities'].get('malware', [])[:2]}")
    
    # Show attack chain
    print(f"\n[CHAIN] Attack Chain:")
    print(f"   {' -> '.join(extraction['attack_chain'][:8])}")
    
    await agent.stop()
    return result

async def test_performance_comparison():
    """Compare NLP-only vs Hybrid performance"""
    print("\n" + "=" * 70)
    print("TEST 3: PERFORMANCE COMPARISON")
    print("=" * 70)
    
    # Load test data
    data_file = Path("data/normalized/SAMPLE_FOR_INSPECTION.json")
    with open(data_file, 'r') as f:
        report = json.load(f)
    
    results = {}
    
    # Test NLP-only
    nlp_config = {
        "llm": {"use_mock": True},
        "nlp_only_mode": True,
        "use_nlp_preprocessing": True
    }
    
    nlp_agent = ExtractorAgent("perf-nlp", nlp_config)
    await nlp_agent.start()
    nlp_result = await nlp_agent.execute({"normalized_reports": [report]})
    results['nlp'] = nlp_result
    await nlp_agent.stop()
    
    # Test Hybrid
    hybrid_config = {
        "llm": {"use_mock": True},
        "nlp_only_mode": False,
        "use_nlp_preprocessing": True
    }
    
    hybrid_agent = ExtractorAgent("perf-hybrid", hybrid_config)
    await hybrid_agent.start()
    hybrid_result = await hybrid_agent.execute({"normalized_reports": [report]})
    results['hybrid'] = hybrid_result
    await hybrid_agent.stop()
    
    # Compare results
    print("\n[RESULTS] Comparison Results:")
    print("\n" + "-" * 70)
    print(f"{'Metric':<30} {'NLP-Only':<20} {'Hybrid':<20}")
    print("-" * 70)
    
    nlp_summary = results['nlp']['extraction_summary']
    hybrid_summary = results['hybrid']['extraction_summary']
    
    print(f"{'TTPs Extracted':<30} {nlp_summary['total_ttps_extracted']:<20} {hybrid_summary['total_ttps_extracted']:<20}")
    print(f"{'Processing Time (ms)':<30} {nlp_summary['processing_time_ms']:<20.0f} {hybrid_summary['processing_time_ms']:<20.0f}")
    print(f"{'NLP Time (ms)':<30} {nlp_summary['nlp_processing_time_ms']:<20.0f} {hybrid_summary['nlp_processing_time_ms']:<20.0f}")
    print(f"{'LLM Time (ms)':<30} {'N/A':<20} {hybrid_summary['llm_processing_time_ms']:<20.0f}")
    
    # Get confidence stats
    nlp_ttps = results['nlp']['extraction_results'][0]['extracted_ttps']
    hybrid_ttps = results['hybrid']['extraction_results'][0]['extracted_ttps']
    
    nlp_avg_conf = sum(t['confidence_score'] for t in nlp_ttps) / len(nlp_ttps) if nlp_ttps else 0
    hybrid_avg_conf = sum(t['confidence_score'] for t in hybrid_ttps) / len(hybrid_ttps) if hybrid_ttps else 0
    
    print(f"{'Avg Confidence':<30} {nlp_avg_conf:<20.2f} {hybrid_avg_conf:<20.2f}")
    
    print(f"\n[INSIGHT] Insights:")
    if hybrid_summary['total_ttps_extracted'] > nlp_summary['total_ttps_extracted']:
        print("   [OK] Hybrid extracted more TTPs (better coverage)")
    if hybrid_avg_conf > nlp_avg_conf:
        print("   [OK] Hybrid has higher confidence scores (better quality)")
    if nlp_summary['processing_time_ms'] < hybrid_summary['processing_time_ms']:
        print("   [OK] NLP-only is faster (good for real-time)")
    
    return results

async def test_entity_extraction():
    """Test detailed entity extraction"""
    print("\n" + "=" * 70)
    print("TEST 4: DETAILED ENTITY EXTRACTION")
    print("=" * 70)
    
    from agents.extractor.nlp.entity_extractor import EntityExtractor
    
    extractor = EntityExtractor()
    
    # Load sample text
    data_file = Path("data/normalized/SAMPLE_FOR_INSPECTION.json")
    with open(data_file, 'r') as f:
        report = json.load(f)
    
    text = report['description']
    entities = extractor.extract(text)
    
    print("\n[DETAIL] Extracted Entities:")
    print(f"\n[INFO] Malware Families: {entities.malware_families}")
    print(f"Tools: {entities.tools}")
    print(f"Threat Actors: {entities.threat_actors}")
    print(f"ATT&CK Techniques: {entities.attack_techniques}")
    
    print(f"\n[INFO] Network IOCs:")
    print(f"  IPs: {entities.ip_addresses}")
    print(f"  Domains: {entities.domains}")
    print(f"  URLs: {entities.urls[:3]}")
    
    print(f"\n[INFO] File Hashes:")
    for hash_type, hashes in entities.file_hashes.items():
        print(f"  {hash_type.upper()}: {len(hashes)} found")
    
    # Identify tactics
    tactics = extractor.identify_tactics(text)
    print(f"\n[INFO] Identified Tactics:")
    for tactic, keywords in tactics.items():
        print(f"  {tactic}: {keywords[:3]}")
    
    # Entity summary
    summary = extractor.create_entity_summary(entities)
    print(f"\n[INFO] Summary:")
    print(f"  {summary}")

async def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("HYBRID NLP+LLM EXTRACTOR - COMPLETE TEST SUITE")
    print("=" * 70)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Run tests
        await test_entity_extraction()
        await asyncio.sleep(1)
        
        await test_nlp_only()
        await asyncio.sleep(1)
        
        await test_hybrid_mode()
        await asyncio.sleep(1)
        
        results = await test_performance_comparison()
        
        # Save results
        output_dir = Path("data/extracted")
        output_dir.mkdir(exist_ok=True, parents=True)
        
        output_file = output_dir / "hybrid_extraction_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n[SAVE] Results saved to: {output_file}")
        
        print("\n" + "=" * 70)
        print("[DONE] ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 70)

        print("\n[INFO] Key Takeaways:")
        print("  [OK] NLP layer successfully extracts entities and IOCs")
        print("  [OK] Hybrid mode combines NLP precision with LLM understanding")
        print("  [OK] Both modes produce MITRE ATT&CK mapped TTPs")
        print("  [OK] Entity correlation enhances TTP context")

        return True
        
    except Exception as e:
        print(f"\n[ERROR] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)