"""
Test script for Hybrid NLP + Gemini Extractor Agent
Run with: python test_extractor_hybrid.py
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
import os
from dotenv import load_dotenv
import sys

from agents.extractor.agent import ExtractorAgent

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

async def test_hybrid_with_mock():
    """Test hybrid approach with mock Gemini"""
    print("=" * 80)
    print("HYBRID NLP + GEMINI EXTRACTOR TEST (MOCK MODE)")
    print("=" * 80)
    
    config = {
        "llm": {
            # "use_mock": True,
            "api_key": os.getenv("GEMINI_API_KEY"),  # ← THÊM DÒNG NÀY
            "use_mock": False,
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3,
            "max_tokens": 1000
        },
        "use_nlp_preprocessing": True,
        "nlp_entity_boost": True,
        "min_confidence": 0.5,
        "enable_caching": True,
        "batch_size": 5
    }
    
    agent = ExtractorAgent(name="hybrid-test-1", config=config)
    
    try:
        print("\n1. Initializing Hybrid Agent...")
        await agent.start()
        print("   ✓ Agent initialized (NLP + Gemini enabled)")
        
        # Load test data
        with open("data/normalized/cti_reports_20251004_212903.json") as f:
            test_reports = json.load(f)
        
        test_report = test_reports[0]
        
        print(f"\n2. Processing report: {test_report['title']}")
        print(f"   Report ID: {test_report['report_id']}")
        print(f"   Description length: {len(test_report['description'])} chars")
        print(f"   Threat Actors: {', '.join(test_report.get('threat_actors', []))}")
        print(f"   Malware: {', '.join(test_report.get('malware_families', []))}")
        print(f"   IOCs: {len(test_report.get('indicators', []))} indicators")
        
        # Extract
        start_time = datetime.utcnow()
        
        message = {
            "normalized_reports": [test_report]
        }
        
        result = await agent.execute(message)
        
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        
        # Display results
        print("\n" + "=" * 80)
        print("EXTRACTION RESULTS - HYBRID APPROACH")
        print("=" * 80)
        
        summary = result.get("extraction_summary", {})
        
        print(f"\nExecution Summary:")
        print(f"  Status: {result.get('status')}")
        print(f"  Total Processing Time: {summary.get('processing_time_ms'):.0f}ms")
        print(f"  NLP Processing Time: {summary.get('nlp_processing_time_ms'):.0f}ms")
        print(f"  LLM Processing Time: {summary.get('llm_processing_time_ms'):.0f}ms")
        print(f"  Gemini API Calls: {summary.get('gemini_api_calls')}")
        
        print(f"\nExtraction Summary:")
        print(f"  Total TTPs Extracted: {summary.get('total_ttps_extracted')}")
        print(f"  High Confidence TTPs: {summary.get('high_confidence_ttps')}")
        print(f"  Avg Confidence: {result['statistics'].get('avg_confidence_score', 0):.2f}")
        
        # Display NLP analysis
        if result.get("extraction_results"):
            extraction = result["extraction_results"][0]
            nlp_analysis = extraction.get("nlp_analysis", {})
            
            print(f"\nNLP Analysis:")
            entities = nlp_analysis.get("entities", {})
            print(f"  Malware Found: {', '.join(entities.get('malware', [])[:3])}")
            print(f"  Tools Detected: {', '.join(entities.get('tools', [])[:3])}")
            print(f"  Threat Actors: {', '.join(entities.get('threat_actors', []))}")
            print(f"  IPs Found: {len(entities.get('ips', []))}")
            print(f"  Domains Found: {len(entities.get('domains', []))}")
            
            ttp_indicators = nlp_analysis.get("ttp_indicators", {})
            if ttp_indicators:
                print(f"  TTP Indicators from NLP:")
                for tactic, techniques in list(ttp_indicators.items())[:5]:
                    print(f"    - {tactic}: {', '.join(techniques[:2])}")
            
            # Display extracted TTPs
            ttps = extraction.get("extracted_ttps", [])
            
            print(f"\n" + "-" * 80)
            print(f"EXTRACTED TTPs ({len(ttps)} total):")
            print("-" * 80)
            
            for i, ttp in enumerate(ttps[:10], 1):
                print(f"\n{i}. {ttp.get('technique_name')}")
                print(f"   Attack ID: {ttp.get('attack_id')}")
                print(f"   Tactic: {ttp.get('tactic')}")
                print(f"   Confidence: {ttp.get('confidence_score')} ({ttp.get('confidence_level')})")
                
                # Show confidence breakdown
                breakdown = ttp.get('confidence_breakdown', {})
                if breakdown:
                    print(f"   Breakdown: Base={breakdown.get('base', 0):.2f} " +
                          f"Method={breakdown.get('method_bonus', 0):.2f} " +
                          f"Mapping={breakdown.get('mapping_bonus', 0):.2f}")
                
                print(f"   Method: {ttp.get('extraction_method')}")
                
                if ttp.get('related_entities', {}).get('malware'):
                    print(f"   Malware: {', '.join(ttp['related_entities']['malware'][:2])}")
                
                desc = ttp.get('description', '')
                if desc:
                    print(f"   Description: {desc[:100]}...")
        
        # Statistics
        print("\n" + "-" * 80)
        print("DETAILED STATISTICS:")
        stats = result.get("statistics", {})
        print(f"  Total Reports Processed: {stats.get('total_reports_processed')}")
        print(f"  Total TTPs Extracted: {stats.get('total_ttps_extracted')}")
        print(f"  NLP Entities Found: {stats.get('nlp_entities_extracted')}")
        print(f"  NLP TTP Indicators Found: {stats.get('nlp_ttp_indicators_found')}")
        print(f"  Gemini TTPs Extracted: {stats.get('gemini_ttps_extracted')}")
        print(f"  Gemini API Calls: {stats.get('gemini_api_calls')}")
        print(f"  Cache Hits: {stats.get('cache_hits')}")
        print(f"  Extraction Errors: {stats.get('extraction_errors')}")
        
        # Save results
        output_path = Path("data/processed/test_hybrid_extraction.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        
        print(f"\n✓ Results saved to {output_path}")
        
        # Health check
        health = await agent.health_check()
        print(f"\nAgent Health: {health.get('health', {}).get('status')}")
        print(f"  Health Score: {health.get('health', {}).get('score')}")
        
        await agent.shutdown()
        print("\n✓ Agent shutdown complete")
        
        print("\n" + "=" * 80)
        print("HYBRID TEST COMPLETED SUCCESSFULLY")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


async def test_nlp_component():
    """Test NLP component separately"""
    print("=" * 80)
    print("NLP COMPONENT TEST")
    print("=" * 80)
    
    from agents.extractor.nlp.pipeline import NLPPipeline
    from agents.extractor.nlp.entity_extractor import EntityExtractor
    
    # Load test data
    with open("data/normalized/cti_reports_20251004_212903.json") as f:
        test_reports = json.load(f)
    
    test_report = test_reports[0]
    description = test_report.get("description", "")
    
    print(f"\nProcessing report: {test_report['title']}")
    
    # Initialize NLP components
    nlp_pipeline = NLPPipeline()
    entity_extractor = EntityExtractor()
    
    # Process
    start = datetime.utcnow()
    processed_text = nlp_pipeline.process(description)
    nlp_time = (datetime.utcnow() - start).total_seconds() * 1000
    
    start = datetime.utcnow()
    entities = entity_extractor.extract(description)
    entity_time = (datetime.utcnow() - start).total_seconds() * 1000
    
    start = datetime.utcnow()
    ttp_indicators = nlp_pipeline.extract_ttp_indicators(description)
    indicator_time = (datetime.utcnow() - start).total_seconds() * 1000
    
    print(f"\nProcessing Times:")
    print(f"  NLP Pipeline: {nlp_time:.1f}ms")
    print(f"  Entity Extraction: {entity_time:.1f}ms")
    print(f"  TTP Indicators: {indicator_time:.1f}ms")
    
    print(f"\nExtracted Entities:")
    print(f"  Malware Families: {len(entities.malware_families)} - {entities.malware_families}")
    print(f"  Tools: {len(entities.tools)} - {entities.tools}")
    print(f"  Threat Actors: {len(entities.threat_actors)} - {entities.threat_actors}")
    print(f"  IP Addresses: {len(entities.ip_addresses)} - {entities.ip_addresses[:3]}")
    print(f"  Domains: {len(entities.domains)} - {entities.domains[:3]}")
    print(f"  File Hashes: {sum(len(h) for h in entities.file_hashes.values())} total")
    
    print(f"\nTTP Indicators Detected:")
    for tactic, techniques in list(ttp_indicators.items())[:5]:
        print(f"  {tactic}: {techniques}")
    
    print(f"\nProcessed Text Statistics:")
    stats = {
        "sentences": len(processed_text.sentences),
        "technical_terms": len(processed_text.technical_terms),
        "file_paths": len(processed_text.file_paths),
        "registry_keys": len(processed_text.registry_keys),
        "commands": len(processed_text.commands),
        "network_artifacts": len(processed_text.network_artifacts)
    }
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✓ NLP component test completed")


async def test_batch_hybrid():
    """Test batch processing with hybrid approach"""
    print("=" * 80)
    print("BATCH HYBRID PROCESSING TEST")
    print("=" * 80)
    
    config = {
        "llm": {
            "use_mock": True,
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3,
            "max_tokens": 1000
        },
        "use_nlp_preprocessing": True,
        "min_confidence": 0.5,
        "enable_caching": True,
        "batch_size": 2
    }
    
    agent = ExtractorAgent(name="hybrid-batch", config=config)
    
    try:
        await agent.start()
        
        # Load all reports
        with open("data/normalized/cti_reports_20251004_212903.json") as f:
            test_reports = json.load(f)
        
        print(f"\nProcessing {len(test_reports)} reports with hybrid NLP+Gemini...")
        
        message = {
            "normalized_reports": test_reports
        }
        
        result = await agent.execute(message)
        
        summary = result.get("extraction_summary", {})
        
        print(f"\nBatch Results:")
        print(f"  Reports Processed: {summary.get('reports_processed')}")
        print(f"  Total TTPs: {summary.get('total_ttps_extracted')}")
        print(f"  Avg TTPs/Report: {summary.get('avg_ttps_per_report'):.1f}")
        print(f"  Total Processing Time: {summary.get('processing_time_ms'):.0f}ms")
        print(f"  High Confidence: {summary.get('high_confidence_ttps')}")
        
        stats = result.get("statistics", {})
        print(f"\nDetailed Stats:")
        print(f"  NLP Entities: {stats.get('nlp_entities_extracted')}")
        print(f"  NLP Indicators: {stats.get('nlp_ttp_indicators_found')}")
        print(f"  Gemini TTPs: {stats.get('gemini_ttps_extracted')}")
        
        await agent.shutdown()
        print("\n✓ Batch test completed")
        
    except Exception as e:
        print(f"\n✗ Batch test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


async def main():
    """Run tests"""
    print("\n")
    
    # Check test data
    test_data_path = Path("data/normalized/cti_reports_20251004_212903.json")
    if not test_data_path.exists():
        print(f"✗ Test data not found: {test_data_path}")
        return
    
    print("HYBRID NLP + GEMINI EXTRACTOR TEST MENU")
    print("-" * 80)
    print("1. Hybrid Extraction (Mock Gemini)")
    print("2. NLP Component Analysis")
    print("3. Batch Processing")
    print("4. All tests")
    print()
    
    choice = input("Select test (1-4): ").strip()
    
    if choice == "1":
        await test_hybrid_with_mock()
    elif choice == "2":
        await test_nlp_component()
    elif choice == "3":
        await test_batch_hybrid()
    elif choice == "4":
        print("\nRunning all tests...\n")
        await test_nlp_component()
        print("\n")
        await test_hybrid_with_mock()
        print("\n")
        await test_batch_hybrid()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    asyncio.run(main())