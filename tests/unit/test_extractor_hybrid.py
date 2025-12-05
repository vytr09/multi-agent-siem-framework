"""
Test script for Hybrid NLP + Gemini Extractor Agent with Validators
Uses configuration from config/agents.yaml
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime
import os
from dotenv import load_dotenv
import sys

load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agents.extractor.agent import ExtractorAgent
from agents.extractor.validators import (
    AttackIdValidator,
    IndicatorExtractor,
    AdvancedTechniqueDiscovery
)
from tests.conftest import get_full_agent_config

#     print("=" * 80)
    
#     config = {
#         "llm": {
#             # "use_mock": True,
#             "api_key": os.getenv("GEMINI_API_KEY"),  # ← THÊM DÒNG NÀY
#             "use_mock": False,
#             "model": "gemini-2.0-flash-lite",
#             "temperature": 0.3,
#             "max_tokens": 1000
#         },
#         "use_nlp_preprocessing": True,
#         "nlp_entity_boost": True,
#         "min_confidence": 0.5,
#         "enable_caching": True,
#         "batch_size": 5
#     }
    
#     agent = ExtractorAgent(name="hybrid-test-1", config=config)
    
#     try:
#         print("\n1. Initializing Hybrid Agent...")
#         await agent.start()
#         print("   [OK] Agent initialized (NLP + Gemini enabled)")
        
#         # Load test data
#         with open("data/normalized/full_pipeline.json", encoding='utf-8') as f:
#             test_reports = json.load(f)
        
#         test_report = test_reports[0]
        
#         print(f"\n2. Processing report: {test_report['title']}")
#         print(f"   Report ID: {test_report['report_id']}")
#         print(f"   Description length: {len(test_report['description'])} chars")
#         print(f"   Threat Actors: {', '.join(test_report.get('threat_actors', []))}")
#         print(f"   Malware: {', '.join(test_report.get('malware_families', []))}")
#         print(f"   IOCs: {len(test_report.get('indicators', []))} indicators")
        
#         # Extract
#         start_time = datetime.utcnow()
        
#         message = {
#             "normalized_reports": [test_report]
#         }
        
#         result = await agent.execute(message)
        
#         elapsed = (datetime.utcnow() - start_time).total_seconds()
        
#         # Display results
#         print("\n" + "=" * 80)
#         print("EXTRACTION RESULTS - HYBRID APPROACH")
#         print("=" * 80)
        
#         summary = result.get("extraction_summary", {})
        
#         print(f"\nExecution Summary:")
#         print(f"  Status: {result.get('status')}")
#         print(f"  Total Processing Time: {summary.get('processing_time_ms'):.0f}ms")
#         print(f"  NLP Processing Time: {summary.get('nlp_processing_time_ms'):.0f}ms")
#         print(f"  LLM Processing Time: {summary.get('llm_processing_time_ms'):.0f}ms")
#         print(f"  Gemini API Calls: {summary.get('gemini_api_calls')}")
        
#         print(f"\nExtraction Summary:")
#         print(f"  Total TTPs Extracted: {summary.get('total_ttps_extracted')}")
#         print(f"  High Confidence TTPs: {summary.get('high_confidence_ttps')}")
#         print(f"  Avg Confidence: {result['statistics'].get('avg_confidence_score', 0):.2f}")
        
#         # Display NLP analysis
#         if result.get("extraction_results"):
#             extraction = result["extraction_results"][0]
#             nlp_analysis = extraction.get("nlp_analysis", {})
            
#             print(f"\nNLP Analysis:")
#             entities = nlp_analysis.get("entities", {})
#             print(f"  Malware Found: {', '.join(entities.get('malware', [])[:3])}")
#             print(f"  Tools Detected: {', '.join(entities.get('tools', [])[:3])}")
#             print(f"  Threat Actors: {', '.join(entities.get('threat_actors', []))}")
#             print(f"  IPs Found: {len(entities.get('ips', []))}")
#             print(f"  Domains Found: {len(entities.get('domains', []))}")
            
#             ttp_indicators = nlp_analysis.get("ttp_indicators", {})
#             if ttp_indicators:
#                 print(f"  TTP Indicators from NLP:")
#                 for tactic, techniques in list(ttp_indicators.items())[:5]:
#                     print(f"    - {tactic}: {', '.join(techniques[:2])}")
            
#             # Display extracted TTPs
#             ttps = extraction.get("extracted_ttps", [])
            
#             print(f"\n" + "-" * 80)
#             print(f"EXTRACTED TTPs ({len(ttps)} total):")
#             print("-" * 80)
            
#             for i, ttp in enumerate(ttps[:10], 1):
#                 print(f"\n{i}. {ttp.get('technique_name')}")
#                 print(f"   Attack ID: {ttp.get('attack_id')}")
#                 print(f"   Tactic: {ttp.get('tactic')}")
#                 print(f"   Confidence: {ttp.get('confidence_score')} ({ttp.get('confidence_level')})")
                
#                 # Show confidence breakdown
#                 breakdown = ttp.get('confidence_breakdown', {})
#                 if breakdown:
#                     print(f"   Breakdown: Base={breakdown.get('base', 0):.2f} " +
#                           f"Method={breakdown.get('method_bonus', 0):.2f} " +
#                           f"Mapping={breakdown.get('mapping_bonus', 0):.2f}")
                
#                 print(f"   Method: {ttp.get('extraction_method')}")
                
#                 if ttp.get('related_entities', {}).get('malware'):
#                     print(f"   Malware: {', '.join(ttp['related_entities']['malware'][:2])}")
                
#                 desc = ttp.get('description', '')
#                 if desc:
#                     print(f"   Description: {desc[:100]}...")
        
#         # Statistics
#         print("\n" + "-" * 80)
#         print("DETAILED STATISTICS:")
#         stats = result.get("statistics", {})
#         print(f"  Total Reports Processed: {stats.get('total_reports_processed')}")
#         print(f"  Total TTPs Extracted: {stats.get('total_ttps_extracted')}")
#         print(f"  NLP Entities Found: {stats.get('nlp_entities_extracted')}")
#         print(f"  NLP TTP Indicators Found: {stats.get('nlp_ttp_indicators_found')}")
#         print(f"  Gemini TTPs Extracted: {stats.get('gemini_ttps_extracted')}")
#         print(f"  Gemini API Calls: {stats.get('gemini_api_calls')}")
#         print(f"  Cache Hits: {stats.get('cache_hits')}")
#         print(f"  Extraction Errors: {stats.get('extraction_errors')}")
        
#         # Save results
#         output_path = Path("data/processed/test_hybrid_extraction.json")
#         output_path.parent.mkdir(parents=True, exist_ok=True)
        
#         with open(output_path, "w", encoding='utf-8') as f:
#             json.dump(result, f, indent=2, ensure_ascii=False)
        
#         print(f"\n[OK] Results saved to {output_path}")
        
#         # Health check
#         health = await agent.health_check()
#         print(f"\nAgent Health: {health.get('health', {}).get('status')}")
#         print(f"  Health Score: {health.get('health', {}).get('score')}")
        
#         await agent.shutdown()
#         print("\n[OK] Agent shutdown complete")
        
#         print("\n" + "=" * 80)
#         print("HYBRID TEST COMPLETED SUCCESSFULLY")
#         print("=" * 80)
        
#     except Exception as e:
#         print(f"\n[ERROR] Test failed: {e}")
#         import traceback
#         traceback.print_exc()
#         return False
    
#     return True

async def test_hybrid_extraction():
    """
    HYBRID EXTRACTION: Generate complete extraction data from scratch
    
    Process: Load normalized reports → Extract TTPs → Validate/Enhance → Save JSON
    Output: data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json
    """
    print("=" * 80)
    print("OPTION 1: HYBRID EXTRACTION WITH VALIDATORS")
    print("=" * 80)
    
    # Load test data
    data_file = Path("data/normalized/cti_reports_20251004_212903.json")
    if not data_file.exists():
        print(f"\n[ERROR] Test data not found: {data_file}")
        return False
    
    with open(data_file, encoding='utf-8') as f:
        test_reports = json.load(f)
    
    total_reports = len(test_reports)
    print(f"\n[LOAD] Loaded {total_reports} reports from normalized data")
    
    # Ask user how many reports to process
    print("\nSelect scope:")
    print("  1. Single report (first one)")
    print("  2. N reports (specify number)")
    print("  3. All reports")
    
    # option = input("\nChoice (1-3): ").strip()
    option = "1"
    
    if option == "1":
        reports_to_process = [test_reports[0]]
        print(f"→ Processing 1 report")
    elif option == "2":
        try:
            num = int(input(f"Number of reports (1-{total_reports}): ").strip())
            num = max(1, min(num, total_reports))
            reports_to_process = test_reports[:num]
            print(f"→ Processing {num} reports")
        except (ValueError, KeyboardInterrupt):
            reports_to_process = [test_reports[0]]
            print(f"→ Processing 1 report (default)")
    elif option == "3":
        reports_to_process = test_reports
    # Configuration - IMPORTANT: Validators are applied in _format_ttp_for_handoff()
    # Load LLM config from agents.yaml
    yaml_config = get_full_agent_config("extractor")
    llm_config = yaml_config.get("llm", {})
    
    config = {
        "llm": {
            "api_key": llm_config.get("api_key", ""),
            "provider": llm_config.get("provider", "gemini"),
            "use_mock": False,
            "model": llm_config.get("model", "gemini-2.0-flash-lite"),
            "base_url": llm_config.get("base_url"),
            "temperature": llm_config.get("temperature", 0.3),
            "max_tokens": llm_config.get("max_tokens", 1000)
        },
        "use_nlp_preprocessing": True,
        "nlp_entity_boost": True,
        "min_confidence": 0.5,
        "enable_caching": True,
        "batch_size": 5
    }
    
    agent = ExtractorAgent(name="hybrid-extraction", config=config)

    try:
        print("INITIALIZING EXTRACTOR AGENT")
        print("=" * 80)
        await agent.start()
        print("[✓] Agent initialized with NLP + Gemini")
        print(f"    Model: {agent.model_name}")
        print(f"    Min Confidence: {agent.min_confidence_threshold}")
        print(f"    Validators: AttackIdValidator, IndicatorExtractor, AdvancedTechniqueDiscovery")
        
        # Storage for results
        all_extraction_results = []
        total_ttps = 0
        total_processing_time = 0
        total_high_confidence = 0
        
        # Process reports
        print("\n" + "=" * 80)
        print(f"PROCESSING {len(reports_to_process)} REPORT(S)")
        print("=" * 80)
        
        for idx, test_report in enumerate(reports_to_process, 1):
            print(f"\n{'-' * 80}")
            print(f"REPORT {idx}/{len(reports_to_process)}: {test_report.get('title', 'Unknown')[:60]}")
            print(f"{'-' * 80}")
            
            report_id = test_report.get('report_id', 'unknown')
            print(f"ID: {report_id}")
            print(f"Description: {len(test_report.get('description', ''))} chars")
            print(f"Actors: {', '.join(test_report.get('threat_actors', [])[:3]) if test_report.get('threat_actors') else 'None'}")
            print(f"Malware: {', '.join(test_report.get('malware_families', [])[:3]) if test_report.get('malware_families') else 'None'}")
            print(f"IOCs: {len(test_report.get('indicators', []))} indicators")
            
            # Extract
            print(f"\n→ Extracting TTPs...")
            start_time = datetime.utcnow()
            
            message = {"normalized_reports": [test_report]}
            result = await agent.execute(message)
            
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            total_processing_time += elapsed
            
            # Get results
            summary = result.get("extraction_summary", {})
            extraction_results = result.get("extraction_results", [])
            
            if extraction_results:
                extraction = extraction_results[0]
                ttps = extraction.get("extracted_ttps", [])
                total_ttps += len(ttps)
                
                # Count high confidence
                high_conf = sum(1 for t in ttps if t.get('confidence_score', 0) >= 0.8)
                total_high_confidence += high_conf
                
                # Show extraction summary
                print(f"\n[✓] Extraction Results:")
                print(f"    TTPs Extracted: {len(ttps)}")
                print(f"    High Confidence: {high_conf} (≥0.8)")
                print(f"    Processing Time: {summary.get('processing_time_ms', 0):.0f}ms")
                print(f"    Gemini Calls: {summary.get('gemini_api_calls', 0)}")
                
                # Show NLP analysis
                nlp_analysis = extraction.get("nlp_analysis", {})
                if nlp_analysis:
                    entities = nlp_analysis.get("entities", {})
                    print(f"\n    NLP Analysis:")
                    print(f"      Malware: {len(entities.get('malware', []))}")
                    print(f"      Tools: {len(entities.get('tools', []))}")
                    print(f"      Threat Actors: {len(entities.get('threat_actors', []))}")
                    print(f"      IPs: {len(entities.get('ips', []))}")
                    print(f"      Domains: {len(entities.get('domains', []))}")
                
                # Show top TTPs with validation status
                if ttps:
                    print(f"\n    Top 3 TTPs (with validators applied):")
                    for i, ttp in enumerate(ttps[:3], 1):
                        technique = ttp.get('technique_name', 'Unknown')
                        attack_id = ttp.get('attack_id', 'N/A')
                        validated = ttp.get('attack_id_validated', False)
                        indicators_count = len(ttp.get('extracted_indicators', {}))
                        confidence = ttp.get('confidence_score', 0)
                        
                        status = "✓" if validated else "!"
                        print(f"      {i}. {technique} ({attack_id}) {status}")
                        print(f"         Confidence: {confidence:.2f} | Indicators: {indicators_count} | Method: {ttp.get('extraction_method')}")
                
                # Store for final output
                all_extraction_results.append({
                    "report_id": report_id,
                    "title": test_report.get('title', 'Unknown'),
                    "ttps_count": len(ttps),
                    "high_confidence_count": high_conf,
                    "processing_time_ms": summary.get('processing_time_ms', 0),
                    "extraction": extraction
                })
            else:
                print(f"\n[⚠] No extraction results for this report")
        
        # Final Summary
        print("\n" + "=" * 80)
        print("EXTRACTION SUMMARY")
        print("=" * 80)
        
        print(f"\nOverall Statistics:")
        print(f"  Total Reports Processed: {len(reports_to_process)}")
        print(f"  Total TTPs Extracted: {total_ttps}")
        print(f"  High Confidence TTPs: {total_high_confidence}")
        print(f"  Average TTPs per Report: {total_ttps / len(reports_to_process):.1f}")
        print(f"  Total Processing Time: {total_processing_time:.2f}s")
        print(f"  Average Time per Report: {(total_processing_time / len(reports_to_process)):.2f}s")
        
        # Agent statistics
        stats = result.get("statistics", {})
        print(f"\nAgent Statistics:")
        print(f"  Total Reports Processed: {stats.get('total_reports_processed')}")
        print(f"  Total TTPs Extracted: {stats.get('total_ttps_extracted')}")
        print(f"  NLP Entities Found: {stats.get('nlp_entities_extracted')}")
        print(f"  NLP TTP Indicators: {stats.get('nlp_ttp_indicators_found')}")
        print(f"  Gemini TTPs Extracted: {stats.get('gemini_ttps_extracted')}")
        print(f"  Gemini API Calls: {stats.get('gemini_api_calls')}")
        print(f"  Cache Hits: {stats.get('cache_hits')}")
        print(f"  Cache Misses: {stats.get('cache_misses')}")
        print(f"  Extraction Errors: {stats.get('extraction_errors')}")
        
        # Validator statistics
        print(f"\nValidator Statistics (Applied during extraction):")
        print(f"  Attack IDs Validated: {len([t for r in all_extraction_results for t in r['extraction'].get('extracted_ttps', []) if t.get('attack_id_validated')])}")
        print(f"  TTPs with Indicators: {len([t for r in all_extraction_results for t in r['extraction'].get('extracted_ttps', []) if t.get('extracted_indicators')])}")
        
        # Per-report breakdown
        print(f"\n{'-' * 80}")
        print("PER-REPORT BREAKDOWN:")
        print(f"{'-' * 80}")
        print(f"{'#':<4} {'Report ID':<40} {'TTPs':<8} {'High Conf':<10} {'Time (ms)':<10}")
        print(f"{'-' * 80}")
        
        for i, result_item in enumerate(all_extraction_results, 1):
            print(f"{i:<4} {result_item['report_id'][:40]:<40} "
                  f"{result_item['ttps_count']:<8} "
                  f"{result_item['high_confidence_count']:<10} "
                  f"{result_item['processing_time_ms']:<10.0f}")
        
        # Save complete extraction data to JSON
        output_path = Path("data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        final_output = {
            "test_timestamp": datetime.utcnow().isoformat(),
            "total_reports": len(reports_to_process),
            "total_ttps": total_ttps,
            "total_high_confidence_ttps": total_high_confidence,
            "total_processing_time_seconds": total_processing_time,
            "agent_statistics": stats,
            "per_report_results": all_extraction_results,
            "metadata": {
                "extraction_type": "hybrid_nlp_gemini",
                "model_used": agent.model_name,
                "min_confidence_threshold": agent.min_confidence_threshold,
                "nlp_enabled": agent.use_nlp_preprocessing,
                "validators_applied": [
                    "AttackIdValidator",
                    "IndicatorExtractor",
                    "AdvancedTechniqueDiscovery"
                ],
                "validator_integration_point": "_format_ttp_for_handoff()",
                "output_fields_per_ttp": [
                    "ttp_id",
                    "report_id",
                    "technique_name",
                    "attack_id",
                    "attack_id_validated",
                    "attack_id_confidence",
                    "tactic",
                    "description",
                    "confidence_score",
                    "extracted_indicators",
                    "indicator_score",
                    "extraction_method",
                    "tools",
                    "related_entities",
                    "extracted_timestamp"
                ]
            }
        }
        
        with open(output_path, "w", encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
        
        print(f"\n[✓] COMPLETE DATA SAVED:")
        print(f"    Path: {output_path}")
        print(f"    Size: {output_path.stat().st_size / 1024:.1f}KB")
        print(f"    Total TTPs: {total_ttps}")
        print(f"    With validators: ✓ Applied during extraction")
        
        # Health check
        print(f"\n[CHECK] Agent Health:")
        health = await agent.health_check()
        health_status = health.get('health', {})
        print(f"    Status: {health_status.get('status')}")
        print(f"    Score: {health_status.get('score', 0):.1f}")
        
        await agent.shutdown()
        print("\n[✓] Agent shutdown complete")
        
        print("\n" + "=" * 80)
        print("[SUCCESS] HYBRID EXTRACTION COMPLETED")
        print("=" * 80)
        print("\nNext Steps:")
        print("  1. Verify output file: data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json")
        print("  2. Run OPTION 2 to apply additional validators (if needed)")
        print("  3. Pass output to rulegen/attackgen agents")
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        try:
            await agent.shutdown()
        except:
            pass
        return False


async def test_nlp_component():
    """Test NLP component separately"""
    print("=" * 80)
    print("NLP COMPONENT TEST")
    print("=" * 80)
    
    from agents.extractor.nlp.pipeline import NLPPipeline
    from agents.extractor.nlp.entity_extractor import EntityExtractor
    
    # Load test data
    with open("data/normalized/cti_reports_20251004_212903.json", encoding='utf-8') as f:
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
    
    print("\n[OK] NLP component test completed")


async def test_batch_hybrid():
    """Test batch processing with hybrid approach"""
    print("=" * 80)
    print("BATCH HYBRID PROCESSING TEST")
    print("=" * 80)
    
    config = {
        "llm": {
            "use_mock": False,
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
        with open("data/normalized/cti_reports_20251004_212903.json", encoding='utf-8') as f:
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
        print("\n[OK] Batch test completed")
        
    except Exception as e:
        print(f"\n[ERROR] Batch test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


async def test_hybrid_extraction_with_validators():
    """
    Load existing extraction data and enhance with validators
    1. Loads: data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json
    2. Applies: AttackIdValidator, IndicatorExtractor, AdvancedTechniqueDiscovery
    3. Saves: Back to same file (overwrite with enhanced fields)
    """
    print("=" * 80)
    print("HYBRID EXTRACTION + VALIDATORS ENHANCEMENT")
    print("=" * 80)
    
    # Load existing extraction data
    data_file = Path("data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json")
    
    if not data_file.exists():
        print(f"\n[ERROR] Data file not found: {data_file}")
        print("Please run extraction first to generate data.")
        return False
    
    print(f"\n[LOAD] Reading existing extraction data...")
    with open(data_file, 'r', encoding='utf-8') as f:
        original_data = json.load(f)
    
    print(f"  ✓ Loaded: {data_file.name}")
    print(f"  ✓ Total reports: {original_data.get('total_reports', 0)}")
    print(f"  ✓ Total TTPs: {original_data.get('total_ttps', 0)}")
    
    # Initialize validators
    print("\n[INIT] Initializing validators...")
    attack_id_validator = AttackIdValidator()
    indicator_extractor = IndicatorExtractor()
    technique_discoverer = AdvancedTechniqueDiscovery()
    print("  ✓ AttackIdValidator initialized")
    print("  ✓ IndicatorExtractor initialized")
    print("  ✓ AdvancedTechniqueDiscovery initialized")
    
    try:
        print("\n" + "=" * 80)
        print("ENHANCEMENT PHASE")
        print("=" * 80)
        
        # Track enhancements
        enhancement_stats = {
            "total_ttps_processed": 0,
            "ttps_with_extracted_indicators": 0,
            "ttps_with_discovered_techniques": 0,
            "attack_ids_validated": 0,
            "attack_ids_fixed": 0,
            "total_indicators_extracted": 0,
            "total_new_techniques_discovered": 0
        }
        
        print(f"\n[ENHANCE] Processing TTPs with validators...")
        
        # Process each report's TTPs
        for report_result in original_data.get('per_report_results', []):
            report_title = report_result.get('title', 'Unknown')
            extraction = report_result.get('extraction', {})
            ttps = extraction.get('extracted_ttps', [])
            
            print(f"\n  Report: {report_title[:50]}...")
            print(f"  TTPs: {len(ttps)}")
            
            for ttp in ttps:
                enhancement_stats['total_ttps_processed'] += 1
                
                # Get context text for validators
                context_text = ttp.get('description', '')
                if not context_text:
                    context_text = ttp.get('evidence_text', '')
                
                # 1. Validate Attack ID
                attack_id = ttp.get('attack_id', '')
                if attack_id:
                    validation = attack_id_validator.validate_attack_id(attack_id)
                    ttp['attack_id_validated'] = validation.is_valid
                    ttp['attack_id_confidence'] = validation.confidence
                    enhancement_stats['attack_ids_validated'] += 1
                    
                    # Auto-fix if needed
                    if not validation.is_valid and validation.validated_id != attack_id:
                        ttp['attack_id_original'] = attack_id
                        ttp['attack_id'] = validation.validated_id
                        enhancement_stats['attack_ids_fixed'] += 1
                
                # 2. Extract Indicators
                if context_text:
                    indicators = indicator_extractor.extract_indicators(context_text)
                    if indicators and any(indicators.values()):
                        ttp['extracted_indicators'] = indicators
                        ttp['indicator_score'] = indicator_extractor.calculate_indicator_score(indicators)
                        enhancement_stats['ttps_with_extracted_indicators'] += 1
                        
                        # Count total indicators
                        for ind_type, ind_list in indicators.items():
                            if isinstance(ind_list, dict):
                                for subtype, items in ind_list.items():
                                    if items:
                                        enhancement_stats['total_indicators_extracted'] += len(items)
                            elif isinstance(ind_list, list):
                                if ind_list:
                                    enhancement_stats['total_indicators_extracted'] += len(ind_list)
                
                # 3. Discover New Techniques
                existing_techniques = {ttp.get('attack_id')}
                tools = []
                if 'related_entities' in ttp:
                    tools = ttp['related_entities'].get('tools', [])
                
                new_techniques = technique_discoverer.discover_techniques(
                    text=context_text,
                    indicators=ttp.get('extracted_indicators', {}),
                    tools=tools,
                    existing_techniques=existing_techniques
                )
                
                if new_techniques:
                    ttp['discovered_techniques'] = [
                        {
                            'attack_id': tech.technique_id,
                            'name': tech.technique_name,
                            'confidence': tech.confidence,
                            'evidence': tech.evidence,
                            'evidence_type': tech.evidence_type
                        }
                        for tech in new_techniques
                    ]
                    enhancement_stats['ttps_with_discovered_techniques'] += 1
                    enhancement_stats['total_new_techniques_discovered'] += len(new_techniques)
        
        # Add enhancement metadata to original data
        print(f"\n[METADATA] Adding enhancement information...")
        original_data['enhancement_applied'] = {
            "timestamp": datetime.utcnow().isoformat(),
            "validators_used": ["AttackIdValidator", "IndicatorExtractor", "AdvancedTechniqueDiscovery"],
            "statistics": enhancement_stats
        }
        
        # Save enhanced data back to same file
        print(f"\n[SAVE] Saving enhanced data...")
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(original_data, f, indent=2, ensure_ascii=False)
        
        # Display results
        print("\n" + "=" * 80)
        print("ENHANCEMENT RESULTS")
        print("=" * 80)
        
        print(f"\n[SUMMARY]")
        print(f"  Total TTPs Processed: {enhancement_stats['total_ttps_processed']}")
        print(f"  Attack IDs Validated: {enhancement_stats['attack_ids_validated']}")
        print(f"  Attack IDs Fixed: {enhancement_stats['attack_ids_fixed']}")
        print(f"  TTPs with Indicators: {enhancement_stats['ttps_with_extracted_indicators']}")
        print(f"  Total Indicators Extracted: {enhancement_stats['total_indicators_extracted']}")
        print(f"  TTPs with New Techniques: {enhancement_stats['ttps_with_discovered_techniques']}")
        print(f"  Total New Techniques: {enhancement_stats['total_new_techniques_discovered']}")
        
        print(f"\n[OUTPUT FILE]")
        print(f"  File: {data_file}")
        print(f"  Status: ✓ Enhanced (original data preserved)")
        print(f"  New Fields Added to Each TTP:")
        print(f"    ├─ attack_id_validated: boolean")
        print(f"    ├─ attack_id_confidence: float (0-1)")
        print(f"    ├─ attack_id_original: string (if fixed)")
        print(f"    ├─ extracted_indicators: dict with 7 IOC types")
        print(f"    ├─ indicator_score: float (0-1)")
        print(f"    └─ discovered_techniques: list with confidence")
        
        print(f"\n[READY FOR DOWNSTREAM AGENTS]")
        print(f"  ✓ Rulegen: Use extracted_indicators for rule generation")
        print(f"  ✓ Attackgen: Use discovered_techniques for attack generation")
        print(f"  ✓ Evaluator: Measure improvement metrics")
        
        print("\n" + "=" * 80)
        print("[SUCCESS] Enhancement completed!")
        print("=" * 80)
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        try:
            await agent.shutdown()
        except:
            pass
        return False


async def main():
    """Run tests with improved menu"""
    print("\n")
    
    print("=" * 80)
    print("HYBRID NLP + GEMINI EXTRACTOR TEST SUITE")
    print("=" * 80)
    print("\nMENU OPTIONS:")
    print("-" * 80)
    print("1. HYBRID EXTRACTION (RECOMMENDED)")
    print("   - Extracts TTPs from normalized reports")
    print("   - Applies validators during extraction (_format_ttp_for_handoff)")
    print("   - Generates: data/processed/test_hybrid_multi_extraction_gemini-2.0-flash-lite.json")
    print()
    print("2. ENHANCE WITH VALIDATORS (POST-PROCESSING)")
    print("   - Loads existing extraction data")
    print("   - Applies AttackIdValidator, IndicatorExtractor, AdvancedTechniqueDiscovery")
    print("   - Overwrites file with enhanced fields")
    print()
    print("3. NLP COMPONENT ANALYSIS")
    print("   - Tests NLP pipeline separately")
    print("   - Shows entity extraction, TTP indicators, text processing")
    print()
    print("4. BATCH PROCESSING TEST")
    print("   - Tests batch mode with multiple reports")
    print()
    print("5. RUN ALL TESTS")
    print("   - Execute options 1, 3, 4 sequentially")
    print()
    print("0. EXIT")
    print("-" * 80)
    
    choice = input("\nSelect option (0-5): ").strip()
    
    if choice == "1":
        result = await test_hybrid_extraction()
        if result:
            print("\n[SUCCESS] Extraction data ready for downstream agents")
    elif choice == "2":
        result = await test_hybrid_extraction_with_validators()
        if result:
            print("\n[SUCCESS] Data enhanced with validators")
    elif choice == "3":
        await test_nlp_component()
    elif choice == "4":
        result = await test_batch_hybrid()
        if result:
            print("\n[SUCCESS] Batch processing test completed")
    elif choice == "5":
        print("\nRunning all tests...\n")
        print("\n" + "=" * 80)
        print("TEST 1/3: HYBRID EXTRACTION")
        print("=" * 80)
        await test_hybrid_extraction()
        
        print("\n" + "=" * 80)
        print("TEST 2/3: NLP ANALYSIS")
        print("=" * 80)
        await test_nlp_component()
        
        print("\n" + "=" * 80)
        print("TEST 3/3: BATCH PROCESSING")
        print("=" * 80)
        await test_batch_hybrid()
        
        print("\n" + "=" * 80)
        print("[COMPLETE] All tests finished")
        print("=" * 80)
    elif choice == "0":
        print("Exiting...")
        return
    else:
        print("Invalid choice")


if __name__ == "__main__":
    asyncio.run(main())