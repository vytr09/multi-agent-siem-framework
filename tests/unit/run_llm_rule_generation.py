# """
# Run Rule Generation with LLM (Gemini API)
# Simple script to generate Sigma rules using LLM
# """

# import sys
# from pathlib import Path
# import asyncio
# import json
# import os
# from datetime import datetime

# # Add project root to path
# sys.path.append(str(Path(__file__).resolve().parents[3]))

# from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator
# from agents.rulegen.sigma.optimizer import RuleOptimizer
# from agents.rulegen.platforms.splunk import SplunkConverter
# from agents.rulegen.platforms.elasticsearch import ElasticsearchConverter


# async def generate_rules_with_llm():
#     """Generate Sigma rules using LLM"""
    
#     print("\n" + "="*80)
#     print("[INFO] SIGMA RULE GENERATION WITH LLM (GEMINI)")
#     print("="*80)
    
#     # Check API key
#     api_key = os.getenv('GEMINI_API_KEY')
#     if not api_key:
#         print("\n[ERROR] GEMINI_API_KEY not found!")
#         print("\nPlease set your Gemini API key:")
#         print("  Windows: set GEMINI_API_KEY=your-api-key")
#         print("  Linux/Mac: export GEMINI_API_KEY=your-api-key")
#         print("\nOr add to .env file")
#         return
    
#     print(f"[OK] API Key found: {api_key[:10]}...")
    
#     # Paths
#     project_root = Path(__file__).resolve().parents[2]
#     data_path = project_root / "data" / "extracted" / "hybrid_extraction_results.json"
#     output_dir = project_root / "data" / "generated_rules"
    
#     # Check input file
#     if not data_path.exists():
#         print(f"\n[ERROR] Input file not found: {data_path}")
#         return
    
#     print(f"\n[LOAD] Loading extraction data from: {data_path}")
    
#     with open(data_path, 'r', encoding='utf-8') as f:
#         extraction_data = json.load(f)
    
#     hybrid_data = extraction_data.get('hybrid', {})
    
#     if not hybrid_data:
#         print("[ERROR] No hybrid extraction data found")
#         return
    
#     # Extract TTPs
#     ttps = []
#     for result in hybrid_data.get('extraction_results', []):
#         for ttp in result.get('extracted_ttps', []):
#             if ttp.get('confidence_score', 0) >= 0.7:
#                 ttps.append(ttp)
    
#     print(f"[OK] Found {len(ttps)} TTPs to process")
    
#     for idx, ttp in enumerate(ttps, 1):
#         print(f"  {idx}. {ttp['attack_id']}: {ttp['technique_name']}")
    
#     # Initialize LLM generator
#     print("\n[INIT] Initializing LLM generator...")
    
#     llm_config = {
#         'api_key': api_key,
#         'model': 'gemini-1.5-pro',
#         'temperature': 0.3,
#         'max_retries': 3
#     }
    
#     try:
#         llm_generator = LLMSigmaGenerator(llm_config)
#     except Exception as e:
#         print(f"[ERROR] Failed to initialize LLM: {e}")
#         return
    
#     # Initialize optimizer
#     optimizer = RuleOptimizer({})
    
#     # Initialize platform converters
#     print("\n[INIT] Initializing platform converters...")
#     splunk_converter = SplunkConverter({})
#     es_converter = ElasticsearchConverter({})
    
#     print("[OK] Splunk converter ready")
#     print("[OK] Elasticsearch converter ready")
    
#     # Generate rules
#     print("\n" + "="*80)
#     print("[RUN] GENERATING RULES WITH LLM")
#     print("="*80)
    
#     start_time = datetime.now()
#     results = []
    
#     for idx, ttp in enumerate(ttps, 1):
#         print(f"\n{'='*80}")
#         print(f"Processing {idx}/{len(ttps)}: {ttp['attack_id']} - {ttp['technique_name']}")
#         print(f"{'='*80}")
        
#         try:
#             # Step 1: Generate Sigma rule with LLM
#             print("\n[RUN] Generating Sigma rule with LLM...")
#             sigma_rule = await llm_generator.generate_sigma_rule(ttp)
            
#             print(f"[OK] Generated: {sigma_rule.get('title')}")
#             print(f"  - Level: {sigma_rule.get('level')}")
#             print(f"  - Detection selections: {len([k for k in sigma_rule.get('detection', {}).keys() if k.startswith('selection')])}")
            
#             # Step 2: Optimize
#             print("\n[OPT] Optimizing Sigma rule...")
#             sigma_rule = optimizer.optimize(sigma_rule)
#             print("[OK] Optimization complete")
            
#             # Step 3: Convert to platforms
#             platform_rules = {}
            
#             # Splunk
#             print("\n[CONVERT] Converting to Splunk...")
#             try:
#                 splunk_rule = await splunk_converter.convert(sigma_rule)
#                 is_valid = await splunk_converter.validate(splunk_rule)
                
#                 platform_rules['splunk'] = {
#                     'status': 'success',
#                     'rule': splunk_rule,
#                     'syntax': 'SPL',
#                     'validated': is_valid
#                 }
#                 print(f"[OK] Splunk rule generated (validated: {is_valid})")
#             except Exception as e:
#                 print(f"[ERROR] Splunk conversion failed: {e}")
#                 platform_rules['splunk'] = {'status': 'failed', 'error': str(e)}
            
#             # Elasticsearch
#             print("[CONVERT] Converting to Elasticsearch...")
#             try:
#                 es_rule = await es_converter.convert(sigma_rule)
#                 is_valid = await es_converter.validate(es_rule)
                
#                 platform_rules['elasticsearch'] = {
#                     'status': 'success',
#                     'rule': es_rule,
#                     'syntax': 'KQL',
#                     'validated': is_valid
#                 }
#                 print(f"[OK] Elasticsearch rule generated (validated: {is_valid})")
#             except Exception as e:
#                 print(f"[ERROR] Elasticsearch conversion failed: {e}")
#                 platform_rules['elasticsearch'] = {'status': 'failed', 'error': str(e)}
            
#             # Build result
#             result = {
#                 'ttp_id': ttp.get('ttp_id'),
#                 'ttp_name': ttp.get('technique_name'),
#                 'technique_name': ttp.get('technique_name'),
#                 'attack_id': ttp.get('attack_id'),
#                 'tactic': ttp.get('tactic'),
#                 'confidence_score': ttp.get('confidence_score'),
#                 'sigma_rule': sigma_rule,
#                 'platform_rules': platform_rules,
#                 'source_info': {
#                     'report_id': ttp.get('report_id'),
#                     'extraction_method': ttp.get('extraction_method'),
#                     'mapped_by': ttp.get('mapped_by'),
#                     'source_report': ttp.get('source_report', {}),
#                     'threat_actor': ttp.get('context', {}).get('threat_actor', '')
#                 },
#                 'metadata': {
#                     'generated_at': datetime.now().isoformat(),
#                     'llm_model': llm_config['model'],
#                     'llm_generated': True,
#                     'platforms_generated': [p for p, r in platform_rules.items() if r['status'] == 'success'],
#                     'rule_count': sum(1 for r in platform_rules.values() if r['status'] == 'success'),
#                     'optimized': True,
#                     'validated': True
#                 },
#                 'status': 'success'
#             }
            
#             results.append(result)
            
#             print(f"\n[OK] Rule {idx}/{len(ttps)} completed successfully")
            
#         except Exception as e:
#             print(f"\n[ERROR] Error processing TTP: {e}")
#             import traceback
#             traceback.print_exc()
            
#             results.append({
#                 'ttp_id': ttp.get('ttp_id'),
#                 'attack_id': ttp.get('attack_id'),
#                 'status': 'failed',
#                 'error': str(e)
#             })
    
#     end_time = datetime.now()
#     processing_time = (end_time - start_time).total_seconds()
    
#     # Build summary
#     successful = sum(1 for r in results if r.get('status') == 'success')
#     total_rules = sum(r.get('metadata', {}).get('rule_count', 0) for r in results if r.get('status') == 'success')
    
#     summary = {
#         'total_ttps_processed': len(results),
#         'successful': successful,
#         'failed': len(results) - successful,
#         'total_rules_generated': total_rules,
#         'platforms': ['splunk', 'elasticsearch'],
#         'processing_time': processing_time,
#         'llm_model': llm_config['model']
#     }
    
#     # Platform statistics
#     platform_stats = {}
#     for platform in ['splunk', 'elasticsearch']:
#         platform_stats[platform] = {
#             'total': 0,
#             'successful': 0,
#             'failed': 0,
#             'validated': 0
#         }
        
#         for result in results:
#             if result.get('status') == 'success' and 'platform_rules' in result:
#                 if platform in result['platform_rules']:
#                     platform_stats[platform]['total'] += 1
                    
#                     if result['platform_rules'][platform]['status'] == 'success':
#                         platform_stats[platform]['successful'] += 1
                        
#                         if result['platform_rules'][platform].get('validated', False):
#                             platform_stats[platform]['validated'] += 1
#                     else:
#                         platform_stats[platform]['failed'] += 1
    
#     # Build final output
#     output = {
#         'agent_id': 'rulegen_llm',
#         'status': 'success',
#         'timestamp': end_time.isoformat(),
#         'summary': summary,
#         'platform_statistics': platform_stats,
#         'rule_generation_results': results,
#         'llm_config': {
#             'model': llm_config['model'],
#             'temperature': llm_config['temperature']
#         }
#     }
    
#     # Save main output
#     output_dir.mkdir(parents=True, exist_ok=True)
#     main_output = output_dir / "rulegen_llm_output.json"
    
#     print("\n" + "="*80)
#     print("[SAVE] SAVING OUTPUT FILES")
#     print("="*80)
    
#     with open(main_output, 'w', encoding='utf-8') as f:
#         json.dump(output, f, indent=2, ensure_ascii=False)
    
#     file_size = main_output.stat().st_size / 1024
#     print(f"[OK] Main output: {main_output.name} ({file_size:.2f} KB)")
    
#     # Save individual Sigma rules
#     sigma_dir = output_dir / "sigma_rules_llm"
#     sigma_dir.mkdir(exist_ok=True)
    
#     for result in results:
#         if result.get('status') == 'success':
#             attack_id = result['attack_id']
#             sigma_rule = result['sigma_rule']
            
#             rule_path = sigma_dir / f"{attack_id}_llm_generated.json"
#             with open(rule_path, 'w', encoding='utf-8') as f:
#                 json.dump(sigma_rule, f, indent=2, ensure_ascii=False)
            
#             print(f"[OK] Sigma rule: {attack_id}_llm_generated.json")
    
#     # Save platform-specific rules
#     for platform in ['splunk', 'elasticsearch']:
#         platform_dir = output_dir / f"{platform}_rules_llm"
#         platform_dir.mkdir(exist_ok=True)
        
#         for result in results:
#             if result.get('status') == 'success' and platform in result.get('platform_rules', {}):
#                 platform_rule_data = result['platform_rules'][platform]
                
#                 if platform_rule_data['status'] == 'success':
#                     attack_id = result['attack_id']
#                     rule_path = platform_dir / f"{attack_id}_{platform}_llm.json"
                    
#                     with open(rule_path, 'w', encoding='utf-8') as f:
#                         json.dump(platform_rule_data, f, indent=2, ensure_ascii=False)
                    
#                     print(f"✓ {platform.upper()} rule: {attack_id}_{platform}_llm.json")
    
#     # Final summary
#     print("\n" + "="*80)
#     print("✅ RULE GENERATION COMPLETE!")
#     print("="*80)
#     print(f"\n📊 Summary:")
#     print(f"  • Processing time: {processing_time:.2f}s")
#     print(f"  • TTPs processed: {summary['total_ttps_processed']}")
#     print(f"  • Successful: {summary['successful']}")
#     print(f"  • Failed: {summary['failed']}")
#     print(f"  • Total rules generated: {summary['total_rules_generated']}")
#     print(f"  • LLM model: {summary['llm_model']}")
    
#     print(f"\n📈 Platform Statistics:")
#     for platform, stats in platform_stats.items():
#         success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
#         print(f"  • {platform.upper()}: {stats['successful']}/{stats['total']} ({success_rate:.1f}%)")
    
#     print(f"\n📁 Output location: {output_dir}")
#     print(f"  • Main: rulegen_llm_output.json")
#     print(f"  • Sigma: sigma_rules_llm/")
#     print(f"  • Splunk: splunk_rules_llm/")
#     print(f"  • Elasticsearch: elasticsearch_rules_llm/")
#     print("="*80 + "\n")


# if __name__ == "__main__":
#     try:
#         asyncio.run(generate_rules_with_llm())
#     except KeyboardInterrupt:
#         print("\n\n⚠️  Operation cancelled by user")
#     except Exception as e:
#         print(f"\n\n❌ Fatal error: {e}")
#         import traceback
#         traceback.print_exc()

"""
Test script for RuleGen Agent with LLM - FIXED VERSION
"""

import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))

print(f"Project root: {project_root}")
print(f"Python path: {sys.path[0]}")

import asyncio
import json
import os

# Now imports should work
# Try different import paths based on project structure
try:
    from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator
except ModuleNotFoundError:
    try:
        from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator
    except ModuleNotFoundError:
        # Direct import from file location
        sys.path.insert(0, str(project_root / "agents" / "rulegen"))
        from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator


async def test_llm_rule_generation():
    """Test LLM-based Sigma rule generation"""
    
    print("\n" + "="*80)
    print("[TEST] TESTING RULEGEN AGENT WITH LLM")
    print("="*80)
    
    # Load extraction data
    data_path = project_root / "data" / "processed" / "test_hybrid_multi_extraction_gemini-2.0-flash-lite.json"
    
    if not data_path.exists():
        print(f"[ERROR] Data file not found: {data_path}")
        print(f"   Please run the extractor agent first to generate extraction data")
        return
    
    print(f"\n[LOAD] Loading extraction data from: {data_path}")
    
    with open(data_path, 'r', encoding='utf-8') as f:
        extraction_data = json.load(f)
    
    # FIXED: Access the correct structure - per_report_results
    per_report_results = extraction_data.get('per_report_results', [])
    
    if not per_report_results:
        print("[ERROR] No hybrid extraction data found")
        return
    
    # Extract TTPs from all reports
    all_ttps = []
    for report_result in per_report_results:
        extraction = report_result.get('extraction', {})
        extracted_ttps = extraction.get('extracted_ttps', [])
        
        # Filter by confidence threshold
        for ttp in extracted_ttps:
            if ttp.get('confidence_score', 0) >= 0.6:  # Lowered threshold
                all_ttps.append(ttp)
    
    print(f"[OK] Found {len(all_ttps)} TTPs from {len(per_report_results)} reports")
    
    # Limit to first 10 TTPs for testing
    test_ttps = all_ttps[:10]
    
    print(f"\n[INFO] Testing with {len(test_ttps)} TTPs:")
    for idx, ttp in enumerate(test_ttps, 1):
        print(f"  {idx}. {ttp.get('attack_id', 'UNKNOWN')}: {ttp.get('technique_name', 'Unknown')}")
        print(f"     Confidence: {ttp.get('confidence_score', 0):.2f}")
        print(f"     Tactic: {ttp.get('tactic', 'Unknown')}")
    
    # Configure LLM
    config = {
        'api_key': os.getenv('GEMINI_API_KEY'),
        'model': 'gemini-2.0-flash-lite',
        'temperature': 0.3,
        'max_retries': 3
    }
    
    # Check API key
    if not config['api_key']:
        print("\n[ERROR] GEMINI_API_KEY not found in environment")
        print("   Please set: export GEMINI_API_KEY='your-key'")
        return
    
    print(f"\n[OK] API Key found: {config['api_key'][:10]}...")
    
    # Initialize LLM generator
    print("\n[INIT] Initializing LLM Generator...")
    try:
        generator = LLMSigmaGenerator(config)
        print("[OK] Generator initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize generator: {e}")
        return
    
    # Process TTPs
    print("\n" + "="*80)
    print("[RUN] GENERATING SIGMA RULES")
    print("="*80)
    
    results = []
    successful = 0
    failed = 0
    
    for idx, ttp in enumerate(test_ttps, 1):
        print(f"\n[{idx}/{len(test_ttps)}] Processing: {ttp.get('attack_id')} - {ttp.get('technique_name')}")
        print("-" * 80)
        
        try:
            # Generate Sigma rule
            sigma_rule = await generator.generate_sigma_rule(ttp)
            
            if sigma_rule:
                print(f"[OK] Generated: {sigma_rule.get('title', 'Untitled')}")
                print(f"  - ID: {sigma_rule.get('id', 'N/A')}")
                print(f"  - Level: {sigma_rule.get('level', 'N/A')}")
                print(f"  - Status: {sigma_rule.get('status', 'N/A')}")
                
                # Show detection logic
                detection = sigma_rule.get('detection', {})
                if detection:
                    print(f"  - Condition: {detection.get('condition', 'N/A')}")
                    selection_count = sum(1 for k in detection.keys() if k.startswith('selection'))
                    print(f"  - Selections: {selection_count}")
                
                results.append({
                    'ttp_id': ttp.get('ttp_id'),
                    'attack_id': ttp.get('attack_id'),
                    'technique_name': ttp.get('technique_name'),
                    'tactic': ttp.get('tactic'),
                    'confidence_score': ttp.get('confidence_score'),
                    'sigma_rule': sigma_rule,
                    'status': 'success'
                })
                
                successful += 1
            else:
                print(f"[WARN] No rule generated (returned None)")
                failed += 1
                
        except Exception as e:
            print(f"[ERROR] Failed to generate rule: {type(e).__name__}: {str(e)}")
            failed += 1
            
            results.append({
                'ttp_id': ttp.get('ttp_id'),
                'attack_id': ttp.get('attack_id'),
                'status': 'failed',
                'error': str(e)
            })
        
        # Rate limiting
        if idx < len(test_ttps):
            await asyncio.sleep(2)
    
    # Save output
    output_dir = project_root / "data" / "generated_rules"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        'test_timestamp': extraction_data.get('test_timestamp'),
        'input_file': str(data_path.name),
        'total_ttps_tested': len(test_ttps),
        'successful': successful,
        'failed': failed,
        'success_rate': (successful / len(test_ttps) * 100) if test_ttps else 0,
        'llm_config': {
            'model': config['model'],
            'temperature': config['temperature']
        },
        'results': results
    }
    
    output_path = output_dir / "rulegen_llm_test_output.json"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    file_size = output_path.stat().st_size / 1024
    
    # Save individual Sigma rules
    if successful > 0:
        sigma_dir = output_dir / "sigma_rules_llm"
        sigma_dir.mkdir(exist_ok=True)
        
        for result in results:
            if result.get('status') == 'success':
                attack_id = result['attack_id']
                sigma_rule = result['sigma_rule']
                
                rule_path = sigma_dir / f"{attack_id}_llm_generated.json"
                with open(rule_path, 'w', encoding='utf-8') as f:
                    json.dump(sigma_rule, f, indent=2, ensure_ascii=False)
                
                print(f"[SAVE] Sigma rule: {attack_id}_llm_generated.json")
    
    # Print summary
    print("\n" + "="*80)
    print("[DONE] TEST COMPLETE")
    print("="*80)
    print(f"\n[FILE] Output saved to: {output_path}")
    print(f"[INFO] File size: {file_size:.2f} KB")
    
    print(f"\n[SUMMARY] Results:")
    print(f"  - TTPs tested: {len(test_ttps)}")
    print(f"  - Successful: {successful}")
    print(f"  - Failed: {failed}")
    print(f"  - Success rate: {(successful / len(test_ttps) * 100):.1f}%")
    print(f"  - LLM model: {config['model']}")
    
    if successful > 0:
        print(f"\n[INFO] Sigma rules saved to: {sigma_dir}")
    
    # Show errors if any
    errors = [r for r in results if r.get('status') == 'failed']
    if errors:
        print(f"\n[WARN] Failed generations: {len(errors)}")
        for error in errors[:3]:
            print(f"  - {error.get('attack_id', 'UNKNOWN')}: {error.get('error', 'Unknown error')}")
    
    print("\n" + "="*80)
    print("[OK] Test completed!")
    print("="*80 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(test_llm_rule_generation())
    except KeyboardInterrupt:
        print("\n\n[CANCEL] Operation cancelled by user")
    except Exception as e:
        print(f"\n\n[ERROR] Fatal error: {e}")
        import traceback
        traceback.print_exc()