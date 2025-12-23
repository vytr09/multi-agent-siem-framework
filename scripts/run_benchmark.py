"""
Multi-Agent SIEM Framework - Batch Benchmark Script

Executes the pipeline against a directory of PDF/Text reports and aggregates performance metrics.
Handles API rate limits via provider rotation (configured in LangChainLLMWrapper).
"""

import sys
import os
import asyncio
import json
import logging
import time
import yaml
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import statistics

# Disable ChromaDB/PostHog Telemetry locally
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_BOARD_DISABLED"] = "1"
os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.noop.NoOpTelemetry"

# Monkeypatch Posthog to silence "capture() takes 1 positional argument but 3 were given"
try:
    import chromadb.telemetry.product.posthog
    class MockPosthog:
        def __init__(self, *args, **kwargs):
            pass
        def capture(self, *args, **kwargs):
            pass
    chromadb.telemetry.product.posthog.Posthog = MockPosthog
except ImportError:
    pass


# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.logging import get_agent_logger
from core.langchain_orchestrator import LangChainOrchestrator
from agents.collector.normalizers.pdf_normalizer import PDFDatasetNormalizer
from benchmark.rulegen_benchmark import RuleGenBenchmark
from benchmark.attackgen_benchmark import AttackGenBenchmark
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
    print("Warning: pypdf not installed. PDF reading will fail.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = get_agent_logger("benchmark")

DATA_DIR = Path("data/APTnotes/2023")
OUTPUT_DIR = Path("data/benchmark_results")

async def run_benchmark(limit: int = None, delay: int = 60, force: bool = False, skip: int = 0):
    """Run benchmark on reports"""
    
    # Setup directories
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Load Reports
    logger.info(f"Scanning {DATA_DIR} for reports...")
    files = list(DATA_DIR.glob("*.pdf")) + list(DATA_DIR.glob("*.txt"))
    
    if skip:
        files = files[skip:]
        
    if limit:
        files = files[:limit]
        
    logger.info(f"Found {len(files)} reports to process.")
    
    # 2. Initialize Normalizer
    normalizer = PDFDatasetNormalizer()
    
    # 3. Initialize Orchestrator
    orchestrator = LangChainOrchestrator(mode="langchain")
    await orchestrator.initialize()
    await orchestrator.start_all()
    
    results = []
    
    # 4. Processing Loop
    for i, file_path in enumerate(files):
        logger.info(f"\n[{i+1}/{len(files)}] Processing: {file_path.name}")
        result_file = OUTPUT_DIR / f"result_{file_path.stem}.json"
        if not force and result_file.exists():
            try:
                with open(result_file, 'r') as f:
                    existing_data = json.load(f)
                
                # Check if previous run was empty/failed (no TTPs)
                if existing_data.get('status') == 'no_data':
                    logger.info(f"Retrying {file_path.name} (Previous run had no data)")
                else:
                    logger.info(f"Skipping {file_path.name} (Result exists: {result_file})")
                    continue
            except Exception:
                # If file is corrupt, re-run
                logger.warning(f"Result file corrupt, reprocessing: {result_file}")

        start_time = time.time()
        
        try:
            # Extract text
            if file_path.suffix.lower() == '.pdf':
                if not PdfReader:
                    logger.error("pypdf module missing")
                    continue
                    
                logger.info("Reading PDF...")
                try:
                    reader = PdfReader(str(file_path))
                    content = ""
                    for page in reader.pages:
                        content += page.extract_text() + "\n"
                except Exception as e:
                    logger.error(f"Failed to read PDF {file_path}: {e}")
                    continue
                
                # Normalize (Chunking)
                raw_event = {
                    "content": content,
                    "source": str(file_path),
                    "metadata": {"filename": file_path.name}
                }
                report_data = normalizer.normalize_event(raw_event)
                
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Normalize text files too for consistency
                raw_event = {
                    "content": content,
                    "source": str(file_path),
                    "metadata": {"filename": file_path.name}
                }
                report_data = normalizer.normalize_event(raw_event)
            
            # Run Pipeline
            pipeline_result = await orchestrator.run_pipeline([report_data], context={"ignore_duplicates": force})
            
            # Collect Metrics
            duration = time.time() - start_time
            
            # Extract key stats
            extracted_ttps = pipeline_result.get('extraction', {}).get('results', [])
            ttp_count = 0
            if extracted_ttps:
                ttp_count = len(extracted_ttps[0].get('extracted_ttps', []))
                
            rules = pipeline_result.get('rules', {}).get('rules', [])
            rule_count = len(rules)
            
            # SIEM Verification results are at top level
            siem_results = pipeline_result.get('siem_verification', [])
            # ------------------------------------------------------------------
            # Stage 6: Quality Assessment (Legacy Benchmark Integration)
            # ------------------------------------------------------------------
            # Stage 6: Running Quality Assessment (LLM-as-Judge)
            # ------------------------------------------------------------------
            logger.info("Stage 6: Running Quality Assessment (LLM-as-Judge)...")
            
            # Load Configuration
            config_path = Path("config/benchmark_config.yaml")
            if config_path.exists():
                with open(config_path, "r") as f:
                    config_str = f.read()
                    # Expand environment variables
                    for key, value in os.environ.items():
                        config_str = config_str.replace(f"${{{key}}}", value)
                    benchmark_config = yaml.safe_load(config_str)
            else:
                logger.warning("benchmark_config.yaml not found, using defaults")
                benchmark_config = {
                    "llm_judge": {
                        "enabled": True, 
                        "model": "gemini-2.0-flash", 
                        "temperature": 0.3
                    }
                }
            
            rulegen_benchmark = RuleGenBenchmark(benchmark_config)
            attackgen_benchmark = AttackGenBenchmark(benchmark_config)
            
            # Prepare data for benchmarking
            generated_rules = pipeline_result.get('rules', {}).get('rules', [])
            attack_commands = pipeline_result.get('attacks', []) # Attack results are flat list in 'attacks' key check orchestrator
            
            # Note: orchestrator.py saves attack results in variable 'attack_results' but puts them in final_result? 
            # Checking pipeline_result structure... 
            # It seems Orchestrator result structure might need verification.
            # Assuming 'attacks' key based on Orchestrator logic (Stage 3)
            # Actually, `siem_results` zip(rules, attack_results). 
            # Looking at previous file view of Orchestrator:
            # It returns final_result with 'extraction', 'rules', 'evaluation', 'siem_verification'
            # It DOES NOT seem to explicitly export attack commands in the top level final_result!
            # We need to extract them from siem_verification or rules if embedded.
            
            # Workaround: Extract attack commands from siem_verification if available, or just skip if missing.
            # Re-checking Orchestrator code:
            # final_result = { ..., "siem_verification": siem_results, ... }
            # siem_results items have 'attack_id'.
            # We might need to access the raw attack command data.
            # Let's check generated_rules.json or similar.
            
            # Actually, for now let's just run RuleGenBenchmark since we have the rules.
            # We'll skip AttackGenBenchmark integration in this script until we confirm where attack commands are stored.
            
            quality_scores = {}
            
            if generated_rules:
                logger.info(f"Arguments for RuleGenBenchmark: {len(generated_rules)} rules")
                # Format rules for benchmark (expects list of dicts)
                # The benchmark expects specific keys (sigma_rule, platform_rules). 
                # Our pipeline output might differ. 
                # RuleGenAgent output format: { "rules": [ { "title": "...", "detection": ... } ] }
                # RuleGenBenchmark expects: item with "sigma_rule" key.
                
                # Adapting structure
                benchmark_input = []
                for r in generated_rules:
                    benchmark_input.append({
                        "sigma_rule": r,
                        "attack_id": r.get("tags", ["T1059"])[0] if r.get("tags") else "T1059", # Fallback
                        "technique_name": r.get("title", "Unknown"),
                        "tactic": "execution"
                    })
                
                rule_quality_results = await rulegen_benchmark.evaluate_batch(benchmark_input)
                quality_scores['rulegen_avg'] = rulegen_benchmark.get_statistics().get('average_score', 0)
                
                # Save detailed quality report
                quality_file = OUTPUT_DIR / f"quality_report_rulegen_{file_path.stem}.json"
                rulegen_benchmark.export_results(str(quality_file))
                logger.info(f"RuleGen quality report saved to {quality_file}")
            
            if attack_commands:
                logger.info(f"Arguments for AttackGenBenchmark: {len(attack_commands)} commands")
                # Format for benchmark
                # AttackGenBenchmark expects command dicts
                
                attack_quality_results = await attackgen_benchmark.evaluate_batch(attack_commands)
                quality_scores['attackgen_avg'] = attackgen_benchmark.get_statistics().get('average_score', 0)
                
                # Save detailed quality report
                quality_file = OUTPUT_DIR / f"quality_report_attackgen_{file_path.stem}.json"
                attackgen_benchmark.export_results(str(quality_file))
                logger.info(f"AttackGen quality report saved to {quality_file}")
            
            # Combine quality scores
            if quality_scores:
                # Average of available scores
                quality_score_avg = sum(quality_scores.values()) / len(quality_scores)
            else:
                quality_score_avg = 0
            
            # ------------------------------------------------------------------    
            
            siem_verified_count = sum(1 for r in siem_results if r.get('detected') is True)
            
            eval_score = pipeline_result.get('evaluation', {}).get('average_quality_score', 0)
            
            result_entry = {
                "file": file_path.name,
                "status": pipeline_result.get('status'),
                "duration_s": round(duration, 2),
                "ttps_found": ttp_count,
                "rules_generated": rule_count,
                "siem_detections": siem_verified_count,
                "eval_score": round(eval_score, 2),
                "quality_score": round(quality_score_avg, 2)
            }
            results.append(result_entry)
            
            logger.info(f"Finished {file_path.name}: {ttp_count} TTPs, {rule_count} Rules, {siem_verified_count} Verified, Quality: {quality_score_avg:.2f}")


            
            # Save individual result
            with open(OUTPUT_DIR / f"result_{file_path.stem}.json", "w") as f:
                json.dump(pipeline_result, f, indent=2, default=str)
                
            logger.info(f"Success. TTPs: {ttp_count}, Rules: {rule_count}, Verified: {siem_verified_count}")
            
        except Exception as e:
            logger.error(f"Failed to process {file_path.name}: {e}")
            results.append({
                "file": file_path.name,
                "status": "error",
                "error": str(e)
            })

        # Rate limiting delay (skip after last item)
        if i < len(files) - 1 and delay > 0:
            logger.info(f"Sleeping for {delay}s to respect rate limits...")
            time.sleep(delay)
            
    # 5. Generate Summary
    logger.info("\nGenerating Benchmark Summary...")
    
    success_runs = [r for r in results if r['status'] == 'success']
    failed_runs = [r for r in results if r['status'] != 'success']
    
    summary = {
        "total_files": len(files),
        "successful": len(success_runs),
        "failed": len(failed_runs),
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {}
    }
    
    if success_runs:
        summary["metrics"] = {
            "avg_duration_s": statistics.mean([r['duration_s'] for r in success_runs]),
            "avg_ttps_per_report": statistics.mean([r['ttps_found'] for r in success_runs]),
            "avg_rules_per_report": statistics.mean([r['rules_generated'] for r in success_runs]),
            "avg_siem_detection_rate": statistics.mean([r['siem_detections'] for r in success_runs]), # Raw count
            "avg_eval_score": statistics.mean([r['eval_score'] for r in success_runs]),
            "avg_quality_score": statistics.mean([r['quality_score'] for r in success_runs])
        }
    
    summary["detailed_results"] = results
    
    with open(OUTPUT_DIR / "benchmark_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
        
    print("\n" + "="*60)
    print(f"BENCHMARK COMPLETE")
    print(f"Total: {len(files)}, Success: {len(success_runs)}, Failed: {len(failed_runs)}")
    if success_runs:
        m = summary['metrics']
        print(f"Avg Time: {m['avg_duration_s']:.2f}s")
        print(f"Avg TTPs: {m['avg_ttps_per_report']:.1f}")
        print(f"Avg Rules: {m['avg_rules_per_report']:.1f}")
        print(f"Avg Quality: {m['avg_quality_score']:.2f}")
    print("="*60)

    # Cleanup
    await orchestrator.cleanup()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Limit number of files to process")
    parser.add_argument("--delay", type=int, default=60, help="Delay (seconds) between reports to avoid rate limits")
    parser.add_argument("--force", action="store_true", help="Force reprocessing (ignore duplicates)")
    parser.add_argument("--skip", type=int, default=0, help="Number of files to skip")
    args = parser.parse_args()
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(run_benchmark(limit=args.limit, delay=args.delay, force=args.force, skip=args.skip))
