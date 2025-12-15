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
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import statistics

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.logging import get_agent_logger
from core.logging import get_agent_logger
from core.langchain_orchestrator import LangChainOrchestrator
from agents.collector.normalizers.pdf_normalizer import PDFDatasetNormalizer
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

async def run_benchmark(limit: int = None):
    """Run benchmark on reports"""
    
    # Setup directories
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Load Reports
    logger.info(f"Scanning {DATA_DIR} for reports...")
    files = list(DATA_DIR.glob("*.pdf")) + list(DATA_DIR.glob("*.txt"))
    
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
            pipeline_result = await orchestrator.run_pipeline([report_data])
            
            # Collect Metrics
            duration = time.time() - start_time
            
            # Extract key stats
            extracted_ttps = pipeline_result.get('extraction', {}).get('results', [])
            ttp_count = 0
            if extracted_ttps:
                ttp_count = len(extracted_ttps[0].get('extracted_ttps', []))
                
            rules = pipeline_result.get('rules', {}).get('rules', [])
            rule_count = len(rules)
            
            siem_verified_count = sum(1 for r in rules if r.get('siem_verification', {}).get('status') == 'detected')
            
            eval_score = pipeline_result.get('evaluation', {}).get('average_quality_score', 0)
            
            result_entry = {
                "file": file_path.name,
                "status": pipeline_result.get('status'),
                "duration_s": round(duration, 2),
                "ttps_found": ttp_count,
                "rules_generated": rule_count,
                "siem_detections": siem_verified_count,
                "evaluatior_score": eval_score,
                "error": pipeline_result.get('error')
            }
            
            results.append(result_entry)
            
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
             "avg_quality_score": statistics.mean([r['evaluatior_score'] for r in success_runs])
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
    args = parser.parse_args()
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(run_benchmark(args.limit))
