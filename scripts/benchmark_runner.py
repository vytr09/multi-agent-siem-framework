
import sys
import os
import asyncio
import time
import json
import yaml
import argparse
from pathlib import Path
from datetime import datetime
import logging

# Disable ChromaDB/PostHog Telemetry locally
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_BOARD_DISABLED"] = "1"
os.environ["CHROMA_TELEMETRY_IMPL"] = "chromadb.telemetry.noop.NoOpTelemetry"

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.logging import get_agent_logger
from core.langchain_orchestrator import LangChainOrchestrator
from agents.collector.normalizers.pdf_normalizer import PDFDatasetNormalizer
from benchmark.rulegen_benchmark import RuleGenBenchmark
from benchmark.attackgen_benchmark import AttackGenBenchmark
from pypdf import PdfReader

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = get_agent_logger("benchmark_runner")

OUTPUT_DIR = Path("data/benchmark_results")

async def process_single_file(orchestrator, file_path: Path):
    """Process a single file using the same logic as benchmark_single.py"""
    logger.info(f"Processing: {file_path.name}")
    
    # 1. Read PDF/Text
    content = ""
    try:
        if file_path.suffix.lower() == '.pdf':
            reader = PdfReader(str(file_path))
            for page in reader.pages:
                content += page.extract_text() + "\n"
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return None

    # 2. Normalize
    normalizer = PDFDatasetNormalizer()
    raw_event = {
        "content": content,
        "source": str(file_path),
        "metadata": {"filename": file_path.name}
    }
    report_data = normalizer.normalize_event(raw_event)
    
    # 3. Run Pipeline with force ignore_duplicates
    start_time = time.time()
    try:
        # Force ignore_duplicates=True ensures we always process, consistent with benchmark_single
        result = await orchestrator.run_pipeline([report_data], context={"ignore_duplicates": True})
    except Exception as e:
        logger.error(f"Pipeline failed for {file_path.name}: {e}")
        return None
        
    duration = time.time() - start_time
    
    # 4. Metrics & Quality Assessment
    extracted_ttps = result.get('extraction', {}).get('results', [])
    if extracted_ttps:
         extracted_ttps = extracted_ttps[0].get('extracted_ttps', [])
         
    rules = result.get('rules', {}).get('rules', [])
    siem_verification = result.get('siem_verification', [])
    
    # Run Quality Logic
    quality_scores = {}
    
    # Configure Benchmark
    config_path = Path("config/benchmark_config.yaml")
    if config_path.exists():
        with open(config_path, "r") as f:
            config_str = f.read()
            for key, value in os.environ.items():
                config_str = config_str.replace(f"${{{key}}}", value)
            benchmark_config = yaml.safe_load(config_str)
    else:
        benchmark_config = {
            "llm_judge": {
                "enabled": True, 
                "model": "gemini-2.0-flash",
                "temperature": 0.3
            }
        }
    
    rulegen_benchmark = RuleGenBenchmark(benchmark_config)
    attackgen_benchmark = AttackGenBenchmark(benchmark_config)
    
    # Rules Benchmark
    if rules:
        benchmark_input = []
        for r in rules:
            benchmark_input.append({
                "sigma_rule": r,
                "attack_id": r.get("tags", ["T1059"])[0] if r.get("tags") else "T1059",
                "technique_name": r.get("title", "Unknown"),
                "tactic": "execution"
            })
        try:
            await rulegen_benchmark.evaluate_batch(benchmark_input)
            quality_scores['rulegen_avg'] = rulegen_benchmark.get_statistics().get('average_score', 0)
            
            # Save RuleGen Quality Report
            quality_file = OUTPUT_DIR / f"quality_report_rulegen_{file_path.stem}.json"
            rulegen_benchmark.export_results(str(quality_file))
        except Exception as e:
            logger.warning(f"RuleGen benchmark failed: {e}")

    # Benchmark Attacks
    attacks = result.get('attacks', [])
    if attacks:
        attack_benchmark_input = []
        for a in attacks:
            # Map result structure to benchmark expectation
            attack_benchmark_input.append({
                "name": a.get("technique_name", "Unknown Attack"),
                "command": a.get("command"),
                "explanation": a.get("description", "No description provided"),
                "mitre_attack_id": a.get("technique_id", "T1xxx"),
                "technique_name": a.get("technique_name", "Unknown"),
                "tactic": a.get("tactic", "execution"),
                "platform": a.get("platform", "windows"),
                "indicators": [], 
                "cleanup": "",
                "prerequisites": ["Admin" if a.get("requires_admin") else "User"],
                "command_id": a.get("id"),
                "confidence_score": a.get("confidence_score", 0.8),
                "metadata": {"campaign": "benchmark", "threat_actor": "APT"}
            })
            
        try:
            await attackgen_benchmark.evaluate_batch(attack_benchmark_input)
            quality_scores['attackgen_avg'] = attackgen_benchmark.get_statistics().get('average_score', 0)
            
            # Save AttackGen Quality Report
            quality_file_attacks = OUTPUT_DIR / f"quality_report_attackgen_{file_path.stem}.json"
            attackgen_benchmark.export_results(str(quality_file_attacks))
        except Exception as e:
            logger.warning(f"AttackGen benchmark failed: {e}")

    # Calculate Quality Score
    quality_score_avg = sum(quality_scores.values()) / len(quality_scores) if quality_scores else 0
    
    # Save Result
    result_entry = result.copy()
    result_entry['benchmark_metrics'] = {
        "duration_s": duration,
        "quality_score": quality_score_avg
    }
    
    result_file = OUTPUT_DIR / f"result_{file_path.stem}.json"
    with open(result_file, "w") as f:
        json.dump(result_entry, f, indent=2, default=str)
    
    # Return Summary Data
    return {
        "file": file_path.name,
        "status": "success",
        "duration_s": duration,
        "ttps_found": len(extracted_ttps),
        "rules_generated": len(rules),
        "attacks_generated": len(attacks),
        "siem_detections": len([x for x in siem_verification if x.get('detected')]),
        "quality_score": quality_score_avg
    }

async def main():
    parser = argparse.ArgumentParser(description="Robust Batch Benchmark Runner")
    parser.add_argument("--dir", type=str, default="data/APTnotes/2023", help="Directory containing reports")
    parser.add_argument("--limit", type=int, help="Limit number of reports")
    parser.add_argument("--file", type=str, help="Process single file by name")
    parser.add_argument("--skip-existing", action="store_true", help="Skip reports that already have a result file")
    args = parser.parse_args()
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Get Files
    if args.file:
        files = [Path(args.file)]
        if not files[0].exists():
            # Try prepending default dir
            files = [Path(args.dir) / args.file]
    else:
        source_dir = Path(args.dir)
        files = list(source_dir.glob("*.pdf")) + list(source_dir.glob("*.txt"))
        
    if args.limit:
        files = files[:args.limit]
        
    logger.info(f"Found {len(files)} reports to process")
    
    # Initialize Orchestrator ONCE
    orchestrator = LangChainOrchestrator(mode="langchain")
    await orchestrator.initialize()
    await orchestrator.start_all()
    
    summary_results = []
    
    try:
        for i, file_path in enumerate(files):
            msg = f"[{i+1}/{len(files)}] >>> Processing: {file_path.name}"
            print(f"\n{'-'*80}")
            print(f" {msg}")
            print(f"{'-'*80}\n")
            print(f" {msg}")
            print(f"{'-'*80}\n")
            logger.info(msg)
            
            # Check for existing result
            result_file = OUTPUT_DIR / f"result_{file_path.stem}.json"
            if args.skip_existing and result_file.exists():
                print(f"Skipping {file_path.name} (Result exists)")
                logger.info(f"Skipping {file_path.name} because result file exists and --skip-existing is set")
                
                # Try to load existing result for summary
                try:
                    with open(result_file, 'r') as f:
                        data = json.load(f)
                    
                    if data.get('status') == 'success':
                         metrics = data.get('benchmark_metrics', {})
                         final_report = data.get('final_report', {})
                         
                         summary_results.append({
                            "file": file_path.name,
                            "status": "skipped (success)",
                            "duration_s": metrics.get('duration_s', 0),
                            "ttps_found": final_report.get('total_ttps', 0),
                            "quality_score": metrics.get('quality_score', 0)
                         })
                         continue
                except Exception:
                    pass # If read fails, just process it or continue? Better to just skip execution.
                    
                continue
            
            summary = await process_single_file(orchestrator, file_path)
            
            if summary:
                summary_results.append(summary)
            else:
                summary_results.append({
                    "file": file_path.name,
                    "status": "failed"
                })
            
            # Brief pause
            await asyncio.sleep(2)
            
    finally:
        await orchestrator.cleanup()
        
    # Save Summary
    summary_file = OUTPUT_DIR / "benchmark_runner_summary.json"
    with open(summary_file, "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "total_files": len(files),
            "results": summary_results
        }, f, indent=2)
    
    logger.info(f"Batch Benchmark Complete. Summary saved to {summary_file}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
