
import sys
import os
import asyncio
import time
import json
import yaml
from pathlib import Path
from datetime import datetime

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
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = get_agent_logger("benchmark_single")

TARGET_FILE = Path("data/APTnotes/2023/Checkpoint_BlindEagle-Targeting-Ecuador-Sharpened-Tools(01-05-2023).pdf")
OUTPUT_DIR = Path("data/benchmark_results")

async def run_single_benchmark():
    if not TARGET_FILE.exists():
        logger.error(f"File not found: {TARGET_FILE}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Starting benchmark for: {TARGET_FILE}")
    
    # Initialize Normalizer
    normalizer = PDFDatasetNormalizer()
    
    # Initialize Orchestrator
    orchestrator = LangChainOrchestrator(mode="langchain")
    logger.info("Initializing Orchestrator...")
    await orchestrator.initialize()
    await orchestrator.start_all()
    
    # Read PDF
    logger.info("Reading PDF...")
    try:
        reader = PdfReader(str(TARGET_FILE))
        content = ""
        for page in reader.pages:
            content += page.extract_text() + "\n"
    except Exception as e:
        logger.error(f"Failed to read PDF: {e}")
        return

    # Normalize
    raw_event = {
        "content": content,
        "source": str(TARGET_FILE),
        "metadata": {"filename": TARGET_FILE.name}
    }
    report_data = normalizer.normalize_event(raw_event)
    
    # Run Pipeline
    logger.info(">>> STARTING PIPELINE EXECUTION <<<")
    start_time = time.time()
    
    # Force ignore duplicates to ensure full processing
    result = await orchestrator.run_pipeline([report_data], context={"ignore_duplicates": True})
    
    end_time = time.time()
    duration = end_time - start_time
    
    logger.info(">>> PIPELINE EXECUTION FINISHED <<<")
    
    # --- Metrics & Output ---
    
    extracted_ttps = result.get('extraction', {}).get('results', []) 
    # Adjust for list wrapper in orchestrator output
    if extracted_ttps:
         extracted_ttps = extracted_ttps[0].get('extracted_ttps', [])
         
    rules = result.get('rules', {}).get('rules', [])
    attacks = []
    
    # Extract attacks (from Orchestrator's internal structure or verify_rule integration)
    siem_verification = result.get('siem_verification', [])
    for sv in siem_verification:
        # Reconstruct attack object if possible, or count
        attacks.append({"id": sv.get("attack_id")})
    
    # --- Quality Assessment (Stage 6 Logic) ---
    logger.info("Running Quality Assessment (LLM-as-Judge)...")
    
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
    
    quality_scores = {}
    
    # Benchmark Rules
    if rules:
        logger.info(f" Benchmarking {len(rules)} Rules...")
        benchmark_input = []
        for r in rules:
            benchmark_input.append({
                "sigma_rule": r,
                "attack_id": r.get("tags", ["T1059"])[0] if r.get("tags") else "T1059",
                "technique_name": r.get("title", "Unknown"),
                "tactic": "execution"
            })
        
        await rulegen_benchmark.evaluate_batch(benchmark_input)
        quality_scores['rulegen_avg'] = rulegen_benchmark.get_statistics().get('average_score', 0)
        
        # Save Quality Report
        quality_file = OUTPUT_DIR / f"quality_report_rulegen_{TARGET_FILE.stem}.json"
        rulegen_benchmark.export_results(str(quality_file))
        logger.info(f"RuleGen quality report saved to {quality_file}")

    # Benchmark Attacks
    attacks = result.get('attacks', [])
    if attacks:
        logger.info(f" Benchmarking {len(attacks)} Attacks...")
        attack_benchmark_input = []
        for a in attacks:
            # Map result structure to benchmark expectation
            # Benchmark expects: name, command, explanation, indicators, prerequisites, cleanup, platform, technique_name, mitre_attack_id
            attack_benchmark_input.append({
                "name": a.get("technique_name", "Unknown Attack"),
                "command": a.get("command"),
                "explanation": a.get("description", "No description provided"),
                "mitre_attack_id": a.get("technique_id", "T1xxx"),
                "technique_name": a.get("technique_name", "Unknown"),
                "tactic": a.get("tactic", "execution"),
                "platform": a.get("platform", "windows"),
                "indicators": [], # Might not be explicitly present in simple output
                "cleanup": "", # Might not be present
                "prerequisites": ["Admin" if a.get("requires_admin") else "User"],
                "command_id": a.get("id"),
                "confidence_score": a.get("confidence_score", 0.8),
                "metadata": {"campaign": "benchmark", "threat_actor": "APT"}
            })
            
        await attackgen_benchmark.evaluate_batch(attack_benchmark_input)
        stats = attackgen_benchmark.get_statistics()
        quality_scores['attackgen_avg'] = stats.get('average_score', 0)
        
        # Save Quality Report
        quality_file_attacks = OUTPUT_DIR / f"quality_report_attackgen_{TARGET_FILE.stem}.json"
        attackgen_benchmark.export_results(str(quality_file_attacks))
        logger.info(f"AttackGen quality report saved to {quality_file_attacks}")
    else:
        logger.warning("No attacks found to benchmark.")
    
    # Calculate Quality Score
    if quality_scores:
        quality_score_avg = sum(quality_scores.values()) / len(quality_scores)
    else:
        quality_score_avg = 0
    
    # Save Main Result File
    result_entry = result.copy()
    result_entry['benchmark_metrics'] = {
        "duration_s": duration,
        "quality_score": quality_score_avg
    }
    
    result_file = OUTPUT_DIR / f"result_{TARGET_FILE.stem}.json"
    with open(result_file, "w") as f:
        json.dump(result_entry, f, indent=2, default=str)
    logger.info(f"Full pipeline result saved to {result_file}")

    print("\n" + "="*60)
    print(f"BENCHMARK RESULT FOR: {TARGET_FILE.name}")
    print(f"Time Taken: {duration:.2f} seconds ({duration/60:.2f} minutes)")
    print(f"Status: {result.get('status')}")
    print(f"TTPs Extracted: {len(extracted_ttps)}")
    print(f"Rules Generated: {len(rules)}")
    print(f"Verified Detections: {len([x for x in siem_verification if x.get('detected')])}")
    print(f"Quality Score (Avg): {quality_score_avg:.2f}")
    print(f"Output File: {result_file}")
    print("="*60 + "\n")
    
    await orchestrator.cleanup()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_single_benchmark())
