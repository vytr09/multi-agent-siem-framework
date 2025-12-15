"""
Multi-Agent SIEM Framework - Main Execution Script

This script serves as the main entry point for running the agent pipeline 
in a 'production' or manual mode, separate from the test suite.

Usage:
    python scripts/run_agents.py --input "Attacker used PowerShell..."
    python scripts/run_agents.py --file path/to/report.pdf
    python scripts/run_agents.py --dir path/to/reports/
"""

import sys
import os
import argparse
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.logging import get_agent_logger
from core.langchain_orchestrator import LangChainOrchestrator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = get_agent_logger("run_agents")

async def main():
    parser = argparse.ArgumentParser(description="Multi-Agent SIEM Framework Pipeline")
    
    # Input arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", "-i", type=str, help="Raw text input describing the threat")
    group.add_argument("--file", "-f", type=str, help="Path to a single CTI report file (PDF, TXT, JSON)")
    group.add_argument("--dir", "-d", type=str, help="Path to a directory containing CTI reports")
    
    # Configuration arguments
    parser.add_argument("--mode", "-m", type=str, choices=["langchain", "traditional", "hybrid"], default="langchain", help="Agent operation mode")
    parser.add_argument("--config", "-c", type=str, default="config/agents.yaml", help="Path to configuration file")
    
    # Execution flags
    parser.add_argument("--no-siem", action="store_true", help="Skip SIEM verification stage")
    parser.add_argument("--no-attack", action="store_true", help="Skip Attack Generation stage")
    parser.add_argument("--output", "-o", type=str, default="data/output/manual_run", help="Output directory")

    args = parser.parse_args()
    
    # 1. Prepare Input Data
    cti_reports = []
    
    if args.input:
        cti_reports.append({
            "id": "manual_input_1",
            "content": args.input,
            "source": "manual_cli",
            "timestamp": "now"
        })
        logger.info(f"Loaded 1 manual input report")
        
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            sys.exit(1)
            
        # Basic content reading (expand for PDF later if needed, or rely on normalizers)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            cti_reports.append({
                "id": file_path.name,
                "content": content,
                "source": str(file_path),
                "timestamp": "now"
            })
            logger.info(f"Loaded report from {file_path}")
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            sys.exit(1)
            
    elif args.dir:
        dir_path = Path(args.dir)
        if not dir_path.exists():
            logger.error(f"Directory not found: {dir_path}")
            sys.exit(1)
            
        # Read all txt/json files
        for fpath in dir_path.glob("*.*"):
            if fpath.suffix.lower() in ['.txt', '.json', '.md']:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    cti_reports.append({
                        "id": fpath.name,
                        "content": content,
                        "source": str(fpath),
                        "timestamp": "now"
                    })
                except Exception:
                    pass
        logger.info(f"Loaded {len(cti_reports)} reports from {dir_path}")

    if not cti_reports:
        logger.error("No valid reports found to process.")
        sys.exit(1)

    # 2. Initialize Orchestrator
    try:
        orchestrator = LangChainOrchestrator(config_path=args.config, mode=args.mode)
        await orchestrator.initialize()
        
        # Apply overrides
        orchestrator.output_dir = Path(args.output)
        
        if args.no_siem:
            orchestrator.siem_integrator = None
            logger.info("SIEM verification disabled via flag")
            
        if args.no_attack:
            orchestrator.attackgen = None
            logger.info("Attack generation disabled via flag")
            
        await orchestrator.start_all()
        
    except Exception as e:
        logger.error(f"Failed to initialize orchestrator: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # 3. Run Pipeline
    try:
        logger.info("Starting pipeline execution...")
        result = await orchestrator.run_pipeline(cti_reports)
        
        # 4. Report Results
        if result['status'] == 'success':
            print("\n" + "="*80)
            print("PIPELINE EXECUTION SUCCESSFUL")
            print("="*80)
            print(f"Final Score: {result.get('final_score', 0):.2f}")
            print(f"Iterations: {result.get('iterations', 0)}")
            print(f"\nResults saved to: {args.output}")
            print(f"Full Report: {args.output}/{args.mode}/pipeline_result.json")
            
            # Print simplified summary
            rules = result.get('rules', {}).get('rules', [])
            print(f"\nGenerated {len(rules)} Rules:")
            for rule in rules:
                print(f"  - {rule.get('title')} (Status: {rule.get('siem_verification', {}).get('status', 'unknown')})")
                
        else:
            print("\n" + "="*80)
            print("PIPELINE EXECUTION FAILED")
            print("="*80)
            print(f"Error: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        logger.error(f"Pipeline runtime error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await orchestrator.cleanup()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
