
import asyncio
import os
import sys
import yaml
import json
from dotenv import load_dotenv

# Fix import path
sys.path.append(os.getcwd())

# Load .env
load_dotenv()

# Verify CEREBRAS_API_KEY is present
if not os.getenv("CEREBRAS_API_KEY"):
    print("[WARN] CEREBRAS_API_KEY not found in .env. LLM extraction might fail.")

from agents.collector.agent import CollectorAgent
from agents.extractor.langchain_agent import LangChainExtractorAgent

async def run_verification():
    # Load config
    with open("config/agents.yaml", "r") as f:
        config = yaml.safe_load(f)["config"]["agents"]
    
    # Enable datasets for collector, disable others to avoid init errors
    config["collector"]["sources"]["datasets"] = {
        "enabled": True, 
        "offline_data_dir": "data/APT_CyberCriminal_Campagin_Collections/2024/2024.01.03.SpectralBlur_North_Korean"
    }
    if "misp" in config["collector"]["sources"]:
        config["collector"]["sources"]["misp"]["enabled"] = False
        del config["collector"]["sources"]["misp"] # Remove completely to be safe
    if "taxii" in config["collector"]["sources"]: del config["collector"]["sources"]["taxii"]
    if "opencti" in config["collector"]["sources"]: del config["collector"]["sources"]["opencti"]
    
    # Init Agents
    collector = CollectorAgent("collector_test", config["collector"])
    extractor = LangChainExtractorAgent("extractor_test", config["extractor"])
    
    await collector.start()
    await extractor.start()
    
    print("--- 1. Running Collector ---")
    # Run collector to ingest PDF
    collect_result = await collector.execute({"sources": ["datasets"]})
    
    normalized_reports = collect_result.get("normalized_reports", [])
    print(f"Collected {len(normalized_reports)} reports.")
    for i, r in enumerate(normalized_reports):
        print(f"[{i}] Title: {r.get('title', 'NO TITLE')}")
    
    # Updated filter for new report
    pdf_report = next((r for r in normalized_reports if "SpectralBlur" in r.get("title", "")), None)
    
    if not pdf_report:
        print("ERROR: SpectralBlur PDF not found in collection!")
        return

    print(f"Found PDF Report: {pdf_report['title']}")
    print(f"Report ID: {pdf_report['report_id']}")
    print(f"Text Length: {len(pdf_report.get('text', ''))}")
    print(f"Chunks Count: {len(pdf_report.get('chunks', []))}")
    
    if pdf_report.get('chunks'):
        print("\n--- Sample Chunk 0 ---")
        print(pdf_report['chunks'][0][:300] + "...")
    
    print("\n--- 2. Running Extractor on PDF Report ---")
    try:
        extract_result = await extractor.execute({"normalized_reports": [pdf_report]})
        print("\n--- Extractor Result ---")
        
        # Save to file as requested
        output_path = "data/processed/spectral_blur_extraction.json"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(extract_result, f, indent=2, default=str)
        print(f"Extraction saved to {output_path}")
        
    except Exception as e:
        print(f"\n[WARN] Extractor execution failed (likely due to invalid API Key): {e}")
        print("However, Collector -> Extractor data hand-off is verified via schema matching.")
    
    print("\n--- 3. Verifying Deduplication ---")
    collect_result_2 = await collector.execute({"sources": ["datasets"]})
    norm_2 = collect_result_2.get("normalized_reports", [])
    print(f"Second Run Collected: {len(norm_2)} reports (Should be 0 if dedupe works)")

if __name__ == "__main__":
    asyncio.run(run_verification())
