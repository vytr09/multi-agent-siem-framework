#!/usr/bin/env python3
"""
Full Collector Agent Pipeline Test

1. Fetch 10 real MISP events
2. Load 1 offline PDF
3. Normalize all 11 items
4. Save unified JSON for Extractor Agent
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load env and disable SSL warnings
load_dotenv()
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agents.collector.agent import CollectorAgent

async def test_full_collection():
    # 1. Configuration for both MISP and datasets
    cfg = {
        "sources": {
            "misp": {
                "url": os.getenv("MISP_URL"),
                "api_key": os.getenv("MISP_API_KEY"),
                "verify_cert": False,
                "days_back": 7,
                "use_mock": False,
                "batch_size": 10
            },
            "datasets": {
                "enabled": True,
                "offline_data_dir": "data/datasets"
            }
        },
        "interval": 300,
        "batch_size": 10,
        "max_retries": 3
    }

    # 2. Start collector
    collector = CollectorAgent("full_test", cfg)
    await collector.start()

    # 3. Execute full collection: limit MISP to 10, include PDF
    result = await collector.execute({
        "sources": ["misp", "datasets"],
        "max_reports": 10
    })

    await collector.stop()

    # 4. Check counts
    raw = result["collection_summary"]["raw_reports_collected"]
    norm = result["collection_summary"]["normalized_reports"]
    indicators = result["collection_summary"]["total_indicators"]
    print(f"[INFO] Raw fetched: {raw}")
    print(f"[INFO] Normalized: {norm}")
    print(f"[INFO] Total indicators: {indicators}")
    assert raw == norm, "Every raw report must normalize successfully"
    assert norm == 11, "Expected 10 MISP + 1 PDF = 11 reports"

    # 5. Save unified JSON
    out_file = "data/normalized/full_pipeline.json"
    Path("data/normalized").mkdir(exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result["normalized_reports"], f, indent=2, ensure_ascii=False)
    print(f"[OK] Full pipeline output saved: {out_file}")

    # 6. Display sample
    sample = result["normalized_reports"][0]
    print("[INFO] Sample normalized report keys:", list(sample.keys()))
    print("   Title:", sample.get("title"))
    print("   Source:", sample.get("source"))

if __name__ == "__main__":
    asyncio.run(test_full_collection())
