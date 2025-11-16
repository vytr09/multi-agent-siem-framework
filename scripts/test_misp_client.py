#!/usr/bin/env python3
import asyncio
import os
import sys
import urllib3
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.collector.clients.misp_client import create_misp_client

async def test_real_misp_full():
    config = {
        "url": os.getenv("MISP_URL"),
        "api_key": os.getenv("MISP_API_KEY"),
        "verify_cert": False,
        "days_back": 7,
        "batch_size": 10
    }

    client = create_misp_client(config, use_mock=False)
    connected = await client.test_connection()
    print(f"Connection: {'Success' if connected else 'Failed'}")
    if not connected:
        return

    # 1. Get summary via synchronous search_index (no await)
    summary_list = client.misp.search_index(
        published=True,
        timestamp=f"{config['days_back']}d",
        limit=config['batch_size'],
        pythonify=False
    )
    print(f"Summary events fetched: {len(summary_list)} IDs")

    # 2. Fetch full details synchronously
    print("Fetching full event data (first 3 IDs):")
    for ev in summary_list[:3]:
        evt = ev.get("Event", ev)
        event_id = evt.get("id")
        full = client.misp.get_event(event_id, pythonify=False)  # sync
        data = full.get("Event", full)
        print(f"\n• Event ID: {data.get('id')}")
        print(f"  Info: {data.get('info')}")
        print(f"  Attributes (IOCs): {len(data.get('Attribute', []))}")
        print(f"  Tags: {[t['name'] for t in data.get('Tag', [])]}")

asyncio.run(test_real_misp_full())
