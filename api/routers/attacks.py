from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import json
from pathlib import Path

router = APIRouter()

ATTACKS_FILE = Path("data/output/langchain/attackgen/generated_attacks.json")

@router.get("/", response_model=List[Dict[str, Any]])
async def get_attacks():
    """Get all generated attack commands"""
    # Try reading from unified pipeline result first
    pipeline_file = Path("data/output/langchain/pipeline_result.json")
    if pipeline_file.exists():
        try:
            with open(pipeline_file, "r") as f:
                data = json.load(f)
                # Structure: data['attacks'] (list)
                if "attacks" in data:
                     return data["attacks"]
        except Exception as e:
            print(f"Error reading pipeline attacks: {e}")

    if not ATTACKS_FILE.exists():
        print(f"[DEBUG] Attacks file not found at {ATTACKS_FILE}")
        return []
        
    try:
        print(f"[DEBUG] Reading attacks from {ATTACKS_FILE} (Last Modified: {ATTACKS_FILE.stat().st_mtime})")
        with open(ATTACKS_FILE, "r") as f:
            data = json.load(f)
            
            if isinstance(data, dict):
                if "attack_commands" in data:
                    print(f"[DEBUG] Found {len(data['attack_commands'])} attacks")
                    return data["attack_commands"]
                return [data]
            return data
    except Exception as e:
        print(f"[ERROR] Reading attacks: {e}")
        return []
