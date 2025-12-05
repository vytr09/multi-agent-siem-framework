from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import json
from pathlib import Path

router = APIRouter()

ATTACKS_FILE = Path("data/output/langchain/attackgen/generated_attacks.json")

@router.get("/", response_model=List[Dict[str, Any]])
async def get_attacks():
    """Get all generated attack commands"""
    if not ATTACKS_FILE.exists():
        return []
        
    try:
        with open(ATTACKS_FILE, "r") as f:
            data = json.load(f)
            
            if isinstance(data, dict):
                if "attack_commands" in data:
                    return data["attack_commands"]
                return [data]
            return data
    except Exception as e:
        print(f"Error reading attacks: {e}")
        return []
