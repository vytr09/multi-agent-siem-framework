from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import json
import os
from pathlib import Path

router = APIRouter()

RULES_FILE = Path("data/output/rulegen/generated_rules.json")

@router.get("/", response_model=List[Dict[str, Any]])
async def get_rules():
    """Get all generated Sigma rules"""
    if not RULES_FILE.exists():
        return []
    
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            
            # Handle nested structure from RuleGen agent
            if isinstance(data, dict):
                # Check for rule_generation_results key (new format)
                if "rule_generation_results" in data:
                    # Extract the sigma_rule from each result
                    return [item.get("sigma_rule", item) for item in data["rule_generation_results"]]
                # Fallback for other dict structures
                return [data]
            
            # If it's already a list
            return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read rules: {str(e)}")

@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    """Get a specific rule by ID (mock implementation as IDs might not be unique/stable)"""
    # This is a placeholder. Real implementation would need stable IDs.
    rules = await get_rules()
    for rule in rules:
        if rule.get("title") == rule_id or rule.get("id") == rule_id:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")
