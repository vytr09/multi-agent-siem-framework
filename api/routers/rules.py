from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import json
import os
from pathlib import Path
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

RULES_FILE = Path("data/output/rulegen/generated_rules.json")

@router.get("/", response_model=List[Dict[str, Any]])
async def get_rules():
    """Get all generated Sigma rules"""
    # Try reading from unified pipeline result first
    pipeline_file = Path("data/output/langchain/pipeline_result.json")
    if pipeline_file.exists():
        try:
            with open(pipeline_file, "r") as f:
                data = json.load(f)
                # Structure: data['rules']['rules']
                if "rules" in data and isinstance(data["rules"], dict):
                     return data["rules"].get("rules", [])
        except Exception as e:
            logger.error(f"Error reading pipeline rules: {e}")

    # Fallback to legacy file
    if not RULES_FILE.exists():
        logger.warning(f"[DEBUG] Rules file not found at {RULES_FILE}")
        return []
    
    try:
        logger.info(f"[DEBUG] Reading rules from {RULES_FILE} (Size: {RULES_FILE.stat().st_size} bytes, Last Modified: {RULES_FILE.stat().st_mtime})")
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
            
            # Handle nested structure from RuleGen agent
            if isinstance(data, dict):
                # Check for rule_generation_results key (new format)
                if "rule_generation_results" in data:
                    logger.info(f"[DEBUG] Found {len(data['rule_generation_results'])} rules in rule_generation_results")
                    # Extract the sigma_rule from each result
                    return [item.get("sigma_rule", item) for item in data["rule_generation_results"]]
                # Fallback for other dict structures
                return [data]
            
            # If it's already a list
            logger.info(f"[DEBUG] Found {len(data)} rules in list format")
            return data
    except Exception as e:
        logger.error(f"[ERROR] Failed to read rules: {e}")
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
