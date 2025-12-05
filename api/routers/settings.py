from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, Optional
import yaml
from pathlib import Path
import os
from pydantic import BaseModel
from dotenv import dotenv_values, set_key

router = APIRouter()

CONFIG_PATH = Path("config/agents.yaml")
ENV_PATH = Path(".env")

class SettingsUpdate(BaseModel):
    config: Optional[Dict[str, Any]] = None
    env: Optional[Dict[str, str]] = None

def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="Configuration file not found")
    
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            # Unwrap root 'config' key if present
            if data and 'config' in data and 'agents' in data['config']:
                return data['config']
            return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load config: {str(e)}")

def save_config(config: Dict[str, Any]):
    try:
        # Wrap in root 'config' key if not present, to maintain file structure
        data_to_save = config
        if 'agents' in config and 'config' not in config:
            data_to_save = {'config': config}
            
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(data_to_save, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save config: {str(e)}")

def load_env() -> Dict[str, str]:
    if not ENV_PATH.exists():
        return {}
    return dotenv_values(ENV_PATH)

def save_env(env_updates: Dict[str, str]):
    try:
        print(f"DEBUG: Received env updates: {env_updates}")
        # We use set_key to preserve comments and structure if possible
        # But set_key writes one by one, which might be slow. 
        # For a few keys it's fine.
        for key, value in env_updates.items():
            # If value is masked (contains ****), don't update it
            if value and "****" not in value:
                 print(f"DEBUG: Setting {key} to {value[:5]}...")
                 set_key(ENV_PATH, key, value)
                 os.environ[key] = value
            else:
                 print(f"DEBUG: Skipping {key} (masked or empty)")
    except Exception as e:
        print(f"DEBUG: Error saving env: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save env vars: {str(e)}")

@router.get("/")
async def get_settings():
    """Get current system configuration and env vars"""
    config = load_config()
    env = load_env()
    
    return {
        "config": config,
        "env": env
    }

from api.core.agent_manager import agent_manager

@router.post("/")
async def update_settings(update: SettingsUpdate):
    """Update system configuration and env vars"""
    if update.config:
        save_config(update.config)
    
    if update.env:
        save_env(update.env)
    
    # Force reload of agents to pick up new config/env
    await agent_manager.stop_all()
        
    return {"status": "success", "message": "Configuration updated successfully"}
