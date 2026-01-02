from fastapi import APIRouter, HTTPException, Body
from typing import List, Dict, Any, Optional
import yaml
from pathlib import Path
from pydantic import BaseModel
from api.core.agent_manager import agent_manager

router = APIRouter()

CONFIG_PATH = Path("config/providers.yaml")

class ProviderModel(BaseModel):
    name: str
    type: str
    model: str
    api_key_env: str
    priority: int
    base_url: Optional[str] = None

class ProvidersConfig(BaseModel):
    providers: List[ProviderModel]

@router.get("/", response_model=ProvidersConfig)
async def get_providers():
    """Get list of configured LLM providers"""
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="Providers config file not found")
        
    try:
        with open(CONFIG_PATH, "r") as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read config: {str(e)}")

@router.post("/")
async def update_providers(config: ProvidersConfig):
    """Update LLM providers configuration"""
    try:
        # Sort by priority before saving
        providers_list = [p.dict(exclude_none=True) for p in config.providers]
        providers_list.sort(key=lambda x: x['priority'])
        
        data = {"providers": providers_list}
        
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(data, f, sort_keys=False)
            
        return {"status": "success", "message": "Configuration saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save config: {str(e)}")

@router.post("/active")
async def set_active_provider(provider_name: str = Body(..., embed=True)):
    """Set a specific provider as active (Priority 1)"""
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="Providers config file not found")
        
    try:
        with open(CONFIG_PATH, "r") as f:
            data = yaml.safe_load(f)
            
        providers = data.get("providers", [])
        target_found = False
        
        # Shift priorities
        # 1. Provide requested provider gets priority 1
        # 2. Others shift down
        
        new_providers = []
        for p in providers:
            if p.get("name") == provider_name:
                p["priority"] = 1
                target_found = True
            else:
                # If priority was 1, move it to 2 (or just re-normalize all)
                pass
        
        if not target_found:
             raise HTTPException(status_code=404, detail=f"Provider '{provider_name}' not found")

        # Re-sort/Re-normalize priorities
        # Filter request provider
        target = next(p for p in providers if p.get("name") == provider_name)
        others = [p for p in providers if p.get("name") != provider_name]
        
        # Sort others by their original priority (to keep relative order)
        others.sort(key=lambda x: x.get('priority', 99))
        
        # Re-assign priorities
        target['priority'] = 1
        for i, p in enumerate(others):
            p['priority'] = i + 2
            
        # Combine
        all_providers = [target] + others
        
        # Save
        with open(CONFIG_PATH, "w") as f:
            yaml.dump({"providers": all_providers}, f, sort_keys=False)
            
        return {"status": "success", "message": f"Provider '{provider_name}' set to active"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update provider: {str(e)}")

@router.post("/reload")
async def reload_agents():
    """Reload agent configuration to apply provider changes"""
    try:
        # Force stop and re-init
        await agent_manager.stop_all()
        await agent_manager.initialize()
        await agent_manager.start_all()
        return {"status": "success", "message": "Agents reloaded with new configuration"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload agents: {str(e)}")
