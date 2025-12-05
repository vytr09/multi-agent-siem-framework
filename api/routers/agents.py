from fastapi import APIRouter, HTTPException, BackgroundTasks, Body
from typing import Dict, Any, List, Optional
from api.core.agent_manager import agent_manager
from pydantic import BaseModel

router = APIRouter()

class PipelineInput(BaseModel):
    cti_reports: Optional[List[Dict[str, Any]]] = None
    extracted_ttps: Optional[List[Dict[str, Any]]] = None

@router.get("/")
async def list_agents():
    """Get status and details of all agents"""
    # Ensure config is loaded to display details even if stopped
    await agent_manager.ensure_config_loaded()
        
    return {
        "status": agent_manager.get_agent_status(),
        "details": agent_manager.get_agent_details()
    }

@router.post("/initialize")
async def initialize_agents():
    """Initialize all agents"""
    await agent_manager.initialize()
    await agent_manager.start_all()
    return {"status": "initialized"}

@router.post("/{agent_name}/start")
async def start_agent(agent_name: str):
    """Start a specific agent"""
    try:
        await agent_manager.start_agent(agent_name)
        return {"status": "started", "agent": agent_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/run")
async def run_pipeline(input_data: PipelineInput, background_tasks: BackgroundTasks):
    """Run the agent pipeline"""
    # For now, we'll run it synchronously to return results, 
    # but in production this should be a background task with a job ID
    try:
        result = await agent_manager.run_pipeline(input_data.dict(exclude_none=True))
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{agent_name}/run")
async def run_agent(agent_name: str, input_data: Dict[str, Any] = Body(...)):
    """Run a specific agent"""
    try:
        result = await agent_manager.run_agent(agent_name, input_data)
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{agent_name}/stop")
async def stop_agent(agent_name: str):
    """Stop a specific agent"""
    try:
        await agent_manager.stop_agent(agent_name)
        return {"status": "stopped", "agent": agent_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_agents():
    """Stop all agents"""
    await agent_manager.stop_all()
    return {"status": "stopped"}
