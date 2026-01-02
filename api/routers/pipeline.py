"""Pipeline router - serves pipeline execution results"""
from fastapi import APIRouter, HTTPException
from pathlib import Path
import json

router = APIRouter()

RESULT_PATH = Path("data/output/langchain/pipeline_result.json")


@router.get("/result")
async def get_pipeline_result():
    """Get the latest pipeline result"""
    if not RESULT_PATH.exists():
        return {"status": "no_result", "message": "No pipeline has been run yet."}
    
    try:
        with open(RESULT_PATH, "r", encoding="utf-8") as f:
            result = json.load(f)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load result: {str(e)}")
