from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any
import os
from pathlib import Path

router = APIRouter()

LOG_FILE = Path("logs/system.log")

@router.get("/")
async def get_logs(limit: int = Query(100, ge=1, le=1000)):
    """Get system logs (last N lines)"""
    if not LOG_FILE.exists():
        return {"logs": []}
    
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            # Return last 'limit' lines, reversed (newest first)
            return {"logs": [line.strip() for line in reversed(lines[-limit:])]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")
