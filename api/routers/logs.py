from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import os
from pathlib import Path
import asyncio
import logging

router = APIRouter()
logger = logging.getLogger("api.logs")

LOG_FILE = Path("logs/system.log")

@router.get("/")
async def get_logs(limit: int = Query(100, ge=1, le=1000)):
    """Get system logs (last N lines)"""
    if not LOG_FILE.exists():
        return {"logs": []}
    
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            # Return last 'limit' lines in chronological order (oldest first, newest last)
            return {"logs": [line.strip() for line in lines[-limit:]]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")

@router.websocket("/ws")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    try:
        if not LOG_FILE.exists():
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            LOG_FILE.touch()

        with open(LOG_FILE, "r") as f:
            # Move to end of file to stream only new logs
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if line:
                    try:
                        await websocket.send_text(line.strip())
                    except Exception:
                        break # Client disconnected
                else:
                    await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.info("Client disconnected from log stream")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close()

