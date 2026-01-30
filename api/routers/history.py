"""
Pipeline History API Router
Provides endpoints to list and retrieve past pipeline runs
"""
from fastapi import APIRouter, HTTPException
from pathlib import Path
from typing import List, Optional
import json

router = APIRouter()

HISTORY_DIR = Path("data/output/langchain/history")

@router.get("/")
async def list_pipeline_history(limit: int = 20):
    """List all past pipeline runs, most recent first"""
    if not HISTORY_DIR.exists():
        return {"runs": [], "total": 0}
    
    # Get all history files
    files = sorted(HISTORY_DIR.glob("*.json"), reverse=True)
    
    runs = []
    for f in files[:limit]:
        try:
            with open(f, 'r') as fp:
                data = json.load(fp)
            
            # Extract summary info safely source_report
            
            # 1. Rules Extraction
            rules_raw = data.get("rules", [])
            rules_list = []
            if isinstance(rules_raw, dict):
                rules_list = rules_raw.get("rules", [])
            elif isinstance(rules_raw, list):
                rules_list = rules_raw
                
            # 2. TTPs Extraction
            ttps_list = []
            extraction = data.get("extraction", {})
            if isinstance(extraction, dict):
                results = extraction.get("extraction_results", [])
                if results and isinstance(results, list):
                    ttps_list = results[0].get("extracted_ttps", [])
            elif isinstance(extraction, list):
                # Legacy format support if any
                pass
                
            # 3. Report Source from Filename or Data
            report_source = "Unknown"
            parts = f.stem.split('_', 2)
            if len(parts) > 2:
                report_source = parts[2]
            elif ttps_list and isinstance(ttps_list[0], dict):
                 report_source = ttps_list[0].get("report_id") or "Unknown"

            runs.append({
                "id": f.stem,
                "filename": f.name,
                "timestamp": f.stem.split('_')[0] + "_" + f.stem.split('_')[1] if '_' in f.stem else f.stem,
                "report_source": report_source,
                "ttps_count": len(ttps_list),
                "rules_count": len(rules_list),
                "final_score": data.get("final_score", 0),
                "iterations": data.get("iterations", 0),
                "verified_count": sum(1 for r in rules_list if isinstance(r, dict) and r.get("siem_verification", {}).get("detected")),
            })
        except Exception as e:
            # Skip corrupted files
            continue
    
    return {"runs": runs, "total": len(list(HISTORY_DIR.glob("*.json")))}


@router.get("/{run_id}")
async def get_pipeline_run(run_id: str):
    """Get full details of a specific pipeline run"""
    if not HISTORY_DIR.exists():
        raise HTTPException(status_code=404, detail="No history available")
    
    # Find file matching run_id
    matching = list(HISTORY_DIR.glob(f"*{run_id}*.json"))
    if not matching:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    
    file_path = matching[0]
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading run: {e}")


@router.delete("/{run_id}")
async def delete_pipeline_run(run_id: str):
    """Delete a specific pipeline run from history"""
    if not HISTORY_DIR.exists():
        raise HTTPException(status_code=404, detail="No history available")
    
    matching = list(HISTORY_DIR.glob(f"*{run_id}*.json"))
    if not matching:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    
    try:
        matching[0].unlink()
        return {"status": "deleted", "run_id": run_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting run: {e}")
