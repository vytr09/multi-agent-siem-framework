from fastapi import APIRouter
from api.core.agent_manager import agent_manager
import json
from pathlib import Path
import os

router = APIRouter()

@router.get("/")
async def get_metrics():
    """Get current system metrics"""
    metrics = {
        "system_status": "healthy",
        "active_agents": agent_manager.get_agent_status(),
        "rules_generated": 0,
        "detection_rate": 0.0,
        "attacks_launched": 0
    }

    # 1. Count Generated Rules
    # Check both old and new paths
    rules_paths = [
        Path("data/output/langchain/rulegen/generated_rules.json"),
        Path("data/output/rulegen/generated_rules.json")
    ]
    
    for rules_file in rules_paths:
        if rules_file.exists():
            try:
                with open(rules_file, "r") as f:
                    data = json.load(f)
                    # Handle new format where rules are in "rules" key
                    if isinstance(data, dict) and "rules" in data:
                        metrics["rules_generated"] = len(data["rules"])
                    elif isinstance(data, list):
                        metrics["rules_generated"] = len(data)
                break # Stop if found
            except:
                pass

    # 2. Calculate Detection Rate & Attacks from Feedback Loop
    # Check both old and new paths
    feedback_dirs = [
        Path("data/output/langchain/feedback_loop_siem"), # Hypothetical new path
        Path("data/output/feedback_loop_siem")
    ]
    
    # Also check the orchestrator output for the latest run
    latest_run_file = Path("data/output/langchain/pipeline_result.json")
    if latest_run_file.exists():
         try:
            with open(latest_run_file, "r") as f:
                data = json.load(f)
                # If we have a successful run, count it as 1 attack launched
                if data.get("status") == "success":
                    metrics["attacks_launched"] = 1 # Simplified for single run
                    
                    # Calculate detection rate from verification results
                    siem_metrics = data.get("siem_metrics", {})
                    if "detection_rate" in siem_metrics:
                        metrics["detection_rate"] = round(siem_metrics["detection_rate"] * 100, 1)
         except:
             pass

    return metrics

@router.get("/activity")
async def get_recent_activity(limit: int = 5):
    """Get recent activity from logs"""
    log_file = Path("logs/system.log")
    activities = []
    
    if log_file.exists():
        try:
            with open(log_file, "r") as f:
                # Read last N lines
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    # Parse simple log format: 2023-10-27 10:00:00 [INFO] Message
                    # Or standard python logging: 2025-12-05 15:52:01,810 - logger - LEVEL - Message
                    
                    parts = line.split(" - ", 3)
                    if len(parts) >= 3:
                        # Python logging format
                        timestamp = parts[0].split(",")[0]
                        level = parts[2].strip()
                        message = parts[3].strip()
                    else:
                        # Fallback or other format
                        parts = line.split(" ", 3)
                        if len(parts) >= 4:
                            timestamp = f"{parts[0]} {parts[1]}"
                            level = parts[2].strip("[]")
                            message = parts[3].strip()
                        else:
                            continue

                    type_map = {
                        "INFO": "info",
                        "WARNING": "warning",
                        "ERROR": "error",
                        "CRITICAL": "error"
                    }
                    
                    activities.append({
                        "time": timestamp.split(" ")[1] if " " in timestamp else timestamp,
                        "event": message,
                        "type": type_map.get(level, "info")
                    })
        except:
            pass
            
    return activities

@router.get("/latest_attack")
async def get_latest_attack():
    """Get details of the latest simulated attack"""
    # Check LangChain output first
    langchain_file = Path("data/output/langchain/pipeline_result.json")
    
    if langchain_file.exists():
        try:
            with open(langchain_file, "r") as f:
                data = json.load(f)
                if data.get("status") == "success":
                    # Get first rule/attack pair
                    rules = data.get("rules", {}).get("rules", [])
                    verification = data.get("siem_verification", [])
                    
                    if rules and len(rules) > 0:
                        rule = rules[0]
                        # Find corresponding verification
                        detected = False
                        if verification and len(verification) > 0:
                            detected = verification[0].get("detected", False)
                            
                        return {
                            "technique": rule.get("ttp_id", "Unknown"),
                            "status": "Detected" if detected else "Missed",
                            "timestamp": data.get("timestamp", "Just now"), 
                            "details": rule.get("title", "Generated Rule")
                        }
        except:
            pass

    return {"technique": "None", "status": "Waiting", "timestamp": "-", "details": "No attacks run yet"}
