import asyncio
import json
import logging
import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from core.knowledge_base import get_kb_manager

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre_populator")

async def populate_kb():
    """Populate KB with MITRE ATT&CK Techniques"""
    kb = get_kb_manager()
    if not kb or not kb.enabled:
        logger.error("Knowledge Base not available.")
        return

    stix_path = "data/mitre_attack/enterprise-attack.json"
    if not os.path.exists(stix_path):
        logger.error(f"MITRE data not found at {stix_path}")
        return

    logger.info(f"Loading MITRE data from {stix_path}...")
    try:
        with open(stix_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON: {e}")
        return

    objects = data.get("objects", [])
    logger.info(f"Found {len(objects)} STIX objects. Filtering for active Attack Patterns...")

    count = 0
    tasks = []
    
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            # Extract ID
            ext_refs = obj.get("external_references", [])
            mitre_id = next((ref.get("external_id") for ref in ext_refs if ref.get("source_name") == "mitre-attack"), None)
            
            if mitre_id:
                technique = {
                    "name": obj.get("name", "Unknown"),
                    "external_id": mitre_id,
                    "description": obj.get("description", ""),
                    "url": next((ref.get("url") for ref in ext_refs if ref.get("source_name") == "mitre-attack"), ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "detection": obj.get("x_mitre_detection", "N/A"),
                    "tactic": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
                }
                
                # Add to KB
                tasks.append(kb.add_mitre_technique(technique))
                count += 1

    logger.info(f"Adding {len(tasks)} techniques to Knowledge Base (batch processing)...")
    
    # Process in chunks to avoid overwhelming Chroma/EventLoop
    chunk_size = 50
    for i in range(0, len(tasks), chunk_size):
        chunk = tasks[i:i+chunk_size]
        await asyncio.gather(*chunk)
        logger.info(f"Processed {min(i+chunk_size, len(tasks))}/{len(tasks)}")

    logger.info("Successfully populated MITRE Knowledge Base.")

if __name__ == "__main__":
    asyncio.run(populate_kb())
