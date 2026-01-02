from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any
from core.knowledge_base import get_kb_manager

router = APIRouter()

@router.get("/stats")
async def get_stats():
    """Get statistics about the Knowledge Base."""
    kb = get_kb_manager()
    if not kb or not kb.enabled:
        return {"enabled": False, "stats": {}}
    
    try:
        stats = {}
        # Get count for each collection
        for col_name in [kb.COLLECTION_MITRE, kb.COLLECTION_RULES, kb.COLLECTION_TTPS, kb.COLLECTION_REPORTS]:
            try:
                col = kb.client.get_collection(col_name)
                stats[col_name] = col.count()
            except Exception:
                stats[col_name] = 0
                
        return {"enabled": True, "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch stats: {e}")

@router.get("/search")
async def search_knowledge(
    query: str = Query(..., min_length=2),
    type: str = Query("all", enum=["all", "rules", "ttps", "mitre"]),
    limit: int = Query(5, ge=1, le=20)
):
    """Search the Knowledge Base for relevant context."""
    kb = get_kb_manager()
    if not kb or not kb.enabled:
        return {"results": []}
        
    try:
        results = []
        
        # Search Rules
        if type in ["all", "rules"]:
            rules = await kb.query_similar_rules(query, n_results=limit)
            for r in rules:
                results.append({
                    "type": "rule",
                    "title": r.get('title'),
                    "content": r.get('description'),
                    "metadata": r
                })
                
        # Search MITRE (Simulated via query_mitre_context for now as it returns string)
        if type in ["all", "mitre"]:
            # We need to access vector store directly for structured results, 
            # leveraging the existing helper slightly differently or just parsing the string is messy.
            # Let's use the private helper pattern if possible or just use the public method returning string for v1
            mitre_context = await kb.query_mitre_context(query, n_results=limit)
            if mitre_context:
                results.append({
                    "type": "mitre_context",
                    "title": "MITRE ATT&CK Context",
                    "content": mitre_context,
                    "metadata": {}
                })
                
        return {"results": results}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")
