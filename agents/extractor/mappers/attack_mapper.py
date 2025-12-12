import json
import os
import logging
from typing import Dict, Any, Optional, List

class ATTACKMapper:
    """Map techniques to MITRE ATT&CK using official STIX data"""
    
    def __init__(self, stix_path: str = "data/mitre_attack/enterprise-attack.json"):
        self.logger = logging.getLogger("attack_mapper")
        self.stix_path = stix_path
        self.technique_map = {} # Normalized Name -> ID
        self.id_map = {}        # ID -> Normalized Name
        self.data_loaded = False
        
        self._load_stix_data()
    
    def _load_stix_data(self):
        """Load and index STIX data"""
        if not os.path.exists(self.stix_path):
            self.logger.warning(f"MITRE STIX file not found at {self.stix_path}. Using fallback stub.")
            return

        try:
            with open(self.stix_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            objects = data.get("objects", [])
            count = 0
            
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    # Get External References (to find ID)
                    ext_refs = obj.get("external_references", [])
                    mitre_id = next((ref.get("external_id") for ref in ext_refs if ref.get("source_name") == "mitre-attack"), None)
                    
                    if mitre_id:
                        name = obj.get("name", "").lower().strip()
                        self.technique_map[name] = mitre_id
                        self.id_map[mitre_id] = name
                        
                        # Also map aliases/x_mitre_aliases if available
                        aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])
                        for alias in aliases:
                            self.technique_map[alias.lower().strip()] = mitre_id
                            
                        count += 1
            
            self.data_loaded = True
            self.logger.info(f"Loaded {count} MITRE ATT&CK techniques")
            
        except Exception as e:
            self.logger.error(f"Failed to load STIX data: {e}")

    def map_technique(self, technique_name: str, tactic: str = '', 
                     description: str = '') -> Optional[Dict[str, Any]]:
        """
        Map technique name/ID to ATT&CK ID.
        Prioritizes:
        1. Exact Name Match
        2. Fuzzy Name Match
        """
        if not self.data_loaded:
            return {"technique_id": "UNMAPPED", "subtechnique": False}

        normalized = technique_name.lower().strip()
        
        # 1. Direct Name Match
        if normalized in self.technique_map:
            return {
                "technique_id": self.technique_map[normalized],
                "subtechnique": "." in self.technique_map[normalized]
            }

        # 2. Key Term Search (Simple Fuzzy)
        # Search for longest matching technique name within the input string or visa versa
        best_match = None
        max_len = 0
        
        for name, tid in self.technique_map.items():
            if name in normalized or normalized in name:
                if len(name) > max_len:
                    max_len = len(name)
                    best_match = tid
        
        if best_match:
             return {
                "technique_id": best_match,
                "subtechnique": "." in best_match
            }

        return None

    def validate_or_fallback(self, llm_id: str, llm_name: str) -> Dict[str, Any]:
        """
        Validate LLM extraction or fallback to it.
        This enables 'LLM Trust' logic.
        """
        if not self.data_loaded:
             return {"technique_id": llm_id or "UNMAPPED", "subtechnique": False}

        # Check if LLM provided a valid ID format (Txxxx)
        is_valid_format = bool(llm_id and llm_id.startswith("T") and len(llm_id) >= 5)
        
        # Check if ID exists in our DB
        if is_valid_format and llm_id in self.id_map:
             return {"technique_id": llm_id, "subtechnique": "." in llm_id}
             
        # Try to map by name
        mapped = self.map_technique(llm_name)
        if mapped:
             return mapped
             
        # Fallback: Trust LLM if format looks valid, otherwise UNMAPPED
        if is_valid_format:
             return {"technique_id": llm_id, "subtechnique": "." in llm_id}
             
        return {"technique_id": "UNMAPPED", "subtechnique": False}