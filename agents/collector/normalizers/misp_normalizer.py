# agents/collector/normalizers/misp_normalizer.py
"""
MISP data normalizer for converting MISP events to standard CTI format.
"""

from typing import Dict, Any, List
from agents.collector.normalizers.base import BaseNormalizer
from agents.base.exceptions import DataNormalizationException

class MISPNormalizer(BaseNormalizer):
    """
    Normalizes MISP event data to standard CTI format.
    
    Converts MISP-specific data structures into a standardized format
    that can be processed by the Extractor Agent.
    """
    
    def __init__(self):
        super().__init__()
        self.source_type = "MISP"
    
    def normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single MISP event.
        
        Args:
            raw_event: Raw MISP event data
            
        Returns:
            Normalized event in standard format
        """
        try:
            # Extract the Event data (MISP wraps events in {"Event": {...}})
            event_data = raw_event.get("Event", raw_event)
            
            # Basic event information
            normalized = {
                "report_id": self._generate_report_id(),
                "source_id": event_data.get("id"),
                "source": self.source_type,
                "timestamp": self._get_current_timestamp(),
                "title": event_data.get("info", "Untitled MISP Event"),
                "description": self._build_description(event_data),
                "confidence": self._calculate_misp_confidence(event_data),
                "severity": self._map_threat_level(event_data.get("threat_level_id", "3")),
                "published": event_data.get("published", False),
                "analysis_status": self._map_analysis_status(event_data.get("analysis", "0")),
                
                # Extract structured data
                "indicators": self._extract_indicators(event_data),
                "threat_actors": self._extract_threat_actors(event_data),
                "malware_families": self._extract_malware_families(event_data),
                "attack_patterns": self._extract_attack_patterns(event_data),
                "tags": self._extract_tags(event_data),
                
                # Metadata
                "source_url": None,  # Will be set by client
                "collection_timestamp": self._get_current_timestamp(),
                "raw_data": event_data  # Keep original for debugging
            }
            
            return normalized
            
        except Exception as e:
            raise DataNormalizationException(
                f"Failed to normalize MISP event: {str(e)}",
                data_format="MISP"
            )
    
    def _build_description(self, event_data: Dict[str, Any]) -> str:
        """Build comprehensive description from MISP event"""
        
        description_parts = []
        
        # Basic info
        if event_data.get("info"):
            description_parts.append(event_data["info"])
        
        # Add comment if available
        if event_data.get("comment"):
            description_parts.append(f"\nDetails: {event_data['comment']}")
        
        # Add attribute summary
        attributes = event_data.get("Attribute", [])
        if attributes:
            ioc_count = len([attr for attr in attributes if attr.get("to_ids")])
            description_parts.append(f"\nContains {len(attributes)} attributes ({ioc_count} IOCs)")
        
        # Add object summary
        objects = event_data.get("Object", [])
        if objects:
            obj_types = list(set([obj.get("name", "unknown") for obj in objects]))
            description_parts.append(f"\nObjects: {', '.join(obj_types)}")
        
        return "\n".join(description_parts)
    
    def _calculate_misp_confidence(self, event_data: Dict[str, Any]) -> int:
        """Calculate confidence score based on MISP event characteristics"""
        
        confidence = 50  # Base confidence
        
        # Published events are more reliable
        if event_data.get("published"):
            confidence += 20
        
        # Analysis status affects confidence
        analysis = event_data.get("analysis", "0")
        if analysis == "2":  # Complete analysis
            confidence += 15
        elif analysis == "1":  # Ongoing analysis
            confidence += 10
        
        # More attributes = higher confidence
        attr_count = len(event_data.get("Attribute", []))
        if attr_count > 20:
            confidence += 15
        elif attr_count > 10:
            confidence += 10
        elif attr_count > 5:
            confidence += 5
        
        # Objects add confidence
        obj_count = len(event_data.get("Object", []))
        confidence += min(obj_count * 3, 15)
        
        # Distribution level (more restrictive = higher quality)
        distribution = int(event_data.get("distribution", "3"))
        if distribution <= 1:  # Organization only or community only
            confidence += 10
        
        return min(confidence, 100)
    
    def _map_threat_level(self, threat_level_id: str) -> str:
        """Map MISP threat level to standard severity"""
        
        threat_mapping = {
            "1": "high",      # High
            "2": "medium",    # Medium  
            "3": "low",       # Low
            "4": "undefined"  # Undefined
        }
        
        return threat_mapping.get(str(threat_level_id), "low")
    
    def _map_analysis_status(self, analysis: str) -> str:
        """Map MISP analysis status to standard format"""
        
        analysis_mapping = {
            "0": "initial",      # Initial
            "1": "ongoing",      # Ongoing
            "2": "complete"      # Complete
        }
        
        return analysis_mapping.get(str(analysis), "initial")
    
    def _extract_indicators(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from MISP attributes"""
        
        indicators = []
        attributes = event_data.get("Attribute", [])
        
        for attr in attributes:
            if attr.get("to_ids", False):  # Only IOCs
                indicator = {
                    "id": attr.get("id"),
                    "type": attr.get("type"),
                    "value": attr.get("value"),
                    "category": attr.get("category"),
                    "confidence": self._attribute_confidence(attr),
                    "comment": attr.get("comment", ""),
                    "first_seen": attr.get("timestamp"),
                    "source": "MISP"
                }
                indicators.append(indicator)
        
        return indicators
    
    def _extract_threat_actors(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract threat actor information from tags and objects"""
        
        threat_actors = []
        
        # Check tags for threat actors
        tags = event_data.get("Tag", [])
        for tag in tags:
            tag_name = tag.get("name", "").lower()
            
            # MISP Galaxy threat actor tags
            if "threat-actor" in tag_name or "intrusion-set" in tag_name:
                # Extract actor name from galaxy tag
                if "=" in tag_name:
                    actor_name = tag_name.split("=")[-1].strip('"')
                    if actor_name and actor_name not in threat_actors:
                        threat_actors.append(actor_name)
            
            # Common threat actor patterns
            elif any(pattern in tag_name for pattern in ["apt", "group", "actor"]):
                if tag_name not in threat_actors:
                    threat_actors.append(tag_name)
        
        # Check objects for threat actor information
        objects = event_data.get("Object", [])
        for obj in objects:
            if obj.get("name") == "threat-actor":
                attributes = obj.get("Attribute", [])
                for attr in attributes:
                    if attr.get("object_relation") == "name":
                        actor_name = attr.get("value")
                        if actor_name and actor_name not in threat_actors:
                            threat_actors.append(actor_name)
        
        return threat_actors
    
    def _extract_malware_families(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract malware family information"""
        
        malware_families = []
        
        # Check tags
        tags = event_data.get("Tag", [])
        for tag in tags:
            tag_name = tag.get("name", "").lower()
            
            if "malware" in tag_name:
                if "=" in tag_name:
                    malware_name = tag_name.split("=")[-1].strip('"')
                    if malware_name and malware_name not in malware_families:
                        malware_families.append(malware_name)
        
        # Check objects
        objects = event_data.get("Object", [])
        for obj in objects:
            if obj.get("name") == "malware":
                attributes = obj.get("Attribute", [])
                for attr in attributes:
                    if attr.get("object_relation") in ["name", "family"]:
                        malware_name = attr.get("value")
                        if malware_name and malware_name not in malware_families:
                            malware_families.append(malware_name)
        
        return malware_families
    
    def _extract_attack_patterns(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract MITRE ATT&CK patterns"""
        
        attack_patterns = []
        
        # Check tags for ATT&CK techniques
        tags = event_data.get("Tag", [])
        for tag in tags:
            tag_name = tag.get("name", "")
            
            if "attack-pattern" in tag_name.lower() or "mitre-attack" in tag_name.lower():
                pattern = {
                    "source": "tag",
                    "name": tag_name,
                    "technique_id": self._extract_technique_id(tag_name)
                }
                attack_patterns.append(pattern)
        
        # Check objects for attack patterns
        objects = event_data.get("Object", [])
        for obj in objects:
            if obj.get("name") == "attack-pattern":
                attributes = obj.get("Attribute", [])
                pattern_data = {}
                
                for attr in attributes:
                    relation = attr.get("object_relation")
                    if relation == "name":
                        pattern_data["name"] = attr.get("value")
                    elif relation == "id":
                        pattern_data["technique_id"] = attr.get("value")
                
                if pattern_data:
                    pattern_data["source"] = "object"
                    attack_patterns.append(pattern_data)
        
        return attack_patterns
    
    def _extract_tags(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract and clean tags"""
        
        tags = []
        tag_objects = event_data.get("Tag", [])
        
        for tag in tag_objects:
            tag_name = tag.get("name", "")
            if tag_name and not tag_name.startswith("tlp:"):  # Exclude TLP tags
                tags.append(tag_name)
        
        return tags
    
    def _attribute_confidence(self, attribute: Dict[str, Any]) -> int:
        """Calculate confidence for individual attribute"""
        
        confidence = 60  # Base confidence for MISP attributes
        
        # Check distribution
        distribution = int(attribute.get("distribution", "5"))
        if distribution <= 1:
            confidence += 15
        elif distribution <= 2:
            confidence += 10
        
        # Check if it has a comment (manual analysis)
        if attribute.get("comment"):
            confidence += 10
        
        # Check category reliability
        reliable_categories = [
            "Payload delivery", "Network activity", "Artifacts dropped"
        ]
        if attribute.get("category") in reliable_categories:
            confidence += 5
        
        return min(confidence, 100)
    
    def _extract_technique_id(self, tag_name: str) -> str:
        """Extract MITRE ATT&CK technique ID from tag"""
        
        # Look for T#### pattern
        import re
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        match = re.search(technique_pattern, tag_name.upper())
        
        return match.group(0) if match else ""
