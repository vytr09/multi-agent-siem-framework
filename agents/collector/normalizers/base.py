"""
Base normalizer for CTI data transformation.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime
import uuid

class BaseNormalizer(ABC):
    """
    Abstract base class for data normalizers.
    
    All CTI source normalizers must implement this interface to ensure
    consistent data format across different sources.
    """
    
    def __init__(self):
        self.source_type = self.__class__.__name__.replace("Normalizer", "").upper()
    
    @abstractmethod
    def normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single event to standard format.
        
        Args:
            raw_event: Raw event data from CTI source
            
        Returns:
            Normalized event in standard format
        """
        pass
    
    def normalize_batch(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize a batch of events.
        
        Args:
            raw_events: List of raw events
            
        Returns:
            List of normalized events
        """
        normalized = []
        for event in raw_events:
            try:
                normalized_event = self.normalize_event(event)
                if normalized_event:
                    normalized.append(normalized_event)
            except Exception as e:
                # Log error but continue processing other events
                print(f"Error normalizing event: {e}")
                continue
        
        return normalized
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        return str(uuid.uuid4())
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.utcnow().isoformat() + 'Z'
    
    def _extract_confidence(self, raw_event: Dict[str, Any]) -> int:
        """Extract or calculate confidence score (0-100)"""
        # Default confidence calculation - subclasses can override
        confidence = 50
        
        # Increase confidence for published events
        if raw_event.get("published"):
            confidence += 20
            
        # Increase confidence based on attribute count
        attr_count = len(raw_event.get("attributes", []))
        if attr_count > 10:
            confidence += 20
        elif attr_count > 5:
            confidence += 10
            
        return min(confidence, 100)
