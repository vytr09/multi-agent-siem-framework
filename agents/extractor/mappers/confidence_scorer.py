"""
Confidence scoring system for extracted TTPs.

Calculates confidence scores based on multiple factors:
- Source report quality
- Extraction context
- ATT&CK mapping accuracy
- IOC correlation
"""

from typing import Dict, Any, List


class ConfidenceScorer:
    """
    Calculate confidence scores for extracted TTPs.
    
    Uses multi-factor analysis to determine the reliability
    of each extracted TTP.
    """
    
    def __init__(self):
        # Weight factors for confidence calculation
        self.weights = {
            "report_confidence": 0.25,      # Base report confidence
            "attack_mapping": 0.20,          # ATT&CK mapping quality
            "ioc_correlation": 0.20,         # IOC correlation strength
            "description_detail": 0.15,      # Description specificity
            "tool_mention": 0.10,            # Tool/malware mentions
            "context_richness": 0.10         # Overall context quality
        }
    
    def calculate_confidence(
        self, 
        ttp: Dict[str, Any], 
        report_context: Dict[str, Any]
    ) -> float:
        """
        Calculate overall confidence score for a TTP.
        
        Args:
            ttp: Extracted TTP with details
            report_context: Source report information
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        scores = {}
        
        # 1. Report confidence score
        scores["report_confidence"] = self._score_report_confidence(report_context)
        
        # 2. ATT&CK mapping score
        scores["attack_mapping"] = self._score_attack_mapping(ttp)
        
        # 3. IOC correlation score
        scores["ioc_correlation"] = self._score_ioc_correlation(
            ttp, report_context
        )
        
        # 4. Description detail score
        scores["description_detail"] = self._score_description_detail(ttp)
        
        # 5. Tool mention score
        scores["tool_mention"] = self._score_tool_mentions(
            ttp, report_context
        )
        
        # 6. Context richness score
        scores["context_richness"] = self._score_context_richness(
            ttp, report_context
        )
        
        # Calculate weighted average
        total_confidence = sum(
            scores[factor] * self.weights[factor]
            for factor in self.weights
        )
        
        # Store component scores for debugging
        ttp["confidence_breakdown"] = scores
        
        return round(total_confidence, 3)
    
    def _score_report_confidence(self, report: Dict[str, Any]) -> float:
        """Score based on source report confidence"""
        base_confidence = report.get("confidence", 50) / 100.0
        
        # Boost for published reports
        if report.get("published"):
            base_confidence = min(base_confidence + 0.15, 1.0)
        
        # Boost for complete analysis
        if report.get("analysis_status") == "complete":
            base_confidence = min(base_confidence + 0.10, 1.0)
        
        return base_confidence
    
    def _score_attack_mapping(self, ttp: Dict[str, Any]) -> float:
        """Score based on ATT&CK mapping quality"""
        score = 0.5  # Default medium confidence
        
        # Check if mapped to ATT&CK
        attack_id = ttp.get("attack_id", "")
        
        if attack_id and attack_id != "UNMAPPED":
            score = 0.85  # High confidence for mapped techniques
            
            # Boost for subtechniques (more specific)
            if ttp.get("subtechnique"):
                score = min(score + 0.10, 1.0)
            
            # Check mapping source
            if ttp.get("mapping_source") == "attack_mapper":
                score = min(score + 0.05, 1.0)
        else:
            score = 0.4  # Lower confidence for unmapped
        
        return score
    
    def _score_ioc_correlation(
        self, 
        ttp: Dict[str, Any], 
        report: Dict[str, Any]
    ) -> float:
        """Score based on IOC correlation"""
        score = 0.5  # Default
        
        # Check if TTP has associated indicators
        ttp_indicators = ttp.get("indicators", [])
        report_indicators = report.get("indicators", [])
        
        if not report_indicators:
            return score
        
        # Calculate correlation
        if ttp_indicators:
            # Has specific indicators mentioned
            correlation_strength = len(ttp_indicators) / max(len(report_indicators), 1)
            score = min(0.5 + (correlation_strength * 0.5), 1.0)
        else:
            # No specific indicators, lower confidence
            score = 0.4
        
        return score
    
    def _score_description_detail(self, ttp: Dict[str, Any]) -> float:
        """Score based on description specificity"""
        description = ttp.get("description", "")
        
        if not description:
            return 0.3
        
        # Factors indicating detailed description
        detail_indicators = [
            len(description) > 50,           # Reasonable length
            len(description.split()) > 10,   # Multiple words
            any(word in description.lower() for word in [
                "executed", "download", "created", "modified",
                "established", "dumped", "harvested", "exfiltrated"
            ]),  # Action verbs
            any(word in description.lower() for word in [
                "registry", "process", "file", "network",
                "credential", "powershell", "cmd"
            ])  # Technical terms
        ]
        
        # Calculate score based on met indicators
        detail_score = sum(detail_indicators) / len(detail_indicators)
        return 0.3 + (detail_score * 0.7)  # Scale to 0.3-1.0
    
    def _score_tool_mentions(
        self, 
        ttp: Dict[str, Any], 
        report: Dict[str, Any]
    ) -> float:
        """Score based on tool/malware mentions"""
        score = 0.5  # Default
        
        # Check TTP tools
        ttp_tools = ttp.get("tools", [])
        
        # Check report malware families
        report_malware = report.get("malware_families", [])
        
        if ttp_tools:
            score = 0.8  # High confidence with specific tools
            
            # Extra boost if tools match report malware
            if report_malware:
                tool_names_lower = [t.lower() for t in ttp_tools]
                malware_names_lower = [m.lower() for m in report_malware]
                
                if any(tool in malware_names_lower for tool in tool_names_lower):
                    score = min(score + 0.15, 1.0)
        
        return score
    
    def _score_context_richness(
        self, 
        ttp: Dict[str, Any], 
        report: Dict[str, Any]
    ) -> float:
        """Score based on overall context quality"""
        score = 0.5
        
        # Factors contributing to rich context
        context_factors = [
            bool(report.get("threat_actors")),      # Known threat actors
            bool(report.get("malware_families")),   # Known malware
            len(report.get("indicators", [])) > 5,  # Multiple IOCs
            bool(report.get("attack_patterns")),    # Attack patterns
            bool(ttp.get("tools")),                 # Tools mentioned
            len(ttp.get("description", "")) > 100   # Detailed description
        ]
        
        # Calculate richness score
        richness = sum(context_factors) / len(context_factors)
        score = 0.3 + (richness * 0.7)  # Scale to 0.3-1.0
        
        return score
    
    def get_confidence_level(self, confidence_score: float) -> str:
        """
        Convert numeric confidence to categorical level.
        
        Args:
            confidence_score: Confidence between 0.0 and 1.0
            
        Returns:
            Confidence level string
        """
        if confidence_score >= 0.8:
            return "high"
        elif confidence_score >= 0.6:
            return "medium"
        elif confidence_score >= 0.4:
            return "low"
        else:
            return "very_low"
    
    def filter_by_confidence(
        self, 
        ttps: List[Dict[str, Any]], 
        min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Filter TTPs by minimum confidence threshold.
        
        Args:
            ttps: List of TTPs with confidence scores
            min_confidence: Minimum confidence threshold
            
        Returns:
            Filtered list of TTPs
        """
        return [
            ttp for ttp in ttps
            if ttp.get("confidence_score", 0) >= min_confidence
        ]
    
    def get_statistics(self, ttps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get confidence statistics for a set of TTPs.
        
        Args:
            ttps: List of TTPs with confidence scores
            
        Returns:
            Statistics dictionary
        """
        if not ttps:
            return {
                "total": 0,
                "avg_confidence": 0.0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0
            }
        
        confidences = [ttp.get("confidence_score", 0) for ttp in ttps]
        
        return {
            "total": len(ttps),
            "avg_confidence": sum(confidences) / len(confidences),
            "max_confidence": max(confidences),
            "min_confidence": min(confidences),
            "high_confidence": sum(1 for c in confidences if c >= 0.8),
            "medium_confidence": sum(1 for c in confidences if 0.6 <= c < 0.8),
            "low_confidence": sum(1 for c in confidences if c < 0.6)
        }