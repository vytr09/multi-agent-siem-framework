#!/usr/bin/env python3
"""
Enhanced Confidence Scoring System
Evidence-based scoring với multiple factors
"""

from typing import Dict, List, Any
from enum import Enum
import math


class ConfidenceLevel(Enum):
    """Confidence levels"""
    CRITICAL = (0.95, 1.0, "critical", "🔴")
    VERY_HIGH = (0.85, 0.94, "very_high", "🟠")
    HIGH = (0.75, 0.84, "high", "🟡")
    MEDIUM = (0.60, 0.74, "medium", "🟢")
    LOW = (0.40, 0.59, "low", "🔵")
    VERY_LOW = (0.0, 0.39, "very_low", "⚫")
    
    def __init__(self, min_score, max_score, label, emoji):
        self.min_score = min_score
        self.max_score = max_score
        self.label = label
        self.emoji = emoji


class EnhancedConfidenceScorer:
    """
    Evidence-based confidence scoring
    Factors:
    - Report confidence level
    - MITRE ATT&CK mapping quality
    - IOC/Indicator evidence
    - Description detail/richness
    - Tool mentions
    - Multiple supporting evidence
    - Text context richness
    """
    
    def __init__(self):
        self.weights = {
            'report_confidence': 0.15,      # Base report quality
            'attack_mapping': 0.20,         # MITRE mapping quality
            'ioc_evidence': 0.15,           # IOCs/indicators present
            'description_detail': 0.15,     # Description richness
            'tool_mentions': 0.10,          # Tools/malware mentioned
            'context_richness': 0.15,       # Text detail
            'multiple_sources': 0.10        # Evidence from multiple sources
        }
    
    def calculate_score(
        self,
        ttp: Dict[str, Any],
        report: Dict[str, Any],
        text: str = "",
        nlp_entities: Dict[str, List] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive confidence score with breakdown
        """
        if nlp_entities is None:
            nlp_entities = {}
        
        scores = {}
        
        # 1. Report confidence (base quality)
        scores['report_confidence'] = self._score_report_confidence(report)
        
        # 2. ATT&CK mapping quality
        scores['attack_mapping'] = self._score_attack_mapping(ttp)
        
        # 3. IOC evidence
        scores['ioc_evidence'] = self._score_ioc_evidence(ttp)
        
        # 4. Description detail
        scores['description_detail'] = self._score_description_detail(ttp, text)
        
        # 5. Tool mentions
        scores['tool_mentions'] = self._score_tool_mentions(ttp, nlp_entities)
        
        # 6. Context richness
        scores['context_richness'] = self._score_context_richness(text, ttp)
        
        # 7. Multiple sources/evidence
        scores['multiple_sources'] = self._score_multiple_evidence(ttp, nlp_entities)
        
        # Calculate weighted final score
        final_score = sum(
            scores[factor] * self.weights[factor]
            for factor in self.weights.keys()
        )
        final_score = min(max(final_score, 0.0), 1.0)
        
        # Get confidence level
        conf_level = self._get_confidence_level(final_score)
        
        return {
            'score': round(final_score, 3),
            'level': conf_level.label,
            'emoji': conf_level.emoji,
            'breakdown': {k: round(v, 3) for k, v in scores.items()},
            'weights': self.weights
        }
    
    def _score_report_confidence(self, report: Dict[str, Any]) -> float:
        """
        Score based on report metadata quality
        """
        base_score = 0.6  # Default
        
        # Source credibility
        source = report.get('source', '').lower()
        source_scores = {
            'misp': 0.9,
            'mitre': 0.95,
            'us-cert': 0.95,
            'cisa': 0.95,
            'darpa': 0.9,
            'fireeye': 0.85,
            'mandiant': 0.85,
            'crowdstrike': 0.85,
            'apt': 0.8,
            'threat': 0.75,
            'security': 0.7,
            'blog': 0.6
        }
        
        source_score = 0.6
        for source_key, score in source_scores.items():
            if source_key in source:
                source_score = score
                break
        
        # Report confidence value
        report_conf = report.get('confidence', 50)
        if isinstance(report_conf, str):
            try:
                report_conf = int(report_conf.rstrip('%'))
            except:
                report_conf = 50
        
        conf_score = min(report_conf / 100, 1.0)
        
        # Combine
        final = (source_score * 0.5 + conf_score * 0.5)
        return round(final, 3)
    
    def _score_attack_mapping(self, ttp: Dict[str, Any]) -> float:
        """
        Score ATT&CK mapping quality
        """
        base = 0.5
        
        # Has attack ID
        if ttp.get('attack_id') and ttp.get('attack_id') != 'UNMAPPED':
            mapping_score = 0.95
            
            # Bonus if it's official MITRE mapping
            if ttp.get('mapping_source') == 'attack_mapper':
                mapping_score = 0.95
            elif ttp.get('mapping_source') == 'nlp':
                mapping_score = 0.75
            
            # Bonus if subtechnique
            if ttp.get('subtechnique', False):
                mapping_score = 0.90
        else:
            mapping_score = 0.4
        
        return round(mapping_score, 3)
    
    def _score_ioc_evidence(self, ttp: Dict[str, Any]) -> float:
        """
        Score based on IOC/Indicator evidence
        """
        iocs = ttp.get('correlated_iocs', {})
        indicators = ttp.get('indicators', [])
        
        ioc_count = 0
        
        # Count different types of IOCs
        if isinstance(iocs, dict):
            for ioc_type, values in iocs.items():
                if isinstance(values, list):
                    ioc_count += len(values)
                elif isinstance(values, dict):
                    ioc_count += sum(len(v) if isinstance(v, list) else 1 
                                    for v in values.values())
        
        # Indicator count
        if indicators:
            ioc_count += len(indicators)
        
        # Score based on count
        score = min(0.5 + (ioc_count / 10 * 0.4), 1.0)
        
        return round(score, 3)
    
    def _score_description_detail(self, ttp: Dict[str, Any], text: str = "") -> float:
        """
        Score based on description richness and detail
        """
        description = ttp.get('description', '')
        
        # Word count
        words = len(description.split())
        word_score = min(words / 50, 1.0)  # 50+ words = max score
        
        # Specific indicators (not generic)
        generic_words = {'detected', 'found', 'mentioned', 'activity', 'pattern'}
        specific_count = sum(1 for word in description.lower().split() 
                           if word not in generic_words)
        specific_score = min(specific_count / 20, 1.0)
        
        # Contains technical details
        technical_terms = ['algorithm', 'protocol', 'process', 'registry', 
                          'memory', 'injection', 'evasion', 'encryption']
        tech_score = sum(1 for term in technical_terms 
                        if term in description.lower()) / len(technical_terms)
        
        # Combine
        final = (word_score * 0.4 + specific_score * 0.3 + tech_score * 0.3)
        return round(final, 3)
    
    def _score_tool_mentions(self, ttp: Dict[str, Any], nlp_entities: Dict) -> float:
        """
        Score based on tool/malware mentions
        """
        tools = ttp.get('tools', [])
        related_entities = ttp.get('related_entities', {})
        
        tool_count = len(tools) if tools else 0
        
        # Add entities
        if related_entities:
            tool_count += len(related_entities.get('tools', []))
            tool_count += len(related_entities.get('malware', []))
        
        # NLP entities
        tool_count += len(nlp_entities.get('tools', []))
        tool_count += len(nlp_entities.get('malware', []))
        
        # Score: more tools = more confident
        score = min(0.5 + (tool_count / 5 * 0.4), 1.0)
        
        return round(score, 3)
    
    def _score_context_richness(self, text: str, ttp: Dict) -> float:
        """
        Score based on surrounding context quality
        """
        # Text length
        text_length = len(text.split())
        length_score = min(text_length / 500, 1.0)  # 500+ words = max
        
        # Technique mentioned in text?
        technique = ttp.get('technique_name', '').lower()
        technique_found = technique in text.lower()
        technique_score = 0.9 if technique_found else 0.6
        
        # Multiple sentences mentioning technique
        sentences = text.split('.')
        relevant_sentences = sum(1 for s in sentences 
                               if technique in s.lower())
        relevance_score = min(relevant_sentences / 3, 1.0)
        
        # Combine
        final = (length_score * 0.3 + technique_score * 0.4 + relevance_score * 0.3)
        return round(final, 3)
    
    def _score_multiple_evidence(self, ttp: Dict, nlp_entities: Dict) -> float:
        """
        Score based on multiple independent evidence sources
        """
        evidence_sources = 0
        
        # LLM extraction
        if ttp.get('extraction_method') == 'gemini_llm':
            evidence_sources += 1
        
        # NLP indicators
        if ttp.get('extraction_method') == 'nlp':
            evidence_sources += 1
        
        # Has tools
        if ttp.get('tools'):
            evidence_sources += 1
        
        # Has indicators
        if ttp.get('indicators'):
            evidence_sources += 1
        
        # Has IOCs
        if ttp.get('correlated_iocs'):
            evidence_sources += 1
        
        # Has attack mapping
        if ttp.get('attack_id') and ttp.get('attack_id') != 'UNMAPPED':
            evidence_sources += 1
        
        # Has related entities
        if ttp.get('related_entities'):
            evidence_sources += 1
        
        # NLP corroboration
        if nlp_entities.get('tools') or nlp_entities.get('malware'):
            evidence_sources += 1
        
        # Score: more sources = more confident
        score = min(evidence_sources / 8, 1.0)  # 8 sources possible
        
        return round(score, 3)
    
    def _get_confidence_level(self, score: float) -> ConfidenceLevel:
        """Get confidence level from score"""
        for level in ConfidenceLevel:
            if level.min_score <= score < level.max_score:
                return level
        return ConfidenceLevel.VERY_LOW
    
    def get_level_distribution(self, ttps: List[Dict]) -> Dict[str, int]:
        """
        Analyze confidence level distribution
        """
        distribution = {
            'critical': 0,
            'very_high': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'very_low': 0
        }
        
        for ttp in ttps:
            score = ttp.get('confidence_score', 0)
            level = self._get_confidence_level(score)
            distribution[level.label] += 1
        
        return distribution


def get_enhanced_confidence_scorer() -> EnhancedConfidenceScorer:
    """Factory function"""
    return EnhancedConfidenceScorer()
