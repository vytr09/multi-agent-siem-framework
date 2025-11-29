#!/usr/bin/env python3
"""
Enhanced Text Context Extraction
Cải thiện việc extract full context và aggregate information
"""

import re
from typing import List, Tuple, Dict
from collections import defaultdict


class ContextualTextExtractor:
    """
    Extract rich contextual information for TTPs
    - Paragraph-level context (không chỉ sentence)
    - Cross-sentence aggregation
    - Semantic similarity for grouping
    """
    
    def __init__(self):
        self.sentence_splitter = re.compile(r'(?<=[.!?])\s+(?=[A-Z])')
    
    def extract_full_context(
        self,
        text: str,
        target_technique: str,
        context_window: int = 2,
        max_length: int = 300
    ) -> Dict[str, str]:
        """
        Extract full context for a technique
        
        Args:
            text: Full report text
            target_technique: Technique name to search for
            context_window: Sentences before/after to include
            max_length: Max character length for context
        
        Returns:
            Dict with immediate_context, paragraph_context, full_context
        """
        sentences = self.sentence_splitter.split(text)
        
        # Find relevant sentences
        target_lower = target_technique.lower()
        relevant_indices = []
        
        for i, sentence in enumerate(sentences):
            if target_lower in sentence.lower():
                relevant_indices.append(i)
        
        if not relevant_indices:
            return {
                'found': False,
                'technique': target_technique,
                'context': f"Detected {target_technique}",
                'confidence_modifier': 0.7
            }
        
        # Expand window
        all_indices = set()
        for idx in relevant_indices:
            for offset in range(-context_window, context_window + 1):
                new_idx = idx + offset
                if 0 <= new_idx < len(sentences):
                    all_indices.add(new_idx)
        
        # Build context
        immediate_context = ' '.join(
            sentences[i].strip() for i in sorted(all_indices)
        )
        
        # Truncate if too long
        if len(immediate_context) > max_length:
            immediate_context = immediate_context[:max_length] + "..."
        
        # Get paragraph context (find paragraph boundaries)
        paragraph_context = self._extract_paragraph_context(text, target_technique)
        
        return {
            'found': True,
            'technique': target_technique,
            'immediate_context': immediate_context,
            'paragraph_context': paragraph_context,
            'full_context': text[:500],  # First 500 chars
            'context_richness_score': min(len(immediate_context) / max_length, 1.0),
            'confidence_modifier': self._calculate_context_confidence_boost(
                immediate_context,
                target_technique
            )
        }
    
    def _extract_paragraph_context(self, text: str, technique: str) -> str:
        """Extract paragraph containing technique"""
        # Split by double newline or indent
        paragraphs = re.split(r'\n\n+|\n(?=\t|\s{2,})', text)
        
        technique_lower = technique.lower()
        
        for para in paragraphs:
            if technique_lower in para.lower():
                return para.strip()
        
        # Fallback to first 300 chars
        return text[:300]
    
    def aggregate_related_information(
        self,
        text: str,
        technique: str,
        related_keywords: List[str] = None
    ) -> Dict[str, any]:
        """
        Aggregate information about a technique from multiple parts of text
        """
        if related_keywords is None:
            related_keywords = []
        
        sentences = self.sentence_splitter.split(text)
        technique_lower = technique.lower()
        
        # Find all sentences mentioning technique or keywords
        related_sentences = []
        for sentence in sentences:
            sentence_lower = sentence.lower()
            if technique_lower in sentence_lower:
                related_sentences.append(sentence.strip())
            elif related_keywords:
                if any(kw.lower() in sentence_lower for kw in related_keywords):
                    related_sentences.append(sentence.strip())
        
        # Group by semantic similarity (simple: length and keyword overlap)
        grouped = self._group_sentences_by_similarity(
            related_sentences,
            technique
        )
        
        # Aggregate
        aggregated = {
            'technique': technique,
            'mention_count': len(related_sentences),
            'sentence_groups': grouped,
            'full_aggregation': ' '.join(related_sentences[:5]),
            'richness_score': min(len(' '.join(related_sentences)) / 500, 1.0)
        }
        
        return aggregated
    
    def _group_sentences_by_similarity(
        self,
        sentences: List[str],
        technique: str
    ) -> List[Dict[str, any]]:
        """
        Group sentences by semantic similarity
        Simple approach: group by keyword overlap
        """
        groups = []
        technique_words = set(technique.lower().split())
        
        for sentence in sentences:
            sentence_words = set(sentence.lower().split())
            
            # Calculate similarity with technique
            overlap = len(technique_words & sentence_words)
            similarity = overlap / max(len(technique_words), 1)
            
            groups.append({
                'sentence': sentence,
                'similarity_to_technique': round(similarity, 2),
                'word_count': len(sentence.split())
            })
        
        # Sort by similarity and word count
        groups.sort(
            key=lambda x: (x['similarity_to_technique'], x['word_count']),
            reverse=True
        )
        
        return groups[:5]  # Top 5 most relevant
    
    def calculate_description_enhancement(
        self,
        original_description: str,
        context: Dict[str, str],
        technique: str
    ) -> Dict[str, any]:
        """
        Enhance description with context information
        """
        enhancements = {
            'original': original_description,
            'enhanced': original_description,
            'added_context': [],
            'confidence_boost': 0
        }
        
        # Add context if available
        if context.get('found') and 'immediate_context' in context:
            context_text = context['immediate_context']
            
            # Check if context adds new information
            original_words = set(original_description.lower().split())
            context_words = set(context_text.lower().split())
            
            new_info = context_words - original_words
            if new_info:
                enhancements['added_context'] = list(new_info)[:10]
                enhancements['enhanced'] = f"{original_description}. {context_text}"
                enhancements['confidence_boost'] = min(len(new_info) / 20, 0.15)
        
        return enhancements
    
    def _calculate_context_confidence_boost(self, context: str, technique: str) -> float:
        """
        Calculate confidence boost based on context quality
        """
        boost = 0
        
        # Length bonus (more context = more confidence)
        length_boost = min(len(context) / 300 * 0.1, 0.1)
        boost += length_boost
        
        # Specificity bonus (specific details)
        specific_terms = {
            'algorithm', 'encryption', 'process', 'memory',
            'registry', 'network', 'injection', 'evasion',
            'payload', 'shellcode', 'technique'
        }
        specificity = sum(1 for term in specific_terms if term in context.lower())
        specificity_boost = min(specificity / 5 * 0.1, 0.1)
        boost += specificity_boost
        
        # Action verb bonus (describes actual actions)
        action_verbs = {
            'uses', 'exploits', 'implements', 'executes', 'injects',
            'modifies', 'steals', 'captures', 'extracts', 'exfiltrates'
        }
        action = sum(1 for verb in action_verbs if verb in context.lower())
        action_boost = min(action / 3 * 0.1, 0.1)
        boost += action_boost
        
        return round(boost, 3)
    
    def expand_short_descriptions(
        self,
        ttps: List[Dict],
        text: str
    ) -> List[Dict]:
        """
        Expand TTPs with short descriptions using text context
        """
        enhanced_ttps = []
        
        for ttp in ttps:
            description = ttp.get('description', '')
            technique = ttp.get('technique_name', '')
            
            # Check if description is short
            if len(description.split()) < 15:
                context = self.extract_full_context(text, technique)
                
                if context.get('found'):
                    # Expand description
                    enhanced_desc = self.calculate_description_enhancement(
                        description,
                        context,
                        technique
                    )
                    
                    ttp['description_original'] = description
                    ttp['description'] = enhanced_desc['enhanced'][:200]
                    ttp['context_boost'] = enhanced_desc['confidence_boost']
                else:
                    ttp['context_boost'] = 0
            else:
                ttp['context_boost'] = 0
            
            enhanced_ttps.append(ttp)
        
        return enhanced_ttps
    
    def extract_multi_sentence_evidence(
        self,
        text: str,
        technique: str,
        keywords: List[str] = None
    ) -> Dict[str, any]:
        """
        Extract evidence for a technique from multiple sentences
        """
        if keywords is None:
            keywords = []
        
        sentences = self.sentence_splitter.split(text)
        technique_lower = technique.lower()
        
        evidence = {
            'technique': technique,
            'direct_mentions': [],  # Sentences directly mentioning technique
            'supporting_evidence': [],  # Sentences with related keywords
            'tools_context': [],
            'indicators_context': []
        }
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            
            if technique_lower in sentence_lower:
                evidence['direct_mentions'].append(sentence.strip())
            
            # Supporting evidence
            if keywords and any(kw.lower() in sentence_lower for kw in keywords):
                evidence['supporting_evidence'].append(sentence.strip())
            
            # Tools context
            tools_keywords = ['tool', 'malware', 'utility', 'software', 'program']
            if any(t in sentence_lower for t in tools_keywords):
                evidence['tools_context'].append(sentence.strip())
            
            # Indicators context
            ioc_keywords = ['ip', 'domain', 'url', 'hash', 'file', 'registry', 'port']
            if any(i in sentence_lower for i in ioc_keywords):
                evidence['indicators_context'].append(sentence.strip())
        
        # Limit evidence items
        for key in evidence:
            if isinstance(evidence[key], list):
                evidence[key] = evidence[key][:3]
        
        return evidence


def get_contextual_text_extractor() -> ContextualTextExtractor:
    """Factory function"""
    return ContextualTextExtractor()
