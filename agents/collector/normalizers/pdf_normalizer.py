import re
import hashlib
import uuid
from typing import Dict, Any, List, Set
from agents.collector.normalizers.base import BaseNormalizer
from agents.base.exceptions import DataNormalizationException

class PDFDatasetNormalizer(BaseNormalizer):
    """
    Normalizes offline PDF-based CTI into standard CTI format.
    Implements IntelEx IoC-Guided Chunking Mechanism.
    """

    def __init__(self):
        super().__init__()
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for Anchor Identification (IntelEx)"""
        # Simplified regexes from Extractor/NLP pipeline to identify 'Anchor Sentences'
        self.patterns = {
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE),
            'hash': re.compile(r'\b[a-fA-F0-9]{32,64}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
            'keywords': re.compile(r'\b(attack|exploit|backdoor|malware|trojan|ransomware|c2|phishing|inject|execute)\b', re.IGNORECASE)
        }

    def normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            content = raw_event.get("content", "")
            if not content:
                return {}

            # Generate stable ID based on content hash (Deduplication support)
            content_hash = hashlib.md5(f"{raw_event.get('source')}{content[:1000]}".encode()).hexdigest()
            report_id = f"pdf-{content_hash}"
            
            # Metadata
            filename = raw_event.get("metadata", {}).get("filename", "unknown.pdf")
            
            # IntelEx Chunking
            chunks = self._perform_chunking(content)

            return {
                "report_id": report_id,
                "source": raw_event.get("source", "unknown"),
                "title": filename,
                "description": content[:5000], # Preserve more text for context, but keep limit
                "text": content, # Full text for Extractor
                "chunks": chunks, # Structured IntelEx chunks
                "confidence": 80, # Increased confidence due to specialized processing
                "severity": "medium",
                "published": False,
                "indicators": [],
                "threat_actors": [],
                "malware_families": [],
                "tags": ["pdf_ingestion", "intelex_chunked"],
                "raw_data": {k:v for k,v in raw_event.items() if k != "content"} # Don't duplicate full content in raw_data
            }
        except Exception as e:
            raise DataNormalizationException(f"PDF normalization failed: {e}")

    def _perform_chunking(self, text: str) -> List[str]:
        """
        Implement IntelEx IoC-Guided Chunking:
        1. Split sentences.
        2. Identify Anchors (sentences with IoCs/Keywords).
        3. Sliding Window around Anchors (Size 5: -2 to +2).
        4. Deduplicate.
        """
        # 1. Split sentences (Simple heuristic, can be improved with NLTK if available)
        # Handle common abbreviations to avoid bad splits like 'e.g.'
        text_clean = re.sub(r'(?<=e\.g)\.', '', text)
        text_clean = re.sub(r'(?<=i\.e)\.', '', text_clean)
        sentences = [s.strip() for s in re.split(r'[.!?]\s+', text_clean) if s.strip()]
        
        if not sentences:
            return []

        anchor_indices = set()
        
        # 2. Identify Anchors
        for i, sent in enumerate(sentences):
            if self._is_anchor(sent):
                anchor_indices.add(i)
        
        # 3. Sliding Window & Merge
        # IntelEx suggests context window. We use +/- 2 sentences.
        selected_indices = set()
        window_size = 2
        
        for idx in anchor_indices:
            start = max(0, idx - window_size)
            end = min(len(sentences), idx + window_size + 1)
            selected_indices.update(range(start, end))
            
        sorted_indices = sorted(list(selected_indices))
        
        if not sorted_indices:
            # Fallback: if no specific anchors, take first 5 and last 5 sentences
            return sentences[:5] + sentences[-5:] if len(sentences) > 10 else sentences

        # 4. Construct Chunks
        final_chunks = []
        current_chunk_indices = []
        
        # Group consecutive indices into chunks
        for i, idx in enumerate(sorted_indices):
            if not current_chunk_indices:
                current_chunk_indices.append(idx)
                continue
                
            if idx == current_chunk_indices[-1] + 1:
                current_chunk_indices.append(idx)
            else:
                # Gap found, finalize current chunk
                chunk_text = " ".join([sentences[j] for j in current_chunk_indices])
                final_chunks.append(chunk_text)
                current_chunk_indices = [idx]
        
        if current_chunk_indices:
            chunk_text = " ".join([sentences[j] for j in current_chunk_indices])
            final_chunks.append(chunk_text)
            
        return final_chunks

    def _is_anchor(self, sentence: str) -> bool:
        """Check if sentence contains IoCs or Threat Keywords"""
        for pattern in self.patterns.values():
            if pattern.search(sentence):
                return True
        return False
