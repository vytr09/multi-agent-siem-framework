# agents/collector/normalizers/pdf_normalizer.py
from typing import Dict, Any
from agents.collector.normalizers.base import BaseNormalizer
from agents.base.exceptions import DataNormalizationException

class PDFDatasetNormalizer(BaseNormalizer):
    """
    Normalizes offline PDF-based CTI into standard CTI format.
    """

    def normalize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            content = raw_event["content"]
            report_id = self._generate_report_id()
            return {
                "report_id": report_id,
                "source": raw_event["source"],
                "title": raw_event["metadata"]["filename"],
                "description": content[:1000],  # preview
                "confidence": 50,
                "severity": "low",
                "published": False,
                "indicators": [],
                "threat_actors": [],
                "malware_families": [],
                "attack_patterns": [],
                "raw_data": raw_event
            }
        except Exception as e:
            raise DataNormalizationException(f"PDF normalization failed: {e}")
