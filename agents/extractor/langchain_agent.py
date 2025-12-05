"""
LangChain-Enhanced Extractor Agent
Integrates LangChain for TTP extraction
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import os

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import ExtractorException
from agents.extractor.mappers.attack_mapper import ATTACKMapper
from agents.extractor.mappers.confidence_scorer import ConfidenceScorer
from agents.extractor.nlp.pipeline import NLPPipeline
from agents.extractor.nlp.entity_extractor import EntityExtractor
from core.logging import get_agent_logger
from core.langchain_integration import (
    create_langchain_llm,
    create_ttp_extraction_chain,
    TTPExtractionChain
)


class LangChainExtractorAgent(BaseAgent):
    """
    LangChain-powered TTP Extraction Agent
    
    Uses LangChain for structured TTP extraction with:
    - Pydantic output parsing
    - Automatic retries
    - Better prompt management
    - Structured outputs
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.ttp_chain: Optional[TTPExtractionChain] = None
        
        # Traditional components
        self.attack_mapper = ATTACKMapper()
        self.confidence_scorer = ConfidenceScorer()
        self.nlp_pipeline = NLPPipeline()
        self.entity_extractor = EntityExtractor()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.use_nlp_preprocessing = config.get("use_nlp_preprocessing", True)
        self.min_confidence_threshold = config.get("min_confidence", 0.5)
        
        # Statistics
        self.stats = {
            "total_reports_processed": 0,
            "total_ttps_extracted": 0,
            "langchain_extractions": 0,
            "traditional_extractions": 0,
            "extraction_errors": 0,
            "avg_confidence_score": 0.0,
            "processing_time_ms": 0
        }
        
        self.logger = get_agent_logger(f"langchain_extractor_{name}", self.id)
    
    async def start(self) -> None:
        """Start the agent"""
        await super().start()
        
        try:
            if self.langchain_enabled:
                # Initialize LangChain components
                llm_wrapper = create_langchain_llm(self.llm_config)
                self.ttp_chain = create_ttp_extraction_chain(llm_wrapper)
                
                self.logger.info("LangChain Extractor Agent started with LangChain integration")
            else:
                self.logger.info("LangChain Extractor Agent started (LangChain disabled)")
                
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise ExtractorException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute TTP extraction"""
        start_time = datetime.utcnow()
        
        try:
            # Parse input
            reports = input_data.get("reports", [])
            if not reports and "text" in input_data:
                reports = [{"text": input_data["text"], "report_id": "inline"}]
            
            if not reports:
                return {
                    "status": "no_data",
                    "message": "No reports to process"
                }
            
            self.logger.info(f"Processing {len(reports)} reports with LangChain")
            
            # Extract from reports
            extraction_results = []
            
            for report in reports:
                try:
                    result = await self._extract_from_report(report)
                    extraction_results.append(result)
                    self.stats["total_reports_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Extraction failed: {str(e)}")
                    self.stats["extraction_errors"] += 1
                    continue
            
            # Calculate statistics
            total_ttps = sum(len(r.get("ttps", [])) for r in extraction_results)
            self.stats["total_ttps_extracted"] += total_ttps
            
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            return {
                "status": "success",
                "extraction_summary": {
                    "reports_processed": len(extraction_results),
                    "total_ttps_extracted": total_ttps,
                    "langchain_extractions": self.stats["langchain_extractions"],
                    "processing_time_ms": processing_time_ms
                },
                "results": extraction_results,
                "ttps": [ttp for r in extraction_results for ttp in r.get("ttps", [])]
            }
            
        except Exception as e:
            self.logger.error(f"Execution error: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _extract_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Extract TTPs from a single report"""
        report_text = report.get("text", report.get("content", ""))
        
        # Step 1: NLP preprocessing
        nlp_context = {}
        if self.use_nlp_preprocessing:
            nlp_context = await self._nlp_preprocessing(report_text)
        
        # Step 2: LangChain extraction
        if self.langchain_enabled and self.ttp_chain:
            try:
                ttp_output = await self.ttp_chain.extract(report_text, nlp_context)
                
                # Convert to dict format
                ttps = [
                    {
                        "ttp_id": f"ttp_{i}",
                        "technique_name": ttp.technique_name,
                        "technique_id": ttp.technique_id,
                        "tactic": ttp.tactic,
                        "description": ttp.description,
                        "confidence_score": ttp.confidence,
                        "indicators": ttp.indicators,
                        "tools": ttp.tools,
                        "source": "langchain"
                    }
                    for i, ttp in enumerate(ttp_output.ttps)
                ]
                
                self.stats["langchain_extractions"] += 1
                
                return {
                    "report_id": report.get("report_id", "unknown"),
                    "ttps": ttps,
                    "extraction_method": "langchain",
                    "nlp_context": nlp_context
                }
                
            except Exception as e:
                self.logger.warning(f"LangChain extraction failed: {e}, falling back")
                return await self._traditional_extraction(report_text, nlp_context, report)
        else:
            return await self._traditional_extraction(report_text, nlp_context, report)
    
    async def _nlp_preprocessing(self, text: str) -> Dict[str, Any]:
        """NLP preprocessing"""
        try:
            # Extract entities
            entities_obj = self.entity_extractor.extract(text)
            
            # Convert dataclass to dict/list for JSON serialization
            entities = []
            if entities_obj.malware_families:
                entities.extend([{"type": "malware", "value": m} for m in entities_obj.malware_families])
            if entities_obj.tools:
                entities.extend([{"type": "tool", "value": t} for t in entities_obj.tools])
            if entities_obj.threat_actors:
                entities.extend([{"type": "actor", "value": a} for a in entities_obj.threat_actors])
            
            # Extract IOCs
            iocs = []
            if entities_obj.ip_addresses:
                iocs.extend([{"type": "ip", "value": ip} for ip in entities_obj.ip_addresses])
            if entities_obj.domains:
                iocs.extend([{"type": "domain", "value": d} for d in entities_obj.domains])
            for hash_type, hashes in entities_obj.file_hashes.items():
                iocs.extend([{"type": hash_type, "value": h} for h in hashes])
            
            # Extract keywords (simplified)
            keywords = []
            for word in text.lower().split():
                if len(word) > 5 and word.isalpha():
                    keywords.append(word)
            
            return {
                "entities": entities[:20],
                "iocs": iocs[:20],
                "keywords": list(set(keywords))[:20]
            }
            
        except Exception as e:
            self.logger.error(f"NLP preprocessing error: {e}")
            return {"entities": [], "iocs": [], "keywords": []}
    
    async def _traditional_extraction(self, text: str, nlp_context: Dict, report: Dict) -> Dict[str, Any]:
        """Traditional extraction fallback"""
        self.stats["traditional_extractions"] += 1
        
        # Simple keyword-based extraction
        ttps = []
        
        # Check for common techniques
        if "phishing" in text.lower() or "spearphishing" in text.lower():
            ttps.append({
                "ttp_id": "ttp_fallback_1",
                "technique_name": "Phishing",
                "technique_id": "T1566",
                "tactic": "Initial Access",
                "description": "Phishing detected in report",
                "confidence_score": 0.6,
                "indicators": [],
                "tools": [],
                "source": "traditional"
            })
        
        if "powershell" in text.lower():
            ttps.append({
                "ttp_id": "ttp_fallback_2",
                "technique_name": "PowerShell",
                "technique_id": "T1059.001",
                "tactic": "Execution",
                "description": "PowerShell execution detected",
                "confidence_score": 0.6,
                "indicators": [],
                "tools": [],
                "source": "traditional"
            })
        
        return {
            "report_id": report.get("report_id", "unknown"),
            "ttps": ttps,
            "extraction_method": "traditional",
            "nlp_context": nlp_context
        }
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        return "reports" in data or "text" in data
