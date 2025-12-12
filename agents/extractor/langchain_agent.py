"""
LangChain-Enhanced Extractor Agent
Integrates LangChain for TTP extraction with sophisticated NLP and enrichment
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import uuid
import os

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import ExtractorException
from agents.extractor.mappers.attack_mapper import ATTACKMapper
from agents.extractor.mappers.confidence_scorer import ConfidenceScorer
from agents.extractor.mappers.enhanced_confidence_scorer import EnhancedConfidenceScorer
from agents.extractor.nlp.pipeline import NLPPipeline
from agents.extractor.nlp.entity_extractor import EntityExtractor
from agents.extractor.nlp.tools_ioc_extractor import ToolsAndIndicatorsExtractor
from agents.extractor.nlp.contextual_extractor import ContextualTextExtractor
from agents.extractor.validators import AttackIdValidator, IndicatorExtractor
from core.logging import get_agent_logger
from core.langchain_integration import (
    create_langchain_llm,
    create_ttp_extraction_chain,
    TTPExtractionChain
)


class LangChainExtractorAgent(BaseAgent):
    """
    LangChain-powered TTP Extraction Agent with Advanced Enrichment
    
    Combines:
    1. LangChain for structured, robust LLM interaction
    2. Sophisticated NLP preprocessing (Entities, IOCs)
    3. Advanced post-processing (Enrichment, Scoring, Mapping)
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.ttp_chain: Optional[TTPExtractionChain] = None
        
        # Core components
        self.attack_mapper = ATTACKMapper()
        self.confidence_scorer = ConfidenceScorer()
        self.enhanced_scorer = EnhancedConfidenceScorer()
        self.nlp_pipeline = NLPPipeline()
        self.entity_extractor = EntityExtractor()
        self.tools_ioc_extractor = ToolsAndIndicatorsExtractor()
        self.contextual_extractor = ContextualTextExtractor()
        
        # Validators
        self.attack_id_validator = AttackIdValidator()
        self.indicator_extractor = IndicatorExtractor()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.use_nlp_preprocessing = config.get("use_nlp_preprocessing", True)
        self.min_confidence_threshold = config.get("min_confidence", 0.5)
        self.enable_caching = config.get("enable_caching", True)
        
        # Statistics
        self.stats = {
            "total_reports_processed": 0,
            "total_ttps_extracted": 0,
            "langchain_extractions": 0,
            "traditional_extractions": 0,
            "extraction_errors": 0,
            "avg_confidence_score": 0.0,
            "high_confidence_ttps": 0,
            "nlp_entities_extracted": 0,
            "nlp_ttp_indicators_found": 0,
            "processing_time_ms": 0,
            "nlp_processing_time_ms": 0,
            "llm_processing_time_ms": 0,
            "cache_hits": 0,
            "cache_misses": 0
        }
        
        self._extraction_cache = {}
        
        # Status tracking
        self._can_execute = True
        self._is_paused = False
        
        self.logger = get_agent_logger(f"langchain_extractor_{name}", self.id)
    
    async def start(self) -> None:
        """Start the agent"""
        await super().start()
        self._can_execute = True
        
        try:
            if self.langchain_enabled:
                # Initialize LangChain components
                llm_wrapper = create_langchain_llm(self.llm_config)
                self.ttp_chain = create_ttp_extraction_chain(llm_wrapper)
                
                self.logger.info("LangChain Extractor Agent started (Enhanced Mode)")
            else:
                self.logger.info("LangChain Extractor Agent started (LangChain disabled)")
                
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise ExtractorException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute TTP extraction"""
        if not self._can_execute:
            return {
                "agent_id": self.id,
                "status": "paused",
                "message": "Agent is paused",
                "timestamp": self.get_timestamp()
            }

        start_time = datetime.utcnow()
        self.set_status(AgentStatus.RUNNING)
        
        try:
            # Parse input
            reports = input_data.get("normalized_reports", [])
            if not reports:
                if "reports" in input_data:
                    reports = input_data["reports"]
                elif "text" in input_data:
                    reports = [{"text": input_data["text"], "report_id": "inline", "title": "Inline Report"}]
                elif "report_id" in input_data: # Handle single report object
                     reports = [input_data]
            
            if not reports:
                return {
                    "status": "no_data",
                    "message": "No reports to process"
                }
            
            self.logger.info(f"Processing {len(reports)} reports with LangChain Enhanced")
            
            # Extract from reports
            extraction_results = []
            
            for report in reports:
                try:
                    result = await self._extract_from_report(report)
                    extraction_results.append(result)
                    self.stats["total_reports_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Extraction failed for {report.get('report_id')}: {str(e)}")
                    self.stats["extraction_errors"] += 1
                    continue
            
            # Calculate statistics
            total_ttps = sum(len(r.get("extracted_ttps", [])) for r in extraction_results)
            self.stats["total_ttps_extracted"] += total_ttps
            
            # Calculate confidence statistics
            all_ttps = [ttp for r in extraction_results for ttp in r.get("extracted_ttps", [])]
            if all_ttps:
                confidences = [ttp.get("confidence_score", 0) for ttp in all_ttps]
                self.stats["avg_confidence_score"] = sum(confidences) / len(confidences)
                self.stats["high_confidence_ttps"] += sum(1 for c in confidences if c >= 0.8)
            
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            return {
                "status": "success",
                "extraction_summary": {
                    "reports_processed": len(extraction_results),
                    "total_ttps_extracted": total_ttps,
                    "langchain_extractions": self.stats["langchain_extractions"],
                    "high_confidence_ttps": self.stats["high_confidence_ttps"],
                    "processing_time_ms": processing_time_ms
                },
                "extraction_results": extraction_results,
                "results": extraction_results, # Backwards compatibility
                "ttps": all_ttps
            }
            
        except Exception as e:
            self.logger.error(f"Execution error: {str(e)}")
            self.set_status(AgentStatus.ERROR, str(e))
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _extract_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Extract TTPs from a single report using the full pipeline"""
        report_id = report.get("report_id", "unknown")
        
        # Check cache
        if self.enable_caching and report_id in self._extraction_cache:
            self.stats["cache_hits"] += 1
            return self._extraction_cache[report_id]
        
        self.stats["cache_misses"] += 1
        
        # Report text
        report_text = report.get("text") or report.get("description") or report.get("content", "")
        
        # Step 1: NLP Preprocessing
        nlp_start = datetime.utcnow()
        nlp_results = await self._nlp_processing(report, report_text)
        nlp_time = (datetime.utcnow() - nlp_start).total_seconds() * 1000
        self.stats["nlp_processing_time_ms"] += nlp_time
        
        # Step 2: NLP Indicators
        nlp_ttp_indicators = nlp_results.get("ttp_indicators", {})
        self.stats["nlp_ttp_indicators_found"] += len(nlp_ttp_indicators)
        if "entities" in nlp_results:
             self.stats["nlp_entities_extracted"] += (
                len(nlp_results["entities"].get("malware", [])) +
                len(nlp_results["entities"].get("tools", [])) +
                len(nlp_results["entities"].get("threat_actors", []))
            )
        
        # Step 3: LangChain Extraction
        llm_start = datetime.utcnow()
        llm_ttps = []
        
        if self.langchain_enabled and self.ttp_chain:
            try:
                # Build context string
                context_str = self._build_context_string(report, nlp_results)
                
                # Execute chain
                ttp_output = await self.ttp_chain.extract(report_text, context_str)
                
                # Convert
                llm_ttps = [
                    {
                        "technique_name": ttp.technique_name,
                        "technique_id": ttp.technique_id,
                        "tactic": ttp.tactic,
                        "description": ttp.description,
                        "confidence": ttp.confidence,
                        "indicators": ttp.indicators,
                        "tools": ttp.tools,
                        "extraction_method": "langchain_llm",
                        "source": "langchain"
                    }
                    for ttp in ttp_output.ttps
                ]
                self.stats["langchain_extractions"] += 1
                
            except Exception as e:
                self.logger.warning(f"LangChain extraction failed: {e}")
                llm_ttps = []
        
        llm_time = (datetime.utcnow() - llm_start).total_seconds() * 1000
        self.stats["llm_processing_time_ms"] += llm_time
        
        # Step 4: NLP TTPs
        nlp_ttps = self._create_ttps_from_nlp_indicators(nlp_ttp_indicators)
        
        # Step 5: Merge
        all_ttps = nlp_ttps + llm_ttps
        
        # Fallback if empty
        if not all_ttps:
            fallback_ttps = await self._traditional_extraction(report_text)
            all_ttps.extend(fallback_ttps)

        # Step 6: Map to ATT&CK
        mapped_ttps = await self._map_ttps_to_attack(all_ttps)
        
        # Step 7: Enrich
        enriched_ttps = self._enrich_ttps_with_entities(mapped_ttps, nlp_results, report_text)
        
        # Step 8: Score
        scored_ttps = self._score_ttps(enriched_ttps, report)
        
        # Step 9: Filter
        filtered_ttps = [
            ttp for ttp in scored_ttps
            if ttp.get("confidence_score", 0) >= self.min_confidence_threshold
        ]
        
        # Step 10: Format
        formatted_ttps = [
            self._format_ttp_for_handoff(ttp, report)
            for ttp in filtered_ttps
        ]
        
        result = {
            "report_id": report_id,
            "extracted_ttps": formatted_ttps, # Standardized key
            "nlp_analysis": nlp_results,
            "metadata": {
                "extraction_method": "LangChain-Enhanced",
                "nlp_processing_time_ms": nlp_time,
                "llm_processing_time_ms": llm_time
            }
        }
        
        # Cache
        if self.enable_caching:
            self._extraction_cache[report_id] = result
            
        return result

    async def _nlp_processing(self, report: Dict[str, Any], text: str) -> Dict[str, Any]:
        """Sophisticated NLP processing"""
        if not self.use_nlp_preprocessing:
            return {}
            
        # Process text
        processed_text = self.nlp_pipeline.process(text)
        
        # Extract entities
        extracted_entities = self.entity_extractor.extract(text)
        
        # Extract indicators
        ttp_indicators = self.nlp_pipeline.extract_ttp_indicators(text)
        
        return {
            "processed_text": {
                "cleaned_text": processed_text.cleaned_text,
                "commands": processed_text.commands,
                "file_paths": processed_text.file_paths,
                "registry_keys": processed_text.registry_keys
            },
            "entities": {
                "malware": extracted_entities.malware_families,
                "tools": extracted_entities.tools,
                "threat_actors": extracted_entities.threat_actors,
                "ips": extracted_entities.ip_addresses,
                "domains": extracted_entities.domains,
                "hashes": {k: v[:5] for k, v in extracted_entities.file_hashes.items()}
            },
            "ttp_indicators": ttp_indicators,
            "context": self.nlp_pipeline.enhance_llm_prompt(processed_text)
        }
    
    def _build_context_string(self, report: Dict[str, Any], nlp_results: Dict[str, Any]) -> str:
        """Build context string for the LLM prompt"""
        
        title = report.get("title", "Unknown")
        threat_actors = report.get("threat_actors", [])
        malware = report.get("malware_families", [])
        iocs = report.get("indicators", [])
        
        # Get NLP context
        entities = nlp_results.get("entities", {})
        processed = nlp_results.get("processed_text", {})
        ttp_indicators = nlp_results.get("ttp_indicators", {})
        
        # Build pieces
        parts = [
            f"**Report Title:** {title}",
            f"**Known Threat Actors:** {', '.join(threat_actors) if threat_actors else 'None'}",
            f"**Malware Families:** {', '.join(malware) if malware else 'None'}"
        ]
        
        # NLP Findings
        nlp_summary = []
        if entities.get("malware"): nlp_summary.append(f"Detected Malware: {', '.join(entities['malware'][:5])}")
        if entities.get("tools"): nlp_summary.append(f"Detected Tools: {', '.join(entities['tools'][:5])}")
        if processed.get("commands"): nlp_summary.append(f"Detected {len(processed['commands'])} commands")
        
        if nlp_summary:
            parts.append("**NLP Analysis Findings:**\n" + "\n".join(nlp_summary))
            
        # IOCs
        if iocs:
            parts.append("**Key IOCs:**\n" + self._summarize_iocs(iocs))
            
        return "\n\n".join(parts)

    def _summarize_iocs(self, iocs: List[Dict]) -> str:
        """Summarize IOCs"""
        if not iocs: return "No IOCs"
        by_type = {}
        for ioc in iocs[:15]:
            t = ioc.get("type", "unknown")
            by_type.setdefault(t, []).append(ioc.get("value", ""))
        return "\n".join([f"- {k}: {', '.join(v[:3])}" for k, v in by_type.items()])

    def _create_ttps_from_nlp_indicators(self, indicators: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Create TTPs from NLP patterns"""
        ttps = []
        for tactic, techniques in indicators.items():
            for technique in techniques:
                ttps.append({
                    "technique_name": technique,
                    "tactic": tactic.replace("_", " ").title(),
                    "description": f"Detected {technique} activity via NLP pattern matching",
                    "indicators": [],
                    "tools": [],
                    "extraction_method": "nlp_indicator",
                    "source": "nlp",
                    "confidence": 0.6 # Base confidence for NLP match
                })
        return ttps

    async def _map_ttps_to_attack(self, ttps: List[Dict]) -> List[Dict[str, Any]]:
        """Map to MITRE ATT&CK"""
        mapped = []
        for ttp in ttps:
            try:
                mapping = self.attack_mapper.map_technique(
                    technique_name=ttp.get("technique_name", ""),
                    tactic=ttp.get("tactic", ""),
                    description=ttp.get("description", "")
                )
                if mapping:
                    ttp["attack_id"] = mapping["technique_id"]
                    ttp["subtechnique"] = mapping.get("subtechnique", False)
                else:
                    ttp["attack_id"] = "UNMAPPED"
                mapped.append(ttp)
            except Exception:
                ttp["attack_id"] = "UNMAPPED"
                mapped.append(ttp)
        return mapped

    def _enrich_ttps_with_entities(self, ttps: List[Dict], nlp_results: Dict, text: str) -> List[Dict]:
        """Enrichment logic"""
        entities = nlp_results.get("entities", {})
        
        for ttp in ttps:
            # Tools
            tools_res = self.tools_ioc_extractor.extract_tools(text, entities)
            ttp["tools"] = list(set(ttp.get("tools", []) + tools_res.get("all_tools", [])))
            ttp["tools_by_category"] = tools_res.get("by_category", {})
            
            # Context
            context = self.contextual_extractor.extract_full_context(text, ttp.get("technique_name", ""))
            ttp["extraction_context"] = context
            
            # Relationship to entities
            ttp["related_entities"] = {
                "malware": entities.get("malware", []),
                "threat_actors": entities.get("threat_actors", [])
            }
            
        return ttps

    def _score_ttps(self, ttps: List[Dict], report: Dict) -> List[Dict]:
        """Calculate confidence scores"""
        text = report.get("text") or report.get("description", "")
        scored = []
        
        for ttp in ttps:
            try:
                res = self.enhanced_scorer.calculate_score(ttp, report, text, {})
                ttp["confidence_score"] = res["score"]
                ttp["confidence_level"] = res["level"]
                ttp["confidence_breakdown"] = res["breakdown"]
                scored.append(ttp)
            except Exception as e:
                # Fallback
                base = ttp.get("confidence", 0.5)
                ttp["confidence_score"] = float(base)
                scored.append(ttp)
        
        return sorted(scored, key=lambda x: x.get("confidence_score", 0), reverse=True)

    def _format_ttp_for_handoff(self, ttp: Dict, report: Dict) -> Dict:
        """Format for output"""
        fix = self.attack_id_validator.validate_attack_id(ttp.get("attack_id", ""))
        attack_id = fix.validated_id if fix.is_valid else ttp.get("attack_id")
        
        return {
            "ttp_id": str(uuid.uuid4()),
            "report_id": report.get("report_id"),
            "technique_name": ttp.get("technique_name"),
            "attack_id": attack_id,
            "tactic": ttp.get("tactic"),
            "description": ttp.get("description"),
            "confidence_score": ttp.get("confidence_score"),
            "confidence_level": ttp.get("confidence_level"),
            "confidence_breakdown": ttp.get("confidence_breakdown"),
            "indicators": ttp.get("indicators", []),
            "tools": ttp.get("tools", []),
            "extraction_method": ttp.get("extraction_method", "unknown")
        }

    async def _traditional_extraction(self, text: str) -> List[Dict]:
        """Fallback extraction"""
        self.stats["traditional_extractions"] += 1
        ttps = []
        if "phishing" in text.lower():
            ttps.append({
                "technique_name": "Phishing",
                "attack_id": "T1566",
                "tactic": "Initial Access",
                "description": "Phishing detected in text",
                "confidence": 0.6,
                "source": "fallback"
            })
        return ttps

    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        if not isinstance(data, dict):
            return False
        
        if "normalized_reports" in data:
            reports = data["normalized_reports"]
            if not isinstance(reports, list):
                return False
            
            for report in reports:
                if not self._validate_report(report) and not report.get("text"): 
                    # Allow text-only reports for direct extraction
                    if not report.get("text"): 
                        return False
        
        elif "report_id" in data:
            if not self._validate_report(data) and not data.get("text"):
                 return False
                 
        elif "text" in data or "reports" in data:
            return True # Allow raw text input
        
        return True
    
    def _validate_report(self, report: Dict[str, Any]) -> bool:
        """Validate individual report"""
        # Lax validation to allow for varied inputs
        if "report_id" not in report and "title" not in report:
            return False
        return True

    async def pause(self) -> None:
        """Pause agent"""
        self._is_paused = True
        self._can_execute = False
        self.set_status(AgentStatus.IDLE, "Agent paused")

    async def resume(self) -> None:
        """Resume agent"""
        self._is_paused = False
        self._can_execute = True
        self.set_status(AgentStatus.IDLE, "Agent resumed")

    async def shutdown(self):
        """Shutdown agent"""
        try:
            await self.stop()
            self.logger.info("LangChainExtractorAgent shutdown complete")
        except Exception as e:
            self.logger.error(f"Shutdown error: {str(e)}")

    def clear_cache(self) -> int:
        """Clear extraction cache"""
        count = len(self._extraction_cache)
        self._extraction_cache.clear()
        return count

    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.stats["cache_hits"] + self.stats["cache_misses"]
        if total == 0:
            return 0.0
        return round((self.stats["cache_hits"] / total) * 100, 2)

    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check behavior"""
        base_health = await super().health_check()
        
        health_score = 100
        
        # Error rate penalty
        if self.stats["total_reports_processed"] > 0:
            error_rate = self.stats["extraction_errors"] / self.stats["total_reports_processed"]
            health_score -= min(error_rate * 50, 30)
        
        # Low confidence penalty
        if self.stats["total_ttps_extracted"] > 0:
            low_conf_count = self.stats["total_ttps_extracted"] - self.stats["high_confidence_ttps"]
            low_conf_rate = low_conf_count / self.stats["total_ttps_extracted"]
            health_score -= min(low_conf_rate * 30, 20)
        
        if self._is_paused:
            health_score = 50
        
        health_score = max(0, health_score)
        health_status = (
            "healthy" if health_score >= 80
            else "degraded" if health_score >= 60
            else "unhealthy"
        )
        
        base_health.update({
            "status": {
                "current": self.status.value,
                "is_paused": self._is_paused,
                "can_execute": self._can_execute
            },
            "performance": {
                "total_processing_time_ms": self.stats["processing_time_ms"],
                "nlp_processing_time_ms": self.stats["nlp_processing_time_ms"],
                "llm_processing_time_ms": self.stats["llm_processing_time_ms"],
                "gemini_api_calls": self.stats.get("gemini_api_calls", 0), # Using .get just in case, though it is in init
                "cache_hit_rate": self._calculate_cache_hit_rate()
            },
            "quality": {
                "avg_confidence": self.stats["avg_confidence_score"],
                "high_confidence_ttps": self.stats["high_confidence_ttps"],
                "nlp_entities_found": self.stats["nlp_entities_extracted"],
                "nlp_indicators_found": self.stats["nlp_ttp_indicators_found"]
            },
            "health": {
                "score": round(health_score, 1),
                "status": health_status
            }
        })
        
        return base_health
