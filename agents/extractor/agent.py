"""
Extractor Agent - Hybrid NLP + Gemini LLM Approach

Processing flow:
1. NLP: Extract entities, patterns, IOCs
2. NLP: Identify TTP indicators from text
3. LLM: Generate high-level TTPs with NLP context
4. ATT&CK: Map to MITRE ATT&CK techniques
5. Scoring: Calculate confidence scores
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from collections import deque
import uuid
import os
from dotenv import load_dotenv

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import ExtractorException, LLMException
from agents.extractor.llm.gemini_client import create_llm_client
from agents.extractor.mappers.attack_mapper import ATTACKMapper
from agents.extractor.mappers.confidence_scorer import ConfidenceScorer
from agents.extractor.mappers.enhanced_confidence_scorer import EnhancedConfidenceScorer
from agents.extractor.nlp.pipeline import NLPPipeline
from agents.extractor.nlp.entity_extractor import EntityExtractor
from agents.extractor.nlp.tools_ioc_extractor import ToolsAndIndicatorsExtractor
from agents.extractor.nlp.contextual_extractor import ContextualTextExtractor
from agents.extractor.validators import AttackIdValidator, IndicatorExtractor, AdvancedTechniqueDiscovery
from core.logging import get_agent_logger

load_dotenv()


class ExtractorAgent(BaseAgent):
    """
    Hybrid TTP Extraction Agent using NLP + Gemini LLM.
    
    Architecture:
    1. NLP Processing: Extract entities and structure text
    2. NLP Indicators: Identify TTP patterns from keywords
    3. LLM Enhancement: Gemini extracts TTPs with NLP context
    4. ATT&CK Mapping: Map to MITRE framework
    5. Confidence Scoring: Multi-factor confidence calculation
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Initialize components
        self.llm_client = None
        self.attack_mapper = ATTACKMapper()
        self.confidence_scorer = ConfidenceScorer()
        self.enhanced_scorer = EnhancedConfidenceScorer()
        self.nlp_pipeline = NLPPipeline()
        self.entity_extractor = EntityExtractor()
        self.tools_ioc_extractor = ToolsAndIndicatorsExtractor()
        self.contextual_extractor = ContextualTextExtractor()
        
        # Initialize validators
        self.attack_id_validator = AttackIdValidator()
        self.indicator_extractor = IndicatorExtractor()
        self.technique_discoverer = AdvancedTechniqueDiscovery()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.use_mock_llm = self.llm_config.get("use_mock", False)
        self.model_name = self.llm_config.get("model", "gemini-2.0-flash-lite")
        self.max_tokens = self.llm_config.get("max_tokens", 1000)
        self.temperature = self.llm_config.get("temperature", 0.3)
        
        # NLP settings
        self.use_nlp_preprocessing = config.get("use_nlp_preprocessing", True)
        self.nlp_entity_boost = config.get("nlp_entity_boost", True)
        
        # Processing settings
        self.min_confidence_threshold = config.get("min_confidence", 0.5)
        self.enable_caching = config.get("enable_caching", True)
        self.batch_size = config.get("batch_size", 5)
        
        # Statistics
        self.stats = {
            "total_reports_processed": 0,
            "total_ttps_extracted": 0,
            "nlp_entities_extracted": 0,
            "nlp_ttp_indicators_found": 0,
            "gemini_ttps_extracted": 0,
            "extraction_errors": 0,
            "gemini_api_calls": 0,
            "avg_confidence_score": 0.0,
            "high_confidence_ttps": 0,
            "processing_time_ms": 0,
            "nlp_processing_time_ms": 0,
            "llm_processing_time_ms": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "last_extraction_time": None
        }
        
        # Status tracking
        self._status_history = deque(maxlen=50)
        self._can_execute = True
        self._is_paused = False
        self._extraction_cache = {}
        
        self.logger = get_agent_logger(f"extractor_{name}", self.id)
    
    async def start(self) -> None:
        """Start the extractor agent"""
        await super().start()
        
        try:
            # Initialize Gemini client
            await self._initialize_llm()
            self._can_execute = True
            
            self.logger.info(
                "Extractor Agent started (Hybrid NLP+Gemini)",
                model=self.model_name,
                use_mock=self.use_mock_llm,
                nlp_enabled=self.use_nlp_preprocessing
            )
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise ExtractorException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, 
                                    input_data: Dict[str, Any],
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute TTP extraction with hybrid approach and memory context"""
        if not self._can_execute:
            return {
                "agent_id": self.id,
                "status": "paused",
                "message": "Agent is paused",
                "timestamp": self.get_timestamp()
            }
        
        start_time = datetime.utcnow()
        
        try:
            self.set_status(AgentStatus.RUNNING)
            self.update_last_activity()
            
            # Parse input
            reports = input_data.get("normalized_reports", [])
            if not reports and "report_id" in input_data:
                reports = [input_data]
            
            if not reports:
                return {
                    "agent_id": self.id,
                    "status": "no_data",
                    "message": "No reports to process",
                    "timestamp": self.get_timestamp()
                }
            
            self.logger.info(f"Processing {len(reports)} reports (Hybrid NLP+Gemini)")
            
            # Extract from reports
            extraction_results = []
            
            for report in reports:
                try:
                    result = await self._extract_from_report_hybrid(report)
                    extraction_results.append(result)
                    self.stats["total_reports_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(
                        f"Failed to extract from {report.get('report_id')}: {str(e)}"
                    )
                    self.stats["extraction_errors"] += 1
                    continue
            
            # Calculate statistics
            total_ttps = sum(len(r.get("extracted_ttps", [])) for r in extraction_results)
            self.stats["total_ttps_extracted"] += total_ttps
            self.stats["last_extraction_time"] = datetime.utcnow().isoformat()
            
            # Calculate confidence statistics
            all_ttps = [
                ttp for result in extraction_results
                for ttp in result.get("extracted_ttps", [])
            ]
            
            if all_ttps:
                confidences = [ttp.get("confidence_score", 0) for ttp in all_ttps]
                self.stats["avg_confidence_score"] = sum(confidences) / len(confidences)
                self.stats["high_confidence_ttps"] += sum(1 for c in confidences if c >= 0.8)
            
            # Processing time
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            result = {
                "agent_id": self.id,
                "status": "success",
                "timestamp": self.get_timestamp(),
                "extraction_summary": {
                    "reports_processed": len(extraction_results),
                    "total_ttps_extracted": total_ttps,
                    "avg_ttps_per_report": total_ttps / len(extraction_results) if extraction_results else 0,
                    "high_confidence_ttps": self.stats["high_confidence_ttps"],
                    "extraction_errors": self.stats["extraction_errors"],
                    "processing_time_ms": processing_time_ms,
                    "gemini_api_calls": self.stats["gemini_api_calls"],
                    "nlp_processing_time_ms": self.stats["nlp_processing_time_ms"],
                    "llm_processing_time_ms": self.stats["llm_processing_time_ms"]
                },
                "extraction_results": extraction_results,
                "statistics": self.stats.copy()
            }
            
            self.set_status(AgentStatus.IDLE)
            self.logger.info(
                "Extraction completed",
                reports=len(extraction_results),
                ttps=total_ttps,
                time_ms=processing_time_ms
            )
            
            return result
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, str(e))
            self.logger.error(f"Execution failed: {str(e)}")
            raise ExtractorException(f"Execution failed: {str(e)}")
    
    async def _extract_from_report_hybrid(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Hybrid extraction using NLP + Gemini"""
        report_id = report.get("report_id")
        
        # Check cache
        if self.enable_caching and report_id in self._extraction_cache:
            self.stats["cache_hits"] += 1
            return self._extraction_cache[report_id]
        
        self.stats["cache_misses"] += 1
        self.logger.info(f"Hybrid extraction for: {report_id}")
        
        # Step 1: NLP Processing
        nlp_start = datetime.utcnow()
        nlp_results = await self._nlp_processing(report)
        nlp_time = (datetime.utcnow() - nlp_start).total_seconds() * 1000
        self.stats["nlp_processing_time_ms"] += nlp_time
        
        # Step 2: NLP-based TTP Indicators
        nlp_ttp_indicators = nlp_results["ttp_indicators"]
        self.stats["nlp_ttp_indicators_found"] += len(nlp_ttp_indicators)
        self.stats["nlp_entities_extracted"] += (
            len(nlp_results["entities"]["malware"]) +
            len(nlp_results["entities"]["tools"]) +
            len(nlp_results["entities"]["threat_actors"])
        )
        
        # Step 3: LLM Extraction with NLP Context
        llm_start = datetime.utcnow()
        llm_ttps = await self._extract_ttps_with_llm_enhanced(
            report,
            nlp_results
        )
        llm_time = (datetime.utcnow() - llm_start).total_seconds() * 1000
        self.stats["llm_processing_time_ms"] += llm_time
        self.stats["gemini_ttps_extracted"] += len(llm_ttps)
        
        # Step 4: Create TTPs from NLP indicators
        nlp_ttps = self._create_ttps_from_nlp_indicators(nlp_ttp_indicators)
        
        # Step 5: Combine all TTPs
        all_ttps = nlp_ttps + llm_ttps
        
        # Step 6: Map to ATT&CK
        mapped_ttps = await self._map_ttps_to_attack(all_ttps)
        
        # Step 7: Enrich with NLP entity context
        enriched_ttps = self._enrich_ttps_with_entities(mapped_ttps, nlp_results)
        
        # Step 8: Score confidence
        scored_ttps = self._score_ttps(enriched_ttps, report)
        
        # Step 9: Filter by threshold
        filtered_ttps = [
            ttp for ttp in scored_ttps
            if ttp.get("confidence_score", 0) >= self.min_confidence_threshold
        ]
        
        # Step 10: Format for handoff
        formatted_ttps = [
            self._format_ttp_for_handoff(ttp, report)
            for ttp in filtered_ttps
        ]
        
        # Build result
        result = {
            "report_id": report_id,
            "source_report": {
                "title": report.get("title"),
                "source": report.get("source"),
                "confidence": report.get("confidence")
            },
            "extracted_ttps": formatted_ttps,
            "nlp_analysis": nlp_results,
            "metadata": {
                "extraction_timestamp": self.get_timestamp(),
                "extraction_method": "Hybrid-NLP+Gemini",
                "llm_model": self.model_name,
                "total_ttps_found": len(all_ttps),
                "nlp_ttps": len(nlp_ttps),
                "gemini_ttps": len(llm_ttps),
                "ttps_after_filtering": len(filtered_ttps),
                "min_confidence_threshold": self.min_confidence_threshold,
                "nlp_processing_time_ms": nlp_time,
                "llm_processing_time_ms": llm_time
            }
        }
        
        # Cache result
        if self.enable_caching:
            self._extraction_cache[report_id] = result
        
        return result
    
    async def _nlp_processing(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """NLP processing to extract entities and indicators"""
        if not self.use_nlp_preprocessing:
            return self._empty_nlp_results()
        
        description = report.get("description", "")
        
        # Process text
        processed_text = self.nlp_pipeline.process(description)
        
        # Extract entities
        extracted_entities = self.entity_extractor.extract(description)
        
        # Extract TTP indicators
        ttp_indicators = self.nlp_pipeline.extract_ttp_indicators(description)
        
        # Build NLP results
        results = {
            "processed_text": {
                "cleaned_text": processed_text.cleaned_text,
                "sentences": processed_text.sentences,
                "technical_terms": processed_text.technical_terms,
                "file_paths": processed_text.file_paths,
                "registry_keys": processed_text.registry_keys,
                "commands": processed_text.commands,
                "network_artifacts": processed_text.network_artifacts,
                "security_keywords": processed_text.security_keywords
            },
            "entities": {
                "malware": extracted_entities.malware_families,
                "tools": extracted_entities.tools,
                "threat_actors": extracted_entities.threat_actors,
                "attack_techniques": extracted_entities.attack_techniques,
                "ips": extracted_entities.ip_addresses[:10],
                "domains": extracted_entities.domains[:10],
                "hashes": {k: v[:5] for k, v in extracted_entities.file_hashes.items()},
                "file_names": extracted_entities.file_names[:10]
            },
            "ttp_indicators": ttp_indicators,
            "context": self.nlp_pipeline.enhance_llm_prompt(processed_text)
        }
        
        return results
    
    def _empty_nlp_results(self) -> Dict[str, Any]:
        """Return empty NLP results when NLP is disabled"""
        return {
            "processed_text": {},
            "entities": {
                "malware": [],
                "tools": [],
                "threat_actors": [],
                "attack_techniques": [],
                "ips": [],
                "domains": [],
                "hashes": {},
                "file_names": []
            },
            "ttp_indicators": {},
            "context": ""
        }
    
    def _create_ttps_from_nlp_indicators(self, indicators: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Create TTP entries from NLP indicators"""
        ttps = []
        
        for tactic, techniques in indicators.items():
            for technique in techniques:
                ttp = {
                    "technique_name": technique,
                    "tactic": tactic.replace("_", " ").title(),
                    "description": f"Detected {technique} activity via NLP pattern matching",
                    "indicators": [],
                    "tools": [],
                    "extraction_method": "nlp",
                    "source": "nlp_indicators"
                }
                ttps.append(ttp)
        
        return ttps
    
    async def _extract_ttps_with_llm_enhanced(
        self,
        report: Dict[str, Any],
        nlp_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract TTPs using Gemini with NLP-enhanced prompt"""
        try:
            # Build enhanced prompt with NLP context
            prompt = self._build_enhanced_extraction_prompt(report, nlp_results)
            
            # Call Gemini
            response = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            self.stats["gemini_api_calls"] += 1
            
            # Parse response
            ttps = self._parse_gemini_response(response)
            
            # Mark as LLM-extracted
            for ttp in ttps:
                ttp["extraction_method"] = "gemini_llm"
            
            return ttps
            
        except Exception as e:
            self.logger.error(f"Gemini extraction failed: {str(e)}")
            return []
    
    def _build_enhanced_extraction_prompt(
        self,
        report: Dict[str, Any],
        nlp_results: Dict[str, Any]
    ) -> str:
        """Build Gemini prompt enhanced with NLP results"""
        
        title = report.get("title", "Unknown")
        description = report.get("description", "")
        threat_actors = report.get("threat_actors", [])
        malware = report.get("malware_families", [])
        iocs = report.get("indicators", [])
        
        # Get NLP context
        nlp_context = nlp_results.get("context", "")
        entities = nlp_results.get("entities", {})
        ttp_indicators = nlp_results.get("ttp_indicators", {})
        processed = nlp_results.get("processed_text", {})
        
        # Build IOC summary
        ioc_summary = self._summarize_iocs(iocs)
        
        # Build NLP context summary
        nlp_summary = self._build_nlp_summary(entities, processed, ttp_indicators)
        
        prompt = f"""You are a cybersecurity expert specializing in MITRE ATT&CK framework.
Your task is to extract ALL Tactics, Techniques, and Procedures (TTPs) from the CTI report.

**Report Title:** {title}

**Threat Actors:** {', '.join(threat_actors) if threat_actors else 'Unknown'}
**Malware Families:** {', '.join(malware) if malware else 'None'}

**NLP Pre-Analysis Results:**
{nlp_summary}

**Key IOCs:**
{ioc_summary}

**Technical Indicators from NLP:**
{nlp_context}

**Full Report Description:**
{description}

---

**TASK:** Extract ALL TTPs mentioned or implied. For each TTP provide:

1. **technique_name** - Specific MITRE ATT&CK technique name
2. **tactic** - MITRE ATT&CK tactic
3. **description** - HOW the technique is used in THIS attack
4. **indicators** - Specific IOCs, commands, registry keys
5. **tools** - Tools/malware used
6. **confidence** - Your confidence (0.1-1.0)

**IMPORTANT:**
- Use NLP analysis above to guide extraction
- Extract ALL techniques, even if only implied
- Link to entities found by NLP (malware, tools, actors)
- Focus on what's actually stated
- Return ONLY valid JSON

**OUTPUT (JSON only):**
[
  {{
    "technique_name": "technique_name",
    "tactic": "tactic_name",
    "description": "how used in this attack",
    "indicators": ["ioc1", "ioc2"],
    "tools": ["tool1"],
    "confidence": 0.9
  }}
]"""

        return prompt
    
    def _build_nlp_summary(
        self, 
        entities: Dict[str, List], 
        processed: Dict[str, Any],
        ttp_indicators: Dict[str, List]
    ) -> str:
        """Build summary of NLP findings"""
        parts = []
        
        if entities.get("malware"):
            parts.append(f"**Malware Found:** {', '.join(entities['malware'][:5])}")
        
        if entities.get("tools"):
            parts.append(f"**Tools Detected:** {', '.join(entities['tools'][:5])}")
        
        if entities.get("threat_actors"):
            parts.append(f"**Threat Actors:** {', '.join(entities['threat_actors'])}")
        
        if processed.get("commands"):
            parts.append(f"**Commands:** {len(processed['commands'])} commands found")
        
        if processed.get("file_paths"):
            parts.append(f"**File Paths:** {', '.join(processed['file_paths'][:3])}")
        
        if processed.get("registry_keys"):
            parts.append(f"**Registry Keys:** {', '.join(processed['registry_keys'][:3])}")
        
        if ttp_indicators:
            tactics = list(ttp_indicators.keys())
            parts.append(f"**Tactics Indicated:** {', '.join(tactics[:5])}")
        
        return "\n".join(parts) if parts else "No NLP findings"
    
    def _summarize_iocs(self, iocs: List[Dict]) -> str:
        """Summarize IOCs for prompt"""
        if not iocs:
            return "No IOCs"
        
        summary_parts = []
        ioc_by_type = {}
        
        for ioc in iocs[:20]:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in ioc_by_type:
                ioc_by_type[ioc_type] = []
            ioc_by_type[ioc_type].append(ioc.get("value", ""))
        
        for ioc_type, values in ioc_by_type.items():
            summary_parts.append(f"- {ioc_type}: {', '.join(values[:3])}")
        
        return "\n".join(summary_parts)
    
    def _parse_gemini_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse Gemini JSON response"""
        try:
            response = response.strip()
            
            # Remove markdown
            if response.startswith("```"):
                lines = response.split("\n")
                response = "\n".join(lines[1:-1])
                if response.startswith("json"):
                    response = "\n".join(response.split("\n")[1:])
            
            ttps = json.loads(response)
            
            if not isinstance(ttps, list):
                ttps = [ttps]
            
            validated = []
            for ttp in ttps:
                if isinstance(ttp, dict) and "technique_name" in ttp:
                    ttp.setdefault("tactic", "Unknown")
                    ttp.setdefault("description", "")
                    ttp.setdefault("indicators", [])
                    ttp.setdefault("tools", [])
                    ttp.setdefault("confidence", 0.5)
                    validated.append(ttp)
            
            return validated
            
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse Gemini response")
            return []
    
    def _enrich_ttps_with_entities(
        self,
        ttps: List[Dict],
        nlp_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enrich TTPs with NLP entity context, tools, and IOCs"""
        
        entities = nlp_results.get("entities", {})
        text = nlp_results.get("processed_text", {}).get("cleaned_text", "")
        
        for ttp in ttps:
            # Add related entities
            ttp["related_entities"] = {
                "malware": entities.get("malware", []),
                "tools": entities.get("tools", []),
                "threat_actors": entities.get("threat_actors", [])
            }
            
            # Extract tools using improved tool extractor
            technique_name = ttp.get("technique_name", "")
            tools_result = self.tools_ioc_extractor.extract_tools(text, entities)
            ttp["tools"] = tools_result.get("all_tools", [])
            ttp["tools_by_category"] = tools_result.get("by_category", {})
            
            # Extract IOCs
            iocs = self.tools_ioc_extractor.extract_iocs(text)
            ttp["extracted_iocs"] = iocs
            
            # Correlate IOCs with TTPs
            ttp = self.tools_ioc_extractor.correlate_iocs_with_ttps([ttp], iocs, text)[0]
            
            # Extract full context for description
            context = self.contextual_extractor.extract_full_context(
                text, technique_name
            )
            ttp["extraction_context"] = context
            
            # Enhance short descriptions
            if len(ttp.get("description", "").split()) < 15:
                enhanced = self.contextual_extractor.calculate_description_enhancement(
                    ttp.get("description", ""),
                    context,
                    technique_name
                )
                ttp["description_enhanced"] = enhanced.get("enhanced", ttp.get("description", ""))
                ttp["context_confidence_boost"] = context.get("confidence_modifier", 0)
        
        return ttps
    
    async def _map_ttps_to_attack(self, ttps: List[Dict]) -> List[Dict[str, Any]]:
        """Map TTPs to MITRE ATT&CK"""
        mapped_ttps = []
        
        for ttp in ttps:
            try:
                attack_mapping = self.attack_mapper.map_technique(
                    technique_name=ttp.get("technique_name", ""),
                    tactic=ttp.get("tactic", ""),
                    description=ttp.get("description", "")
                )
                
                if attack_mapping:
                    ttp["attack_id"] = attack_mapping["technique_id"]
                    ttp["attack_name"] = attack_mapping["technique_name"]
                    ttp["subtechnique"] = attack_mapping.get("subtechnique", False)
                    ttp["mapping_source"] = "attack_mapper"
                else:
                    ttp["attack_id"] = "UNMAPPED"
                    ttp["mapping_source"] = "none"
                
                mapped_ttps.append(ttp)
                
            except Exception as e:
                self.logger.warning(f"Mapping error: {str(e)}")
                continue
        
        return mapped_ttps
    
    def _score_ttps(self, ttps: List[Dict], report: Dict) -> List[Dict[str, Any]]:
        """Calculate confidence scores using enhanced scoring"""
        scored_ttps = []
        text = report.get("description", "")
        
        # Get NLP entities if available
        nlp_entities = {}
        
        for ttp in ttps:
            try:
                # Use enhanced confidence scorer
                scoring_result = self.enhanced_scorer.calculate_score(
                    ttp=ttp,
                    report=report,
                    text=text,
                    nlp_entities=nlp_entities
                )
                
                ttp["confidence_score"] = scoring_result["score"]
                ttp["confidence_level"] = scoring_result["level"]
                ttp["confidence_breakdown"] = scoring_result["breakdown"]
                ttp["confidence_emoji"] = scoring_result["emoji"]
                
                scored_ttps.append(ttp)
                
            except Exception as e:
                self.logger.warning(f"Enhanced scoring failed, using fallback: {str(e)}")
                
                # Fallback to basic scoring
                base_score = ttp.get("confidence", 0.5)
                
                method_bonus = 0.1 if ttp.get("extraction_method") == "gemini_llm" else 0.05
                mapping_bonus = 0.1 if ttp.get("attack_id") != "UNMAPPED" else 0
                entity_bonus = 0.05 if ttp.get("related_entities", {}).get("malware") else 0
                
                final_score = min(base_score + method_bonus + mapping_bonus + entity_bonus, 1.0)
                
                ttp["confidence_score"] = round(final_score, 3)
                ttp["confidence_level"] = "medium"
                ttp["confidence_breakdown"] = {
                    "base": base_score,
                    "method_bonus": method_bonus,
                    "mapping_bonus": mapping_bonus,
                    "entity_bonus": entity_bonus
                }
                
                scored_ttps.append(ttp)
        
        scored_ttps.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)
        return scored_ttps
    
    def _format_ttp_for_handoff(self, ttp: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
        """Format TTP for handoff to RuleGen with validation and enhancement"""
        # Validate and fix Attack ID
        original_attack_id = ttp.get("attack_id", "")
        attack_id_fix = self.attack_id_validator.validate_attack_id(original_attack_id)
        validated_attack_id = attack_id_fix.validated_id if attack_id_fix.is_valid else original_attack_id
        
        # Extract indicators from context
        context_text = ttp.get("description", "") or ttp.get("evidence_text", "")
        indicators = self.indicator_extractor.extract_indicators(context_text)
        
        threat_actors = report.get("threat_actors", [])
        primary_threat_actor = threat_actors[0] if threat_actors else None
        
        context = {
            "threat_actor": primary_threat_actor,
            "malware_used": report.get("malware_families", []),
            "campaign": report.get("title", "")
        }
        
        formatted = {
            "ttp_id": str(uuid.uuid4()),
            "report_id": report.get("report_id"),
            "technique_name": ttp.get("technique_name"),
            "attack_id": validated_attack_id,
            "attack_id_validated": attack_id_fix.is_valid,
            "attack_id_confidence": attack_id_fix.confidence,
            "tactic": ttp.get("tactic"),
            "description": ttp.get("description_enhanced", ttp.get("description")),
            "description_original": ttp.get("description"),
            "confidence_score": ttp.get("confidence_score"),
            "confidence_level": ttp.get("confidence_level"),
            "confidence_breakdown": ttp.get("confidence_breakdown", {}),
            "evidence_text": ttp.get("description", ""),
            "indicators_supporting": ttp.get("indicators", []),
            "extracted_indicators": indicators,
            "indicator_score": self.indicator_extractor.calculate_indicator_score(indicators),
            "context": context,
            "extraction_method": ttp.get("extraction_method", "hybrid"),
            "extraction_source": ttp.get("source", "unknown"),
            "mapped_by": f"{self.model_name}_nlp_hybrid",
            "extracted_timestamp": self.get_timestamp(),
            "tools": ttp.get("tools", []),
            "tools_by_category": ttp.get("tools_by_category", {}),
            "extracted_iocs": ttp.get("extracted_iocs", {}),
            "related_entities": ttp.get("related_entities", {}),
            "correlated_iocs": ttp.get("correlated_iocs", {}),
            "extraction_context": ttp.get("extraction_context", {}),
            "context_confidence_boost": ttp.get("context_confidence_boost", 0),
            "subtechnique": ttp.get("subtechnique", False),
            "mapping_source": ttp.get("mapping_source", "unknown")
        }
        
        return formatted
    
    async def _initialize_llm(self) -> None:
        """Initialize Gemini client"""
        try:
            self.llm_client = create_llm_client(
                self.llm_config,
                use_mock=self.use_mock_llm
            )
            
            if hasattr(self.llm_client, "test_connection"):
                connection_ok = await self.llm_client.test_connection()
                if not connection_ok:
                    raise LLMException("Failed to connect to Gemini API")
            
            self.logger.info("Gemini client initialized successfully")
            
        except Exception as e:
            raise LLMException(f"Gemini initialization failed: {str(e)}")
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        if not isinstance(data, dict):
            return False
        
        if "normalized_reports" in data:
            reports = data["normalized_reports"]
            if not isinstance(reports, list):
                return False
            
            for report in reports:
                if not self._validate_report(report):
                    return False
        
        elif "report_id" in data:
            if not self._validate_report(data):
                return False
        
        return True
    
    def _validate_report(self, report: Dict[str, Any]) -> bool:
        """Validate individual report"""
        required_fields = ["report_id", "description"]
        
        for field in required_fields:
            if field not in report:
                self.logger.warning(f"Missing field: {field}")
                return False
        
        if not report.get("description"):
            self.logger.warning(f"Empty description in {report.get('report_id')}")
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
    
    def clear_cache(self) -> int:
        """Clear extraction cache"""
        count = len(self._extraction_cache)
        self._extraction_cache.clear()
        return count
    
    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check"""
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
                "gemini_api_calls": self.stats["gemini_api_calls"],
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
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.stats["cache_hits"] + self.stats["cache_misses"]
        if total == 0:
            return 0.0
        return round((self.stats["cache_hits"] / total) * 100, 2)
    
    async def shutdown(self):
        """Shutdown agent"""
        try:
            self.set_status(AgentStatus.STOPPED)
            
            if self.llm_client and hasattr(self.llm_client, 'close'):
                await self.llm_client.close()
            
            self.logger.info("ExtractorAgent shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown error: {str(e)}")