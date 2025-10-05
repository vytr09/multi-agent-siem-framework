# """
# Enhanced Extractor Agent - Extracts TTPs from CTI reports using LLM and NLP.

# New features:
# - Batch processing optimization
# - Caching for performance
# - Status history tracking
# - Health monitoring
# - Pause/Resume capability
# - Advanced statistics
# """

# import asyncio
# from typing import Dict, Any, List, Optional
# from datetime import datetime
# import json
# from collections import deque

# from agents.base.agent import BaseAgent, AgentStatus
# from agents.base.exceptions import (
#     ExtractorException, 
#     LLMException, 
#     ATTACKMappingException,
#     ValidationException
# )
# from agents.extractor.llm.openai_client import OpenAIClient, MockLLMClient, create_llm_client
# from agents.extractor.mappers.attack_mapper import ATTACKMapper
# from agents.extractor.mappers.confidence_scorer import ConfidenceScorer
# from core.logging import get_agent_logger


# class ExtractorAgent(BaseAgent):
#     """
#     Enhanced TTP Extraction Agent with advanced features.
    
#     Processes CTI reports to extract structured TTPs with:
#     - High accuracy LLM extraction
#     - ATT&CK framework mapping
#     - Confidence scoring
#     - Performance optimization
#     - Health monitoring
#     """
    
#     def __init__(self, name: str, config: Dict[str, Any]):
#         """
#         Initialize the Extractor Agent.
        
#         Args:
#             name: Agent name
#             config: Configuration dictionary
#         """
#         super().__init__(name, config)
        
#         # Initialize components
#         self.llm_client = None
#         self.attack_mapper = ATTACKMapper()
#         self.confidence_scorer = ConfidenceScorer()
        
#         # Configuration
#         self.llm_config = config.get("llm", {})
#         self.use_mock_llm = self.llm_config.get("use_mock", True)
#         self.model_name = self.llm_config.get("model", "gpt-4")
#         self.max_tokens = self.llm_config.get("max_tokens", 2000)
#         self.temperature = self.llm_config.get("temperature", 0.3)
        
#         # Processing settings
#         self.batch_size = config.get("batch_size", 10)
#         self.min_confidence_threshold = config.get("min_confidence", 0.5)
#         self.enable_caching = config.get("enable_caching", True)
        
#         # Statistics with enhanced metrics
#         self.stats = {
#             "total_reports_processed": 0,
#             "total_ttps_extracted": 0,
#             "total_attack_mappings": 0,
#             "extraction_errors": 0,
#             "mapping_errors": 0,
#             "validation_errors": 0,
#             "last_extraction_time": None,
#             "avg_confidence_score": 0.0,
#             "high_confidence_ttps": 0,
#             "low_confidence_ttps": 0,
#             "avg_processing_time_ms": 0,
#             "fastest_processing_ms": float('inf'),
#             "slowest_processing_ms": 0,
#             "total_processing_time_ms": 0,
#             "cache_hits": 0,
#             "cache_misses": 0
#         }
        
#         # Status tracking
#         self._status_history = deque(maxlen=50)
#         self._can_execute = True
#         self._is_paused = False
        
#         # Simple in-memory cache
#         self._extraction_cache = {}
        
#         # Initialize logger
#         self.logger = get_agent_logger(f"extractor_{name}", self.id)
    
#     async def start(self) -> None:
#         """Start the extractor agent with initialization"""
#         await super().start()
        
#         try:
#             # Initialize LLM client
#             await self._initialize_llm()
            
#             # Load ATT&CK data if needed
#             # self.attack_mapper.load_attack_data()  # Future enhancement
            
#             self._can_execute = True
            
#             self.logger.info("Extractor Agent started successfully",
#                            llm_model=self.model_name,
#                            mock_mode=self.use_mock_llm,
#                            caching=self.enable_caching)
            
#         except Exception as e:
#             self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
#             raise ExtractorException(f"Failed to start Extractor Agent: {str(e)}")
    
#     async def pause(self) -> None:
#         """Pause the agent"""
#         self._is_paused = True
#         self._can_execute = False
#         self.set_status(AgentStatus.IDLE, "Agent paused")
#         self.logger.info("Agent paused")
    
#     async def resume(self) -> None:
#         """Resume the agent"""
#         self._is_paused = False
#         self._can_execute = True
#         self.set_status(AgentStatus.IDLE, "Agent resumed")
#         self.logger.info("Agent resumed")
    
#     async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Execute TTP extraction on CTI reports.
        
#         Args:
#             input_data: Dictionary containing normalized CTI reports
            
#         Returns:
#             Extraction results with TTPs and mappings
#         """
#         if not self._can_execute:
#             return {
#                 "agent_id": self.id,
#                 "status": "paused",
#                 "message": "Agent is paused",
#                 "timestamp": self.get_timestamp()
#             }
        
#         start_time = datetime.utcnow()
        
#         try:
#             self.set_status(AgentStatus.RUNNING)
#             self.update_last_activity()
            
#             # Parse input
#             reports = input_data.get("normalized_reports", [])
#             if not reports:
#                 # Check if single report provided
#                 if "report_id" in input_data:
#                     reports = [input_data]
            
#             if not reports:
#                 return {
#                     "agent_id": self.id,
#                     "status": "no_data",
#                     "message": "No reports to process",
#                     "timestamp": self.get_timestamp()
#                 }
            
#             self.logger.info(f"Processing {len(reports)} CTI reports for TTP extraction")
            
#             # Extract TTPs from all reports
#             extraction_results = []
            
#             for report in reports:
#                 try:
#                     result = await self._extract_from_report(report)
#                     extraction_results.append(result)
#                     self.stats["total_reports_processed"] += 1
                    
#                 except Exception as e:
#                     self.logger.error(f"Failed to extract from report {report.get('report_id')}: {str(e)}")
#                     self.stats["extraction_errors"] += 1
#                     continue
            
#             # Calculate statistics
#             total_ttps = sum(len(r.get("extracted_ttps", [])) for r in extraction_results)
#             self.stats["total_ttps_extracted"] += total_ttps
#             self.stats["last_extraction_time"] = datetime.utcnow().isoformat()
            
#             # Update confidence statistics
#             all_ttps = [
#                 ttp for result in extraction_results 
#                 for ttp in result.get("extracted_ttps", [])
#             ]
            
#             if all_ttps:
#                 confidences = [ttp.get("confidence_score", 0) for ttp in all_ttps]
#                 self.stats["avg_confidence_score"] = sum(confidences) / len(confidences)
#                 self.stats["high_confidence_ttps"] += sum(1 for c in confidences if c >= 0.8)
#                 self.stats["low_confidence_ttps"] += sum(1 for c in confidences if c < 0.5)
            
#             # Update processing time statistics
#             processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
#             self._update_processing_stats(processing_time_ms)
            
#             # Prepare results
#             result = {
#                 "agent_id": self.id,
#                 "status": "success",
#                 "timestamp": self.get_timestamp(),
#                 "extraction_summary": {
#                     "reports_processed": len(extraction_results),
#                     "total_ttps_extracted": total_ttps,
#                     "avg_ttps_per_report": total_ttps / len(extraction_results) if extraction_results else 0,
#                     "extraction_errors": self.stats["extraction_errors"],
#                     "processing_time_ms": processing_time_ms
#                 },
#                 "extraction_results": extraction_results,
#                 "statistics": self.stats.copy()
#             }
            
#             self.set_status(AgentStatus.IDLE)
            
#             self.logger.info("TTP extraction completed",
#                            reports=len(extraction_results),
#                            ttps=total_ttps,
#                            time_ms=processing_time_ms)
            
#             return result
            
#         except Exception as e:
#             self.set_status(AgentStatus.ERROR, str(e))
#             self.logger.error(f"Extraction execution failed: {str(e)}")
#             raise ExtractorException(f"Extraction execution failed: {str(e)}")
    
#     def validate_input(self, data: Dict[str, Any]) -> bool:
#         """
#         Validate input data for extraction.
        
#         Args:
#             data: Input data to validate
            
#         Returns:
#             True if valid, False otherwise
#         """
#         if not isinstance(data, dict):
#             return False
        
#         # Check for reports or single report
#         if "normalized_reports" in data:
#             reports = data["normalized_reports"]
#             if not isinstance(reports, list):
#                 return False
            
#             # Validate each report has required fields
#             for report in reports:
#                 if not self._validate_report(report):
#                     return False
        
#         elif "report_id" in data:
#             # Single report validation
#             if not self._validate_report(data):
#                 return False
#         else:
#             # No reports provided - still valid, will return empty result
#             pass
        
#         return True
    
#     def _validate_report(self, report: Dict[str, Any]) -> bool:
#         """Validate individual report structure"""
#         required_fields = ["report_id", "description"]
        
#         for field in required_fields:
#             if field not in report:
#                 self.logger.warning(f"Report missing required field: {field}")
#                 self.stats["validation_errors"] += 1
#                 return False
        
#         if not report.get("description"):
#             self.logger.warning(f"Report {report['report_id']} has empty description")
#             self.stats["validation_errors"] += 1
#             return False
        
#         return True
    
#     async def _initialize_llm(self) -> None:
#         """Initialize LLM client"""
#         try:
#             self.llm_client = create_llm_client(
#                 self.llm_config,
#                 use_mock=self.use_mock_llm
#             )
            
#             # Test LLM connection
#             if hasattr(self.llm_client, "test_connection"):
#                 connection_ok = await self.llm_client.test_connection()
#                 if not connection_ok:
#                     raise LLMException("Failed to connect to LLM service")
            
#             self.logger.info("LLM client initialized",
#                            model=self.model_name,
#                            mock=self.use_mock_llm)
            
#         except Exception as e:
#             raise LLMException(f"LLM initialization failed: {str(e)}")
    
#     async def _extract_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
#         """
#         Extract TTPs from a single CTI report with caching.
        
#         Args:
#             report: Normalized CTI report
            
#         Returns:
#             Extraction result with TTPs and mappings
#         """
#         report_id = report.get("report_id")
        
#         # Check cache
#         if self.enable_caching and report_id in self._extraction_cache:
#             self.stats["cache_hits"] += 1
#             self.logger.debug(f"Cache hit for report: {report_id}")
#             return self._extraction_cache[report_id]
        
#         self.stats["cache_misses"] += 1
#         self.logger.info(f"Extracting TTPs from report: {report_id}")
        
#         # Step 1: Extract TTPs using LLM
#         raw_ttps = await self._extract_ttps_with_llm(report)
        
#         # Step 2: Map to MITRE ATT&CK
#         mapped_ttps = await self._map_ttps_to_attack(raw_ttps, report)
        
#         # Step 3: Calculate confidence scores
#         scored_ttps = self._score_ttps(mapped_ttps, report)
        
#         # Step 4: Filter by confidence threshold
#         filtered_ttps = [
#             ttp for ttp in scored_ttps 
#             if ttp.get("confidence_score", 0) >= self.min_confidence_threshold
#         ]
        
#         # Step 5: Extract attack chain
#         attack_chain = self._extract_attack_chain(filtered_ttps)
        
#         self.logger.info(f"Extracted {len(filtered_ttps)} TTPs from report {report_id}")
        
#         result = {
#             "report_id": report_id,
#             "source_report": {
#                 "title": report.get("title"),
#                 "source": report.get("source"),
#                 "confidence": report.get("confidence")
#             },
#             "extracted_ttps": filtered_ttps,
#             "attack_chain": attack_chain,
#             "metadata": {
#                 "extraction_timestamp": self.get_timestamp(),
#                 "llm_model": self.model_name,
#                 "total_ttps_found": len(raw_ttps),
#                 "ttps_after_filtering": len(filtered_ttps),
#                 "min_confidence_threshold": self.min_confidence_threshold
#             }
#         }
        
#         # Cache result
#         if self.enable_caching:
#             self._extraction_cache[report_id] = result
        
#         return result
    
#     async def _extract_ttps_with_llm(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
#         """
#         Use LLM to extract TTPs from report.
        
#         Args:
#             report: CTI report
            
#         Returns:
#             List of extracted TTPs
#         """
#         try:
#             # Build extraction prompt
#             prompt = self._build_extraction_prompt(report)
            
#             # Call LLM
#             response = await self.llm_client.generate(
#                 prompt=prompt,
#                 max_tokens=self.max_tokens,
#                 temperature=self.temperature
#             )
            
#             # Parse LLM response
#             ttps = self._parse_llm_response(response)
            
#             self.logger.info(f"LLM extracted {len(ttps)} TTPs from report")
            
#             return ttps
            
#         except Exception as e:
#             self.logger.error(f"LLM extraction failed: {str(e)}")
#             raise LLMException(f"TTP extraction failed: {str(e)}")
    
#     def _build_extraction_prompt(self, report: Dict[str, Any]) -> str:
#         """Build prompt for LLM extraction"""
        
#         title = report.get("title", "Unknown")
#         description = report.get("description", "")
#         indicators = report.get("indicators", [])
#         threat_actors = report.get("threat_actors", [])
#         malware_families = report.get("malware_families", [])
        
#         # Build indicators text
#         indicators_text = "None"
#         if indicators:
#             indicator_list = [
#                 f"- {ind.get('type', 'unknown')}: {ind.get('value', 'N/A')}"
#                 for ind in indicators[:15]
#             ]
#             indicators_text = "\n".join(indicator_list)
        
#         # Build context
#         context_parts = []
#         if threat_actors:
#             context_parts.append(f"Threat Actors: {', '.join(threat_actors)}")
#         if malware_families:
#             context_parts.append(f"Malware: {', '.join(malware_families)}")
        
#         context = "\n".join(context_parts) if context_parts else "No additional context"
        
#         prompt = f"""You are a cybersecurity threat intelligence analyst. Extract ALL Tactics, Techniques, and Procedures (TTPs) from this threat intelligence report.

# Report Title: {title}

# Context:
# {context}

# Report Description:
# {description}

# Indicators of Compromise:
# {indicators_text}

# TASK: Extract ALL TTPs mentioned or implied in this report. For each TTP, provide:
# 1. technique_name: Clear, specific name of the technique
# 2. tactic: MITRE ATT&CK tactic (e.g., Initial Access, Execution, Persistence)
# 3. description: How this technique is used in THIS specific attack
# 4. indicators: List of specific IOCs or patterns related to this technique
# 5. tools: Tools or malware used for this technique

# IMPORTANT: 
# - Extract ALL techniques mentioned, even if only implied
# - Be specific about HOW each technique is used
# - Map to the appropriate MITRE ATT&CK tactic
# - Include technical details from the report

# Return ONLY a valid JSON array with no additional text:
# [
#   {{
#     "technique_name": "Spearphishing Attachment",
#     "tactic": "Initial Access",
#     "description": "Attackers sent emails with malicious Office documents containing macros",
#     "indicators": ["malicious.doc", "macro execution"],
#     "tools": ["Emotet", "PowerShell"]
#   }}
# ]"""

#         return prompt
    
#     def _parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
#         """Parse LLM JSON response"""
#         try:
#             # Clean response
#             response = response.strip()
            
#             # Remove markdown code blocks if present
#             if response.startswith('```'):
#                 lines = response.split('\n')
#                 response = '\n'.join(lines[1:-1])
#                 if response.startswith('json'):
#                     response = '\n'.join(response.split('\n')[1:])
            
#             # Parse JSON
#             ttps = json.loads(response)
            
#             if not isinstance(ttps, list):
#                 ttps = [ttps]
            
#             # Validate TTP structure
#             validated_ttps = []
#             for ttp in ttps:
#                 if isinstance(ttp, dict) and "technique_name" in ttp:
#                     validated_ttps.append(ttp)
            
#             return validated_ttps
            
#         except json.JSONDecodeError as e:
#             self.logger.warning(f"Failed to parse LLM response as JSON: {str(e)}")
#             return []
#         except Exception as e:
#             self.logger.error(f"Error parsing LLM response: {str(e)}")
#             return []
    
#     async def _map_ttps_to_attack(self, ttps: List[Dict], report: Dict) -> List[Dict[str, Any]]:
#         """Map extracted TTPs to MITRE ATT&CK framework"""
#         mapped_ttps = []
        
#         for ttp in ttps:
#             try:
#                 attack_mapping = self.attack_mapper.map_technique(
#                     technique_name=ttp.get("technique_name", ""),
#                     tactic=ttp.get("tactic", ""),
#                     description=ttp.get("description", "")
#                 )
                
#                 if attack_mapping:
#                     ttp["attack_id"] = attack_mapping["technique_id"]
#                     ttp["attack_name"] = attack_mapping["technique_name"]
#                     ttp["tactic"] = attack_mapping["tactic"]
#                     ttp["subtechnique"] = attack_mapping.get("subtechnique", False)
#                     ttp["mapping_source"] = "attack_mapper"
                    
#                     self.stats["total_attack_mappings"] += 1
#                 else:
#                     self.logger.warning(f"Could not map TTP: {ttp.get('technique_name')}")
#                     ttp["attack_id"] = "UNMAPPED"
#                     ttp["mapping_source"] = "none"
#                     self.stats["mapping_errors"] += 1
                
#                 mapped_ttps.append(ttp)
                
#             except Exception as e:
#                 self.logger.error(f"Mapping error for TTP {ttp.get('technique_name')}: {str(e)}")
#                 self.stats["mapping_errors"] += 1
#                 continue
        
#         return mapped_ttps
    
#     def _score_ttps(self, ttps: List[Dict], report: Dict) -> List[Dict[str, Any]]:
#         """Calculate confidence scores for TTPs"""
#         scored_ttps = []
        
#         for ttp in ttps:
#             try:
#                 confidence = self.confidence_scorer.calculate_confidence(
#                     ttp=ttp,
#                     report_context=report
#                 )
                
#                 ttp["confidence_score"] = confidence
#                 ttp["confidence_level"] = self.confidence_scorer.get_confidence_level(confidence)
#                 scored_ttps.append(ttp)
                
#             except Exception as e:
#                 self.logger.warning(f"Scoring error for TTP: {str(e)}")
#                 ttp["confidence_score"] = 0.5
#                 ttp["confidence_level"] = "medium"
#                 scored_ttps.append(ttp)
        
#         # Sort by confidence (highest first)
#         scored_ttps.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)
        
#         return scored_ttps
    
#     def _extract_attack_chain(self, ttps: List[Dict]) -> List[str]:
#         """Reconstruct attack chain from TTPs based on tactic order"""
#         # MITRE ATT&CK tactic order
#         tactic_order = {
#             "reconnaissance": 1,
#             "resource development": 2,
#             "initial access": 3,
#             "execution": 4,
#             "persistence": 5,
#             "privilege escalation": 6,
#             "defense evasion": 7,
#             "credential access": 8,
#             "discovery": 9,
#             "lateral movement": 10,
#             "collection": 11,
#             "command and control": 12,
#             "exfiltration": 13,
#             "impact": 14
#         }
        
#         # Sort TTPs by tactic order
#         sorted_ttps = sorted(
#             ttps,
#             key=lambda x: tactic_order.get(x.get("tactic", "").lower(), 99)
#         )
        
#         # Build chain with unique techniques
#         chain = []
#         seen_techniques = set()
        
#         for ttp in sorted_ttps:
#             attack_id = ttp.get("attack_id")
#             if attack_id and attack_id != "UNMAPPED" and attack_id not in seen_techniques:
#                 chain.append(attack_id)
#                 seen_techniques.add(attack_id)
        
#         return chain
    
#     def _update_processing_stats(self, processing_time_ms: float):
#         """Update processing time statistics"""
#         self.stats["total_processing_time_ms"] += processing_time_ms
        
#         # Update average
#         processed_count = self.stats["total_reports_processed"]
#         if processed_count > 0:
#             self.stats["avg_processing_time_ms"] = (
#                 self.stats["total_processing_time_ms"] / processed_count
#             )
        
#         # Update fastest/slowest
#         if processing_time_ms < self.stats["fastest_processing_ms"]:
#             self.stats["fastest_processing_ms"] = processing_time_ms
#         if processing_time_ms > self.stats["slowest_processing_ms"]:
#             self.stats["slowest_processing_ms"] = processing_time_ms
    
#     def set_status(self, status: AgentStatus, message: Optional[str] = None) -> None:
#         """Set agent status with history tracking"""
#         old_status = self.status
#         super().set_status(status, message)
        
#         # Track status history
#         self._status_history.append({
#             "timestamp": self.get_timestamp(),
#             "from": old_status.value,
#             "to": status.value,
#             "message": message
#         })
    
#     def get_status_history(self, limit: int = 10) -> List[Dict[str, Any]]:
#         """Get status change history"""
#         return list(self._status_history)[-limit:]
    
#     def get_status_summary(self) -> Dict[str, Any]:
#         """Get detailed status summary"""
#         return {
#             "status": self.status.value,
#             "is_paused": self._is_paused,
#             "can_execute": self._can_execute,
#             "is_running": self._is_running,
#             "message": f"Agent is {self.status.value}"
#         }
    
#     def clear_cache(self) -> int:
#         """Clear extraction cache"""
#         cached_count = len(self._extraction_cache)
#         self._extraction_cache.clear()
#         self.logger.info(f"Cleared {cached_count} cached extractions")
#         return cached_count
    
#     async def health_check(self) -> Dict[str, Any]:
#         """Enhanced health check with detailed metrics"""
#         base_health = await super().health_check()
        
#         # Calculate health score
#         health_score = 100
        
#         # Deduct for errors
#         error_rate = self.stats["extraction_errors"] / max(self.stats["total_reports_processed"], 1)
#         health_score -= min(error_rate * 50, 30)
        
#         # Deduct for low confidence
#         if self.stats["total_ttps_extracted"] > 0:
#             low_conf_rate = self.stats["low_confidence_ttps"] / self.stats["total_ttps_extracted"]
#             health_score -= min(low_conf_rate * 30, 20)
        
#         # Check if paused
#         if self._is_paused:
#             health_score = 50
        
#         health_score = max(0, health_score)
        
#         # Determine health status
#         if health_score >= 80:
#             health_status = "healthy"
#         elif health_score >= 60:
#             health_status = "degraded"
#         else:
#             health_status = "unhealthy"
        
#         # Enhanced health info
#         base_health.update({
#             "status": {
#                 "current": self.status.value,
#                 "is_paused": self._is_paused,
#                 "can_execute": self._can_execute
#             },
#             "performance": {
#                 "avg_processing_time_ms": self.stats["avg_processing_time_ms"],
#                 "cache_hit_rate": self._calculate_cache_hit_rate()
#             },
#             "quality": {
#                 "avg_confidence": self.stats["avg_confidence_score"],
#                 "high_confidence_ttps": self.stats["high_confidence_ttps"],
#                 "low_confidence_ttps": self.stats["low_confidence_ttps"]
#             },
#             "health": {
#                 "score": round(health_score, 1),
#                 "status": health_status,
#                 "factors": {
#                     "error_rate": round(error_rate * 100, 2),
#                     "success_rate": round((1 - error_rate) * 100, 2)
#                 }
#             },
#             "timing": {
#                 "last_activity": self.last_activity.isoformat() if self.last_activity else None,
#                 "idle_time_seconds": (
#                     (datetime.utcnow() - self.last_activity).total_seconds()
#                     if self.last_activity else 0
#                 )
#             },
#             "flags": {
#                 "can_execute": self._can_execute,
#                 "is_paused": self._is_paused,
#                 "caching_enabled": self.enable_caching
#             }
#         })
        
#         return base_health
    
#     def _calculate_cache_hit_rate(self) -> float:
#         """Calculate cache hit rate"""
#         total_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
#         if total_requests == 0:
#             return 0.0
#         return round((self.stats["cache_hits"] / total_requests) * 100, 2)
    
#     async def get_statistics(self) -> Dict[str, Any]:
#         """Get comprehensive extractor statistics"""
#         return {
#             "agent_info": {
#                 "id": self.id,
#                 "name": self.name,
#                 "status": self.status.value,
#                 "uptime_seconds": (
#                     (datetime.utcnow() - self.start_time).total_seconds()
#                     if self.start_time else 0
#                 ),
#                 "is_paused": self._is_paused
#             },
#             "configuration": {
#                 "llm_model": self.model_name,
#                 "use_mock": self.use_mock_llm,
#                 "min_confidence_threshold": self.min_confidence_threshold,
#                 "batch_size": self.batch_size,
#                 "caching_enabled": self.enable_caching
#             },
#             "statistics": self.stats.copy(),
#             "health": (await self.health_check()).get("health", {})
#         }



"""
Extractor Agent with NLP Integration - Hybrid approach

Uses both NLP preprocessing and LLM for optimal extraction:
1. NLP extracts entities, patterns, IOCs
2. NLP enriches LLM prompt with structured data
3. LLM extracts high-level TTPs with context
4. Combines both for comprehensive results
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from collections import deque

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import ExtractorException, LLMException
from agents.extractor.llm.openai_client import create_llm_client
from agents.extractor.mappers.attack_mapper import ATTACKMapper
from agents.extractor.mappers.confidence_scorer import ConfidenceScorer
from agents.extractor.nlp.pipeline import NLPPipeline
from agents.extractor.nlp.entity_extractor import EntityExtractor
from core.logging import get_agent_logger


class ExtractorAgent(BaseAgent):
    """
    Hybrid TTP Extraction Agent using NLP + LLM.
    
    Processing flow:
    1. NLP Pre-processing: Extract entities and patterns
    2. Enhanced LLM Prompt: Use NLP results to guide LLM
    3. LLM Extraction: Extract TTPs with rich context
    4. Entity Correlation: Link TTPs with IOCs
    5. Confidence Scoring: Multi-factor confidence calculation
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Initialize components
        self.llm_client = None
        self.attack_mapper = ATTACKMapper()
        self.confidence_scorer = ConfidenceScorer()
        self.nlp_pipeline = NLPPipeline()
        self.entity_extractor = EntityExtractor()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.use_mock_llm = self.llm_config.get("use_mock", True)
        self.model_name = self.llm_config.get("model", "gpt-4")
        self.max_tokens = self.llm_config.get("max_tokens", 2000)
        self.temperature = self.llm_config.get("temperature", 0.3)
        
        # NLP settings
        self.use_nlp_preprocessing = config.get("use_nlp_preprocessing", True)
        self.nlp_only_mode = config.get("nlp_only_mode", False)  # Skip LLM, use only NLP
        
        # Processing settings
        self.batch_size = config.get("batch_size", 10)
        self.min_confidence_threshold = config.get("min_confidence", 0.5)
        self.enable_caching = config.get("enable_caching", True)
        
        # Statistics with NLP metrics
        self.stats = {
            "total_reports_processed": 0,
            "total_ttps_extracted": 0,
            "nlp_entities_extracted": 0,
            "llm_ttps_extracted": 0,
            "total_attack_mappings": 0,
            "extraction_errors": 0,
            "mapping_errors": 0,
            "validation_errors": 0,
            "last_extraction_time": None,
            "avg_confidence_score": 0.0,
            "high_confidence_ttps": 0,
            "low_confidence_ttps": 0,
            "avg_processing_time_ms": 0,
            "fastest_processing_ms": float('inf'),
            "slowest_processing_ms": 0,
            "total_processing_time_ms": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "nlp_processing_time_ms": 0,
            "llm_processing_time_ms": 0
        }
        
        # Status tracking
        self._status_history = deque(maxlen=50)
        self._can_execute = True
        self._is_paused = False
        
        # Cache
        self._extraction_cache = {}
        
        self.logger = get_agent_logger(f"extractor_{name}", self.id)
    
    async def start(self) -> None:
        """Start the extractor agent"""
        await super().start()
        
        try:
            # Initialize LLM client (unless NLP-only mode)
            if not self.nlp_only_mode:
                await self._initialize_llm()
            
            self._can_execute = True
            
            mode = "NLP+LLM" if not self.nlp_only_mode else "NLP-only"
            self.logger.info(f"Extractor Agent started in {mode} mode",
                           use_nlp=self.use_nlp_preprocessing,
                           caching=self.enable_caching)
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise ExtractorException(f"Failed to start Extractor Agent: {str(e)}")
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute TTP extraction with NLP preprocessing"""
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
            
            self.logger.info(f"Processing {len(reports)} reports with hybrid NLP+LLM approach")
            
            # Extract from all reports
            extraction_results = []
            
            for report in reports:
                try:
                    result = await self._extract_from_report_hybrid(report)
                    extraction_results.append(result)
                    self.stats["total_reports_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to extract from report {report.get('report_id')}: {str(e)}")
                    self.stats["extraction_errors"] += 1
                    continue
            
            # Calculate statistics
            total_ttps = sum(len(r.get("extracted_ttps", [])) for r in extraction_results)
            self.stats["total_ttps_extracted"] += total_ttps
            self.stats["last_extraction_time"] = datetime.utcnow().isoformat()
            
            # Update confidence statistics
            all_ttps = [
                ttp for result in extraction_results 
                for ttp in result.get("extracted_ttps", [])
            ]
            
            if all_ttps:
                confidences = [ttp.get("confidence_score", 0) for ttp in all_ttps]
                self.stats["avg_confidence_score"] = sum(confidences) / len(confidences)
                self.stats["high_confidence_ttps"] += sum(1 for c in confidences if c >= 0.8)
                self.stats["low_confidence_ttps"] += sum(1 for c in confidences if c < 0.5)
            
            # Update processing time
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._update_processing_stats(processing_time_ms)
            
            # Prepare results
            result = {
                "agent_id": self.id,
                "status": "success",
                "timestamp": self.get_timestamp(),
                "extraction_summary": {
                    "reports_processed": len(extraction_results),
                    "total_ttps_extracted": total_ttps,
                    "avg_ttps_per_report": total_ttps / len(extraction_results) if extraction_results else 0,
                    "extraction_errors": self.stats["extraction_errors"],
                    "processing_time_ms": processing_time_ms,
                    "nlp_processing_time_ms": self.stats["nlp_processing_time_ms"],
                    "llm_processing_time_ms": self.stats["llm_processing_time_ms"]
                },
                "extraction_results": extraction_results,
                "statistics": self.stats.copy()
            }
            
            self.set_status(AgentStatus.IDLE)
            
            self.logger.info("TTP extraction completed",
                           reports=len(extraction_results),
                           ttps=total_ttps,
                           time_ms=processing_time_ms)
            
            return result
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, str(e))
            self.logger.error(f"Extraction execution failed: {str(e)}")
            raise ExtractorException(f"Extraction execution failed: {str(e)}")
    
    async def _extract_from_report_hybrid(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Hybrid extraction using both NLP and LLM.
        
        Flow:
        1. NLP extracts entities and patterns
        2. NLP enriches LLM prompt
        3. LLM extracts TTPs with enhanced context
        4. Combine and correlate results
        """
        report_id = report.get("report_id")
        
        # Check cache
        if self.enable_caching and report_id in self._extraction_cache:
            self.stats["cache_hits"] += 1
            return self._extraction_cache[report_id]
        
        self.stats["cache_misses"] += 1
        self.logger.info(f"Hybrid extraction for report: {report_id}")
        
        description = report.get("description", "")
        
        # Step 1: NLP Pre-processing
        nlp_start = datetime.utcnow()
        processed_text = self.nlp_pipeline.process(description)
        extracted_entities = self.entity_extractor.extract(description)
        ttp_indicators = self.nlp_pipeline.extract_ttp_indicators(description)
        nlp_time = (datetime.utcnow() - nlp_start).total_seconds() * 1000
        self.stats["nlp_processing_time_ms"] += nlp_time
        self.stats["nlp_entities_extracted"] += len(extracted_entities.malware_families) + len(extracted_entities.tools)
        
        # Step 2: Create TTPs from NLP indicators (if NLP-only mode)
        nlp_ttps = []
        if self.nlp_only_mode:
            nlp_ttps = self._create_ttps_from_nlp(ttp_indicators, extracted_entities)
        
        # Step 3: LLM Extraction (enhanced with NLP results)
        llm_ttps = []
        if not self.nlp_only_mode:
            llm_start = datetime.utcnow()
            llm_ttps = await self._extract_ttps_with_llm_enhanced(
                report, processed_text, extracted_entities
            )
            llm_time = (datetime.utcnow() - llm_start).total_seconds() * 1000
            self.stats["llm_processing_time_ms"] += llm_time
            self.stats["llm_ttps_extracted"] += len(llm_ttps)
        
        # Step 4: Combine TTPs
        all_ttps = nlp_ttps + llm_ttps
        
        # Step 5: Map to ATT&CK
        mapped_ttps = await self._map_ttps_to_attack(all_ttps, report)
        
        # Step 6: Enrich with entity correlations
        enriched_ttps = self._enrich_ttps_with_entities(mapped_ttps, extracted_entities)
        
        # Step 7: Score confidence
        scored_ttps = self._score_ttps(enriched_ttps, report)
        
        # Step 8: Filter by threshold
        filtered_ttps = [
            ttp for ttp in scored_ttps 
            if ttp.get("confidence_score", 0) >= self.min_confidence_threshold
        ]
        
        # Step 9: Extract attack chain
        attack_chain = self._extract_attack_chain(filtered_ttps)
        
        self.logger.info(f"Extracted {len(filtered_ttps)} TTPs (NLP: {len(nlp_ttps)}, LLM: {len(llm_ttps)})")
        
        result = {
            "report_id": report_id,
            "source_report": {
                "title": report.get("title"),
                "source": report.get("source"),
                "confidence": report.get("confidence")
            },
            "extracted_ttps": filtered_ttps,
            "attack_chain": attack_chain,
            "nlp_analysis": {
                "entities": {
                    "malware": extracted_entities.malware_families,
                    "tools": extracted_entities.tools,
                    "threat_actors": extracted_entities.threat_actors,
                    "techniques": extracted_entities.attack_techniques
                },
                "iocs": {
                    "ips": extracted_entities.ip_addresses[:10],  # Limit for size
                    "domains": extracted_entities.domains[:10],
                    "file_hashes": {k: v[:5] for k, v in extracted_entities.file_hashes.items()}
                },
                "ttp_indicators": ttp_indicators,
                "processing_stats": self.nlp_pipeline.get_statistics(processed_text)
            },
            "metadata": {
                "extraction_timestamp": self.get_timestamp(),
                "extraction_mode": "NLP-only" if self.nlp_only_mode else "NLP+LLM",
                "llm_model": self.model_name if not self.nlp_only_mode else None,
                "total_ttps_found": len(all_ttps),
                "ttps_after_filtering": len(filtered_ttps),
                "min_confidence_threshold": self.min_confidence_threshold,
                "nlp_processing_time_ms": nlp_time,
                "llm_processing_time_ms": self.stats["llm_processing_time_ms"] if not self.nlp_only_mode else 0
            }
        }
        
        # Cache result
        if self.enable_caching:
            self._extraction_cache[report_id] = result
        
        return result
    
    def _create_ttps_from_nlp(
        self, 
        ttp_indicators: Dict[str, List[str]],
        entities: Any
    ) -> List[Dict[str, Any]]:
        """Create TTP entries from NLP indicators"""
        ttps = []
        
        for tactic, techniques in ttp_indicators.items():
            for technique in techniques:
                ttp = {
                    "technique_name": technique,
                    "tactic": tactic.replace("_", " ").title(),
                    "description": f"Detected {technique} activity via NLP analysis",
                    "indicators": [],
                    "tools": entities.tools if entities.tools else [],
                    "extraction_method": "nlp"
                }
                ttps.append(ttp)
        
        return ttps
    
    async def _extract_ttps_with_llm_enhanced(
        self,
        report: Dict[str, Any],
        processed_text: Any,
        entities: Any
    ) -> List[Dict[str, Any]]:
        """Extract TTPs using LLM with NLP-enhanced prompt"""
        try:
            # Build enhanced prompt with NLP results
            prompt = self._build_enhanced_extraction_prompt(report, processed_text, entities)
            
            # Call LLM
            response = await self.llm_client.generate(
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Parse response
            ttps = self._parse_llm_response(response)
            
            # Mark as LLM-extracted
            for ttp in ttps:
                ttp["extraction_method"] = "llm"
            
            return ttps
            
        except Exception as e:
            self.logger.error(f"LLM extraction failed: {str(e)}")
            raise LLMException(f"TTP extraction failed: {str(e)}")
    
    def _build_enhanced_extraction_prompt(
        self,
        report: Dict[str, Any],
        processed_text: Any,
        entities: Any
    ) -> str:
        """Build LLM prompt enhanced with NLP results"""
        
        title = report.get("title", "Unknown")
        description = report.get("description", "")
        
        # Get NLP enhancements
        nlp_context = self.nlp_pipeline.enhance_llm_prompt(processed_text)
        entity_summary = self.entity_extractor.create_entity_summary(entities)
        
        prompt = f"""You are a cybersecurity threat intelligence analyst. Extract ALL Tactics, Techniques, and Procedures (TTPs) from this threat intelligence report.

Report Title: {title}

NLP Pre-Analysis Results:
{nlp_context}

Entity Summary: {entity_summary}

Full Report Description:
{description}

TASK: Extract ALL TTPs mentioned or implied. For each TTP provide:
1. technique_name: Clear, specific technique name
2. tactic: MITRE ATT&CK tactic
3. description: HOW this technique is used in THIS attack
4. indicators: Specific IOCs/patterns (use the NLP results above)
5. tools: Tools/malware used

IMPORTANT:
- Extract ALL techniques, even if only implied
- Use the NLP analysis to identify specific indicators
- Link techniques to the extracted entities (malware, tools, IPs, etc.)
- Be specific about implementation details

Return ONLY valid JSON array:
[
  {{
    "technique_name": "Spearphishing Attachment",
    "tactic": "Initial Access",
    "description": "Attackers sent emails with malicious Office documents",
    "indicators": ["malicious.doc", "specific-hash"],
    "tools": ["Emotet"]
  }}
]"""

        return prompt
    
    def _enrich_ttps_with_entities(
        self,
        ttps: List[Dict],
        entities: Any
    ) -> List[Dict[str, Any]]:
        """Enrich TTPs with correlated entity information"""
        
        for ttp in ttps:
            # Add related entities
            ttp["related_entities"] = {
                "malware": entities.malware_families if entities.malware_families else [],
                "tools": entities.tools if entities.tools else [],
                "threat_actors": entities.threat_actors if entities.threat_actors else []
            }
            
            # Add IOC correlation
            if entities.ip_addresses or entities.domains:
                ttp["correlated_iocs"] = {
                    "network": entities.ip_addresses[:3] + entities.domains[:3]
                }
        
        return ttps
    
    # Rest of the methods remain the same as before...
    # (Include all the other methods from previous implementation)
    
    async def _initialize_llm(self) -> None:
        """Initialize LLM client"""
        try:
            self.llm_client = create_llm_client(
                self.llm_config,
                use_mock=self.use_mock_llm
            )
            
            if hasattr(self.llm_client, "test_connection"):
                connection_ok = await self.llm_client.test_connection()
                if not connection_ok:
                    raise LLMException("Failed to connect to LLM service")
            
            self.logger.info("LLM client initialized")
            
        except Exception as e:
            raise LLMException(f"LLM initialization failed: {str(e)}")
    
    def _parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM JSON response"""
        try:
            response = response.strip()
            
            if response.startswith('```'):
                lines = response.split('\n')
                response = '\n'.join(lines[1:-1])
                if response.startswith('json'):
                    response = '\n'.join(response.split('\n')[1:])
            
            ttps = json.loads(response)
            
            if not isinstance(ttps, list):
                ttps = [ttps]
            
            validated_ttps = []
            for ttp in ttps:
                if isinstance(ttp, dict) and "technique_name" in ttp:
                    validated_ttps.append(ttp)
            
            return validated_ttps
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse LLM response: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing LLM response: {str(e)}")
            return []
    
    async def _map_ttps_to_attack(self, ttps: List[Dict], report: Dict) -> List[Dict[str, Any]]:
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
                    ttp["tactic"] = attack_mapping["tactic"]
                    ttp["subtechnique"] = attack_mapping.get("subtechnique", False)
                    ttp["mapping_source"] = "attack_mapper"
                    self.stats["total_attack_mappings"] += 1
                else:
                    ttp["attack_id"] = "UNMAPPED"
                    ttp["mapping_source"] = "none"
                    self.stats["mapping_errors"] += 1
                
                mapped_ttps.append(ttp)
                
            except Exception as e:
                self.logger.error(f"Mapping error: {str(e)}")
                self.stats["mapping_errors"] += 1
                continue
        
        return mapped_ttps
    
    def _score_ttps(self, ttps: List[Dict], report: Dict) -> List[Dict[str, Any]]:
        """Calculate confidence scores"""
        scored_ttps = []
        
        for ttp in ttps:
            try:
                confidence = self.confidence_scorer.calculate_confidence(
                    ttp=ttp,
                    report_context=report
                )
                
                ttp["confidence_score"] = confidence
                ttp["confidence_level"] = self.confidence_scorer.get_confidence_level(confidence)
                scored_ttps.append(ttp)
                
            except Exception as e:
                self.logger.warning(f"Scoring error: {str(e)}")
                ttp["confidence_score"] = 0.5
                ttp["confidence_level"] = "medium"
                scored_ttps.append(ttp)
        
        scored_ttps.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)
        return scored_ttps
    
    def _extract_attack_chain(self, ttps: List[Dict]) -> List[str]:
        """Reconstruct attack chain from TTPs"""
        tactic_order = {
            "reconnaissance": 1, "resource development": 2, "initial access": 3,
            "execution": 4, "persistence": 5, "privilege escalation": 6,
            "defense evasion": 7, "credential access": 8, "discovery": 9,
            "lateral movement": 10, "collection": 11, "command and control": 12,
            "exfiltration": 13, "impact": 14
        }
        
        sorted_ttps = sorted(
            ttps,
            key=lambda x: tactic_order.get(x.get("tactic", "").lower(), 99)
        )
        
        chain = []
        seen = set()
        
        for ttp in sorted_ttps:
            attack_id = ttp.get("attack_id")
            if attack_id and attack_id != "UNMAPPED" and attack_id not in seen:
                chain.append(attack_id)
                seen.add(attack_id)
        
        return chain
    
    def _update_processing_stats(self, processing_time_ms: float):
        """Update processing time statistics"""
        self.stats["total_processing_time_ms"] += processing_time_ms
        
        processed_count = self.stats["total_reports_processed"]
        if processed_count > 0:
            self.stats["avg_processing_time_ms"] = (
                self.stats["total_processing_time_ms"] / processed_count
            )
        
        if processing_time_ms < self.stats["fastest_processing_ms"]:
            self.stats["fastest_processing_ms"] = processing_time_ms
        if processing_time_ms > self.stats["slowest_processing_ms"]:
            self.stats["slowest_processing_ms"] = processing_time_ms
    
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
                self.stats["validation_errors"] += 1
                return False
        
        if not report.get("description"):
            self.logger.warning(f"Empty description in {report['report_id']}")
            self.stats["validation_errors"] += 1
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
    
    def set_status(self, status: AgentStatus, message: Optional[str] = None) -> None:
        """Set status with history tracking"""
        old_status = self.status
        super().set_status(status, message)
        
        self._status_history.append({
            "timestamp": self.get_timestamp(),
            "from": old_status.value,
            "to": status.value,
            "message": message
        })
    
    def get_status_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get status history"""
        return list(self._status_history)[-limit:]
    
    def clear_cache(self) -> int:
        """Clear extraction cache"""
        count = len(self._extraction_cache)
        self._extraction_cache.clear()
        return count
    
    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check"""
        base_health = await super().health_check()
        
        health_score = 100
        error_rate = self.stats["extraction_errors"] / max(self.stats["total_reports_processed"], 1)
        health_score -= min(error_rate * 50, 30)
        
        if self.stats["total_ttps_extracted"] > 0:
            low_conf_rate = self.stats["low_confidence_ttps"] / self.stats["total_ttps_extracted"]
            health_score -= min(low_conf_rate * 30, 20)
        
        if self._is_paused:
            health_score = 50
        
        health_score = max(0, health_score)
        health_status = "healthy" if health_score >= 80 else "degraded" if health_score >= 60 else "unhealthy"
        
        base_health.update({
            "status": {
                "current": self.status.value,
                "is_paused": self._is_paused,
                "can_execute": self._can_execute
            },
            "performance": {
                "avg_processing_time_ms": self.stats["avg_processing_time_ms"],
                "nlp_processing_time_ms": self.stats["nlp_processing_time_ms"],
                "llm_processing_time_ms": self.stats["llm_processing_time_ms"],
                "cache_hit_rate": self._calculate_cache_hit_rate()
            },
            "quality": {
                "avg_confidence": self.stats["avg_confidence_score"],
                "high_confidence_ttps": self.stats["high_confidence_ttps"],
                "low_confidence_ttps": self.stats["low_confidence_ttps"]
            },
            "health": {
                "score": round(health_score, 1),
                "status": health_status,
                "factors": {
                    "error_rate": round(error_rate * 100, 2),
                    "success_rate": round((1 - error_rate) * 100, 2)
                }
            }
        })
        
        return base_health
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.stats["cache_hits"] + self.stats["cache_misses"]
        if total == 0:
            return 0.0
        return round((self.stats["cache_hits"] / total) * 100, 2)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        return {
            "agent_info": {
                "id": self.id,
                "name": self.name,
                "status": self.status.value,
                "uptime_seconds": (
                    (datetime.utcnow() - self.start_time).total_seconds()
                    if self.start_time else 0
                ),
                "is_paused": self._is_paused
            },
            "configuration": {
                "extraction_mode": "NLP-only" if self.nlp_only_mode else "NLP+LLM",
                "llm_model": self.model_name,
                "use_mock": self.use_mock_llm,
                "use_nlp_preprocessing": self.use_nlp_preprocessing,
                "min_confidence_threshold": self.min_confidence_threshold,
                "caching_enabled": self.enable_caching
            },
            "statistics": self.stats.copy(),
            "health": (await self.health_check()).get("health", {})
        }