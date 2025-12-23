"""
LangChain-Enhanced RuleGen Agent
Integrates LangChain for Sigma rule generation
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import AgentException
from core.logging import get_agent_logger
from core.langchain_integration import (
    create_langchain_llm,
    create_sigma_rule_chain,
    SigmaRuleChain
)
from agents.evaluator.feedback_manager import FeedbackManager
from core.knowledge_base import get_kb_manager


class LangChainRuleGenAgent(BaseAgent):
    """
    LangChain-powered Rule Generation Agent
    
    Uses LangChain for:
    - Structured Sigma rule generation
    - Automatic output parsing
    - Feedback-aware prompts
    - Better error handling
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.sigma_chain: Optional[SigmaRuleChain] = None
        
        # Feedback integration
        self.feedback_manager = FeedbackManager()
        self.use_feedback = config.get("use_feedback", True)
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.supported_platforms = config.get("platforms", ["splunk", "elasticsearch"])
        self.min_confidence = config.get("min_confidence_threshold", 0.7)
        
        # Statistics
        self.stats = {
            "rules_generated": 0,
            "ttps_processed": 0,
            "langchain_generations": 0,
            "fallback_generations": 0,
            "errors": 0,
            "processing_time_ms": 0
        }
        
        self.logger = get_agent_logger(f"langchain_rulegen_{name}", self.id)
    
    async def start(self) -> None:
        """Start the agent"""
        await super().start()
        
        try:
            if self.langchain_enabled:
                # Initialize LangChain components
                self.llm_wrapper = create_langchain_llm(self.llm_config)
                self.sigma_chain = create_sigma_rule_chain(self.llm_wrapper)
                # print(f"DEBUG: RuleGen Chain Created: {self.sigma_chain}")
                
                self.logger.info("LangChain RuleGen Agent started with LangChain integration")
            else:
                self.logger.info("LangChain RuleGen Agent started (LangChain disabled)")
                
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise AgentException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rule generation"""
        start_time = datetime.utcnow()
        
        try:
            # Parse input
            ttps = input_data.get("ttps", input_data.get("extracted_ttps", []))
            
            if not ttps:
                return {
                    "status": "no_data",
                    "message": "No TTPs to process"
                }
            
            self.logger.info(f"Generating rules for {len(ttps)} TTPs with LangChain")
            
            # Filter by confidence
            filtered_ttps = [
                ttp for ttp in ttps
                if ttp.get("confidence_score", 0) >= self.min_confidence
            ]
            
            self.logger.info(f"After filtering: {len(filtered_ttps)} TTPs (confidence >= {self.min_confidence})")
            
            # Generate rules
            rule_results = []
            
            for ttp in filtered_ttps:
                try:
                    result = await self._generate_rule_for_ttp(ttp)
                    rule_results.append(result)
                    self.stats["ttps_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Rule generation failed for {ttp.get('technique_id')}: {e}")
                    self.stats["errors"] += 1
                    continue
            
            # Calculate statistics
            successful_rules = sum(1 for r in rule_results if r.get("status") == "success")
            self.stats["rules_generated"] += successful_rules
            
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            return {
                "status": "success",
                "summary": {
                    "ttps_processed": len(filtered_ttps),
                    "rules_generated": successful_rules,
                    "langchain_generations": self.stats["langchain_generations"],
                    "fallback_generations": self.stats["fallback_generations"],
                    "errors": self.stats["errors"],
                    "processing_time_ms": processing_time_ms
                },
                "rule_generation_results": rule_results,
                "rules": [r.get("rule") for r in rule_results if r.get("status") == "success"]
            }
            
        except Exception as e:
            self.logger.error(f"Execution error: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _generate_rule_for_ttp(self, ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Generate rule for a single TTP"""
        ttp_id = ttp.get("technique_id", "unknown")
        
        # Get feedback context if available
        feedback_text = None
        if self.use_feedback:
            # Check for direct feedback passed in input
            input_feedback = ttp.get('feedback', {})
            if input_feedback:
                # Process structured feedback from orchestrator
                evaluation = input_feedback.get('evaluation', {})
                verification_results = input_feedback.get('verification_results', [])
                metrics = evaluation.get('metrics', {})
                
                feedback_lines = ["Previous Attempt Feedback:"]
                
                # Add metrics
                if 'detection_rate' in metrics:
                    feedback_lines.append(f"- Detection Rate: {metrics['detection_rate']:.2%}")
                
                # Add specific verification failures
                if verification_results:
                    ver_result = next((v for v in verification_results if v.get('ttp_id') == ttp_id), None)
                    if ver_result:
                        detection_data = ver_result.get('verification', {})
                        detected = detection_data.get('detected', False) if isinstance(detection_data, dict) else getattr(detection_data, 'detected', False)
                        
                        if not detected:
                            feedback_lines.append(f"- SIEM Verification FAILED: The rule failed to detect the attack.")
                            # Add more details if available
                            if isinstance(detection_data, dict) and 'message' in detection_data:
                                feedback_lines.append(f"  Reason: {detection_data['message']}")
                        else:
                            feedback_lines.append(f"- SIEM Verification PASSED.")
                
                # Add evaluator feedback
                for result in evaluation.get('evaluation_results', []):
                    if result.get('rule_id') == ttp_id or result.get('rule_id') == ttp.get('id'):
                        if result.get('weaknesses'):
                            feedback_lines.append("- Weaknesses identified:")
                            for w in result['weaknesses']:
                                feedback_lines.append(f"  * {w}")
                        if result.get('suggestions'):
                            feedback_lines.append("- Suggestions for improvement:")
                            for s in result['suggestions']:
                                feedback_lines.append(f"  * {s}")
                                
                feedback_text = "\n".join(feedback_lines)
            
            # Fallback to history if no direct feedback
            elif self.feedback_manager:
                feedback_history = self.feedback_manager.get_feedback_history("rulegen", last_n=1)
                if feedback_history:
                    latest_feedback = feedback_history[-1]
                    improvements = latest_feedback.get("improvements_needed", [])
                    suggestions = latest_feedback.get("actionable_suggestions", [])
                    
                    if improvements or suggestions:
                        feedback_text = "Previous feedback:\n"
                        for imp in improvements[:3]:
                            feedback_text += f"- Improve {imp.get('metric')}: {imp.get('suggestion')}\n"
                        for sug in suggestions[:3]:
                            feedback_text += f"- {sug}\n"
        
        # Knowledge Base: Retrieve similar rules (Few-Shot)
        examples_text = ""
        kb = get_kb_manager()
        if kb and kb.enabled:
            query = f"{ttp.get('technique_name', '')} {ttp.get('description', '')}"
            try:
                examples = await kb.query_similar_rules(query, n_results=2)
                if examples:
                    for ex in examples:
                        title = ex.get('title', 'Unknown')
                        detection = ex.get('detection', 'Unknown')
                        # Format as compact YAML-ish for the prompt
                        examples_text += f"Rule: {title}\nDetection: {detection}\n\n"
                    # print(f"DEBUG: Found {len(examples)} examples from KB for {ttp_id}")
            except Exception as e:
                self.logger.warning(f"KB Query Failed: {e}")
        
        # Generate with LangChain
        if self.langchain_enabled and self.sigma_chain:
            # Retry loop for rate limits
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # print(f"DEBUG: Generating rule for {ttp_id} using LangChain")
                    sigma_output = await self.sigma_chain.generate(ttp, feedback_text, examples=examples_text)
                    
                    # Convert to rule format
                    rule = {
                        "title": sigma_output.title,
                        "description": sigma_output.description,
                        "logsource": sigma_output.logsource.model_dump() if hasattr(sigma_output.logsource, 'model_dump') else sigma_output.logsource,
                        "detection": json.loads(sigma_output.detection) if isinstance(sigma_output.detection, str) else sigma_output.detection,
                        "falsepositives": sigma_output.falsepositives,
                        "level": sigma_output.level,
                        "tags": sigma_output.tags,
                        "ttp_id": ttp_id,
                        "technique_name": ttp.get("technique_name"),
                        "generation_method": "langchain"
                    }
                    
                    self.stats["langchain_generations"] += 1
                    
                    return {
                        "ttp_id": ttp_id,
                        "technique_name": ttp.get("technique_name"),
                        "status": "success",
                        "rule": rule,
                        "generation_method": "langchain"
                    }
                    
                except Exception as e:
                    error_msg = str(e).lower()
                    is_rate_limit = "429" in error_msg or "quota" in error_msg or "rate limit" in error_msg or "too many requests" in error_msg
                    
                    if is_rate_limit and attempt < max_retries - 1:
                        self.logger.warning(f"Rate limit hit ({e}). Rotating provider and retrying [{attempt+1}/{max_retries}]...")
                        try:
                             if hasattr(self, 'llm_wrapper'):
                                self.llm_wrapper.rotate_provider()
                                self.sigma_chain = create_sigma_rule_chain(self.llm_wrapper)
                                await asyncio.sleep(1)
                                continue
                        except Exception as rot_e:
                            self.logger.error(f"Rotation failed: {rot_e}")
                    
                    if attempt == max_retries - 1:
                        # print(f"DEBUG: RuleGen LangChain Exception: {e}")
                        self.logger.warning(f"LangChain generation failed for {ttp_id}: {e}, using fallback")
                        return await self._fallback_rule_generation(ttp)
        else:
            return await self._fallback_rule_generation(ttp)
    
    async def _fallback_rule_generation(self, ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule generation"""
        self.stats["fallback_generations"] += 1
        
        ttp_id = ttp.get("technique_id", "unknown")
        technique_name = ttp.get("technique_name", "Unknown Technique")
        
        # Create basic rule
        rule = {
            "title": f"Detection: {technique_name}",
            "description": ttp.get("description", f"Detects {technique_name} activity")[:200],
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": "suspicious"
                },
                "condition": "selection"
            },
            "falsepositives": [
                "Legitimate administrative activity"
            ],
            "level": "medium",
            "tags": [f"attack.{ttp_id.lower()}"],
            "ttp_id": ttp_id,
            "technique_name": technique_name,
            "generation_method": "fallback"
        }
        
        return {
            "ttp_id": ttp_id,
            "technique_name": technique_name,
            "status": "success",
            "rule": rule,
            "generation_method": "fallback"
        }
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        return "ttps" in data or "extracted_ttps" in data
    
    async def initialize(self):
        """Initialize converters (compatibility method)"""
        pass
    
    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process method (compatibility)"""
        return await self.execute(data)
