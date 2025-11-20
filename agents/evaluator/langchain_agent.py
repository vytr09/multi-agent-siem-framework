"""
LangChain-Enhanced Evaluator Agent
Integrates LangChain for rule evaluation and feedback generation
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
    create_evaluation_chain,
    RuleEvaluationChain
)
from agents.evaluator.feedback_manager import FeedbackManager


class LangChainEvaluatorAgent(BaseAgent):
    """
    LangChain-powered Evaluation Agent
    
    Uses LangChain for:
    - Structured rule evaluation
    - Automatic quality scoring
    - Detailed feedback generation
    - Better consistency across evaluations
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.evaluation_chain: Optional[RuleEvaluationChain] = None
        
        # Feedback integration
        self.feedback_manager = FeedbackManager()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.min_quality_score = config.get("min_quality_score", 0.7)
        self.evaluation_criteria = config.get("evaluation_criteria", [
            "accuracy", "completeness", "efficiency", "maintainability"
        ])
        
        # Statistics
        self.stats = {
            "rules_evaluated": 0,
            "langchain_evaluations": 0,
            "fallback_evaluations": 0,
            "feedback_generated": 0,
            "errors": 0,
            "processing_time_ms": 0
        }
        
        self.logger = get_agent_logger(f"langchain_evaluator_{name}", self.id)
    
    async def start(self) -> None:
        """Start the agent"""
        await super().start()
        
        try:
            if self.langchain_enabled:
                # Initialize LangChain components
                llm_wrapper = create_langchain_llm(self.llm_config)
                self.evaluation_chain = create_evaluation_chain(llm_wrapper)
                
                self.logger.info("LangChain Evaluator Agent started with LangChain integration")
            else:
                self.logger.info("LangChain Evaluator Agent started (LangChain disabled)")
                
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise AgentException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rule evaluation"""
        start_time = datetime.utcnow()
        
        try:
            # Parse input
            rules = input_data.get("rules", [])
            
            if not rules:
                return {
                    "status": "no_data",
                    "message": "No rules to evaluate"
                }
            
            self.logger.info(f"Evaluating {len(rules)} rules with LangChain")
            
            # Evaluate rules
            evaluation_results = []
            
            for rule in rules:
                try:
                    result = await self._evaluate_rule(rule)
                    evaluation_results.append(result)
                    self.stats["rules_evaluated"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Evaluation failed for rule: {e}")
                    self.stats["errors"] += 1
                    continue
            
            # Generate feedback
            feedback = await self._generate_feedback(evaluation_results)
            
            # Calculate statistics
            avg_quality = sum(r.get("quality_score", 0) for r in evaluation_results) / len(evaluation_results) if evaluation_results else 0
            passing_rules = sum(1 for r in evaluation_results if r.get("quality_score", 0) >= self.min_quality_score)
            
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            return {
                "status": "success",
                "summary": {
                    "rules_evaluated": len(evaluation_results),
                    "average_quality_score": round(avg_quality, 3),
                    "passing_rules": passing_rules,
                    "failing_rules": len(evaluation_results) - passing_rules,
                    "langchain_evaluations": self.stats["langchain_evaluations"],
                    "fallback_evaluations": self.stats["fallback_evaluations"],
                    "errors": self.stats["errors"],
                    "processing_time_ms": processing_time_ms
                },
                "evaluation_results": evaluation_results,
                "feedback": feedback
            }
            
        except Exception as e:
            self.logger.error(f"Execution error: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _evaluate_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single rule"""
        rule_title = rule.get("title", "Unknown Rule")
        
        # Get TTP info from rule if available
        ttp = {
            "technique_id": rule.get("ttp_id", ""),
            "technique_name": rule.get("technique_name", ""),
            "tactic": ""
        }
        
        # Evaluate with LangChain
        if self.langchain_enabled and self.evaluation_chain:
            try:
                eval_result = await self.evaluation_chain.evaluate(rule, ttp)
                
                # Convert to evaluation result
                result = {
                    "rule_title": rule_title,
                    "rule_id": rule.get("id", rule.get("ttp_id")),
                    "quality_score": eval_result.get("overall_score", 0) / 10.0,  # Scale to 0-1
                    "status": "pass" if eval_result.get("overall_score", 0) >= self.min_quality_score * 10 else "fail",
                    "strengths": eval_result.get("strengths", []),
                    "weaknesses": eval_result.get("weaknesses", []),
                    "suggestions": eval_result.get("suggestions", []),
                    "metrics": {
                        "accuracy": eval_result.get("detection_coverage", 5) / 10.0,
                        "completeness": eval_result.get("completeness", 5) / 10.0,
                        "efficiency": eval_result.get("performance", 5) / 10.0,
                        "maintainability": eval_result.get("false_positive_rate", 5) / 10.0
                    },
                    "evaluation_method": "langchain"
                }
                
                self.stats["langchain_evaluations"] += 1
                
                return result
                
            except Exception as e:
                self.logger.warning(f"LangChain evaluation failed for {rule_title}: {e}, using fallback")
                return await self._fallback_evaluation(rule)
        else:
            return await self._fallback_evaluation(rule)
    
    async def _fallback_evaluation(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback evaluation using basic heuristics"""
        self.stats["fallback_evaluations"] += 1
        
        rule_title = rule.get("title", "Unknown Rule")
        
        # Basic scoring
        score = 0.5
        strengths = []
        weaknesses = []
        suggestions = []
        
        # Check for key fields
        if rule.get("description"):
            score += 0.1
            strengths.append("Has description")
        else:
            weaknesses.append("Missing description")
            suggestions.append("Add detailed description")
        
        if rule.get("detection"):
            score += 0.2
            strengths.append("Has detection logic")
        else:
            weaknesses.append("Missing detection logic")
            suggestions.append("Add detection criteria")
        
        if rule.get("falsepositives"):
            score += 0.1
            strengths.append("Lists false positives")
        else:
            suggestions.append("Document potential false positives")
        
        if rule.get("tags"):
            score += 0.1
            strengths.append("Properly tagged")
        
        return {
            "rule_title": rule_title,
            "rule_id": rule.get("id", rule.get("ttp_id")),
            "quality_score": min(score, 1.0),
            "status": "pass" if score >= self.min_quality_score else "fail",
            "strengths": strengths,
            "weaknesses": weaknesses,
            "suggestions": suggestions,
            "metrics": {
                "accuracy": score,
                "completeness": score,
                "efficiency": 0.5,
                "maintainability": 0.5
            },
            "evaluation_method": "fallback"
        }
    
    async def _generate_feedback(self, evaluation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate feedback for the RuleGen agent"""
        
        if not evaluation_results:
            return {}
        
        # Calculate aggregate metrics
        avg_quality = sum(r.get("quality_score", 0) for r in evaluation_results) / len(evaluation_results)
        
        # Collect common issues
        all_weaknesses = []
        all_suggestions = []
        
        for result in evaluation_results:
            all_weaknesses.extend(result.get("weaknesses", []))
            all_suggestions.extend(result.get("suggestions", []))
        
        # Find most common issues
        from collections import Counter
        weakness_counts = Counter(all_weaknesses)
        suggestion_counts = Counter(all_suggestions)
        
        top_weaknesses = [w for w, _ in weakness_counts.most_common(5)]
        top_suggestions = [s for s, _ in suggestion_counts.most_common(5)]
        
        # Generate feedback
        feedback = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_agent": self.id,
            "target_agent": "rulegen",
            "average_quality_score": round(avg_quality, 3),
            "total_rules_evaluated": len(evaluation_results),
            "improvements_needed": [
                {
                    "metric": "quality",
                    "current_value": avg_quality,
                    "target_value": 0.85,
                    "suggestion": "Improve overall rule quality"
                }
            ],
            "common_issues": top_weaknesses,
            "actionable_suggestions": top_suggestions
        }
        
        # Store feedback
        self.feedback_manager.store_feedback(feedback)
        self.stats["feedback_generated"] += 1
        
        return feedback
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        return "rules" in data and isinstance(data["rules"], list)
    
    async def initialize(self):
        """Initialize (compatibility method)"""
        pass
    
    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process method (compatibility)"""
        return await self.execute(data)
