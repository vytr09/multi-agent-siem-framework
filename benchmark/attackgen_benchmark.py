"""
AttackGen Agent Benchmark
Evaluates attack command quality using LLM-as-Judge methodology
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from benchmark.benchmark_base import (
    BaseBenchmark, 
    BenchmarkMetric, 
    MetricCategory,
    EvaluationResult,
    BenchmarkResult
)
from benchmark.llm_judge import LLMJudge


class AttackGenBenchmark(BaseBenchmark):
    """
    Benchmark for evaluating AttackGen agent outputs.
    
    Evaluates:
    - Technical correctness of commands
    - Realism and operational viability
    - Safety for testing environments
    - Detectability and evasion potential
    - MITRE ATT&CK alignment
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.llm_judge: Optional[LLMJudge] = None
        super().__init__(config)
        
        # Initialize LLM Judge
        if self.use_llm_judge:
            self.llm_judge = LLMJudge(self.llm_judge_config)
    
    def _initialize_metrics(self) -> None:
        """Initialize AttackGen-specific metrics"""
        
        self.metrics = [
            # CORRECTNESS Category
            BenchmarkMetric(
                name="technical_correctness",
                category=MetricCategory.CORRECTNESS,
                description="Command syntax, logic, and technical accuracy",
                weight=2.0,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="attack_alignment",
                category=MetricCategory.CORRECTNESS,
                description="Alignment with MITRE ATT&CK technique description",
                weight=1.5,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="platform_compatibility",
                category=MetricCategory.CORRECTNESS,
                description="Compatibility with target platform (Windows/Linux)",
                weight=1.5,
                min_score=0.0,
                max_score=10.0
            ),
            
            # REALISM Category
            BenchmarkMetric(
                name="operational_realism",
                category=MetricCategory.REALISM,
                description="Resemblance to real-world attack techniques",
                weight=2.0,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="threat_actor_alignment",
                category=MetricCategory.REALISM,
                description="Alignment with known threat actor TTPs",
                weight=1.0,
                min_score=0.0,
                max_score=10.0
            ),
            
            # SAFETY Category
            BenchmarkMetric(
                name="testing_safety",
                category=MetricCategory.SAFETY,
                description="Safety for execution in test environments",
                weight=2.5,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="controlled_impact",
                category=MetricCategory.SAFETY,
                description="Predictable and controllable effects",
                weight=1.5,
                min_score=0.0,
                max_score=10.0
            ),
            
            # DETECTABILITY Category
            BenchmarkMetric(
                name="detection_value",
                category=MetricCategory.DETECTABILITY,
                description="Value for creating effective detection rules",
                weight=1.5,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="artifact_generation",
                category=MetricCategory.DETECTABILITY,
                description="Quality of generated detection artifacts",
                weight=1.0,
                min_score=0.0,
                max_score=10.0
            ),
            
            # EFFECTIVENESS Category
            BenchmarkMetric(
                name="completeness",
                category=MetricCategory.EFFECTIVENESS,
                description="Completeness of attack implementation",
                weight=1.5,
                min_score=0.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="documentation_quality",
                category=MetricCategory.EFFECTIVENESS,
                description="Quality of explanation and documentation",
                weight=1.0,
                min_score=0.0,
                max_score=10.0
            )
        ]
    
    async def evaluate_item(self, command: Dict[str, Any]) -> BenchmarkResult:
        """
        Evaluate a single attack command.
        
        Args:
            command: Attack command from AttackGen agent
            
        Returns:
            BenchmarkResult with detailed scores
        """
        
        print(f"\n[INFO] Evaluating: {command.get('name', 'Unknown Command')}")
        
        # Extract command details
        command_id = command.get("command_id", "unknown")
        attack_id = command.get("mitre_attack_id", "unknown")
        
        # Prepare evaluation criteria for LLM Judge
        criteria = self._prepare_evaluation_criteria()
        
        # Prepare context
        context = self._prepare_context(command)
        
        # Perform LLM evaluation if enabled
        metric_results = []
        
        if self.use_llm_judge and self.llm_judge:
            llm_results = await self._evaluate_with_llm(command, criteria, context)
            metric_results.extend(llm_results)
        
        # Perform rule-based evaluation
        rule_results = await self._evaluate_with_rules(command)
        metric_results.extend(rule_results)
        
        # Calculate scores
        overall_score = self.calculate_overall_score(metric_results)
        category_scores = self.calculate_category_scores(metric_results)
        
        # Generate summary
        summary = self._generate_summary(command, overall_score, category_scores)
        
        result = BenchmarkResult(
            benchmark_id=self.benchmark_id,
            item_id=command_id,
            item_type="attack_command",
            overall_score=overall_score,
            category_scores=category_scores,
            metric_results=metric_results,
            summary=summary,
            metadata={
                "attack_id": attack_id,
                "technique_name": command.get("technique_name"),
                "platform": command.get("platform"),
                "tactic": command.get("tactic"),
                "confidence_score": command.get("confidence_score"),
                "source": command.get("source")
            }
        )
        
        print(f"[INFO] Overall Score: {overall_score:.3f}")
        
        return result
    
    def _prepare_evaluation_criteria(self) -> List[Dict[str, Any]]:
        """Prepare criteria for LLM evaluation"""
        return [
            {
                "name": "technical_correctness",
                "description": (
                    "Evaluate the technical correctness of the command:\n"
                    "- Syntax validity for the target platform\n"
                    "- Logical flow and execution order\n"
                    "- Proper use of tools and utilities\n"
                    "- Handling of edge cases and errors"
                ),
                "weight": 2.0
            },
            {
                "name": "attack_alignment",
                "description": (
                    "Assess alignment with MITRE ATT&CK technique:\n"
                    "- Matches technique description and objectives\n"
                    "- Uses appropriate methods for the technique\n"
                    "- Covers key aspects of the technique\n"
                    "- Produces expected artifacts"
                ),
                "weight": 1.5
            },
            {
                "name": "operational_realism",
                "description": (
                    "Evaluate operational realism:\n"
                    "- Resembles real-world attack techniques\n"
                    "- Uses tools/methods seen in actual campaigns\n"
                    "- Follows typical attack patterns\n"
                    "- Realistic for threat actor capabilities"
                ),
                "weight": 2.0
            },
            {
                "name": "threat_actor_alignment",
                "description": (
                    "Assess alignment with known threat actor TTPs:\n"
                    "- Matches techniques used by identified threat actors\n"
                    "- Reflects real-world threat actor capabilities\n"
                    "- Uses tools/methods associated with the threat actor\n"
                    "- Appropriate sophistication level for the threat actor"
                ),
                "weight": 1.0
            },
            {
                "name": "testing_safety",
                "description": (
                    "Assess safety for testing environments:\n"
                    "- No destructive or irreversible actions\n"
                    "- Controlled and predictable behavior\n"
                    "- Proper cleanup instructions\n"
                    "- Safe for production-like test environments"
                ),
                "weight": 2.5
            },
            {
                "name": "detection_value",
                "description": (
                    "Evaluate value for detection development:\n"
                    "- Generates useful detection artifacts\n"
                    "- Clear indicators for SIEM rules\n"
                    "- Helps build effective detection logic\n"
                    "- Balances evasion and detectability"
                ),
                "weight": 1.5
            },
            {
                "name": "documentation_quality",
                "description": (
                    "Assess documentation quality:\n"
                    "- Clear explanation of what the command does\n"
                    "- Well-documented prerequisites\n"
                    "- Detailed expected indicators\n"
                    "- Complete cleanup instructions"
                ),
                "weight": 1.0
            }
        ]
    
    def _prepare_context(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare evaluation context"""
        return {
            "technique_context": {
                "attack_id": command.get("mitre_attack_id"),
                "technique_name": command.get("technique_name"),
                "tactic": command.get("tactic"),
                "platform": command.get("platform")
            },
            "threat_context": {
                "confidence_score": command.get("confidence_score"),
                "threat_actor": command.get("metadata", {}).get("threat_actor"),
                "campaign": command.get("metadata", {}).get("campaign")
            },
            "evaluation_focus": [
                "Technical accuracy and executability",
                "Alignment with MITRE ATT&CK framework",
                "Safety for security testing",
                "Value for detection engineering"
            ]
        }
    
    async def _evaluate_with_llm(
        self,
        command: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Evaluate using LLM Judge"""
        
        print("  [LLM] Running LLM evaluation...")
        
        # Prepare item for LLM
        llm_item = {
            "command_name": command.get("name"),
            "command": command.get("command"),
            "explanation": command.get("explanation"),
            "indicators": command.get("indicators", []),
            "prerequisites": command.get("prerequisites", []),
            "cleanup": command.get("cleanup"),
            "platform": command.get("platform"),
            "technique": command.get("technique_name"),
            "attack_id": command.get("mitre_attack_id")
        }
        
        # Call LLM Judge
        llm_result = await self.llm_judge.evaluate(llm_item, criteria, context)
        
        # Convert LLM results to EvaluationResult objects
        results = []
        
        for eval_data in llm_result.get("evaluations", []):
            metric = self.get_metric_by_name(eval_data["criterion"])
            if metric:
                normalized = metric.normalize_score(eval_data["score"])
                
                result = EvaluationResult(
                    metric_name=eval_data["criterion"],
                    score=eval_data["score"],
                    normalized_score=normalized,
                    explanation=eval_data["explanation"],
                    confidence=eval_data.get("confidence", 0.8),
                    metadata={
                        "strengths": eval_data.get("strengths", []),
                        "weaknesses": eval_data.get("weaknesses", []),
                        "source": "llm_judge"
                    }
                )
                results.append(result)
        
        return results
    
    async def _evaluate_with_rules(self, command: Dict[str, Any]) -> List[EvaluationResult]:
        """Evaluate using rule-based checks"""
        
        print("  [RULES] Running rule-based evaluation...")
        
        results = []
        
        # Platform compatibility check
        platform_score = self._check_platform_compatibility(command)
        metric = self.get_metric_by_name("platform_compatibility")
        if metric:
            results.append(EvaluationResult(
                metric_name="platform_compatibility",
                score=platform_score,
                normalized_score=metric.normalize_score(platform_score),
                explanation=self._get_platform_explanation(command, platform_score),
                confidence=1.0,
                metadata={"source": "rule_based"}
            ))
        
        # Completeness check
        completeness_score = self._check_completeness(command)
        metric = self.get_metric_by_name("completeness")
        if metric:
            results.append(EvaluationResult(
                metric_name="completeness",
                score=completeness_score,
                normalized_score=metric.normalize_score(completeness_score),
                explanation=self._get_completeness_explanation(command, completeness_score),
                confidence=1.0,
                metadata={"source": "rule_based"}
            ))
        
        # Controlled impact check
        impact_score = self._check_controlled_impact(command)
        metric = self.get_metric_by_name("controlled_impact")
        if metric:
            results.append(EvaluationResult(
                metric_name="controlled_impact",
                score=impact_score,
                normalized_score=metric.normalize_score(impact_score),
                explanation=self._get_impact_explanation(command, impact_score),
                confidence=1.0,
                metadata={"source": "rule_based"}
            ))
        
        # Artifact generation check
        artifact_score = self._check_artifact_generation(command)
        metric = self.get_metric_by_name("artifact_generation")
        if metric:
            results.append(EvaluationResult(
                metric_name="artifact_generation",
                score=artifact_score,
                normalized_score=metric.normalize_score(artifact_score),
                explanation=self._get_artifact_explanation(command, artifact_score),
                confidence=1.0,
                metadata={"source": "rule_based"}
            ))
        
        return results
    
    def _check_platform_compatibility(self, command: Dict[str, Any]) -> float:
        """Check platform compatibility"""
        platform = command.get("platform", "").lower()
        cmd_text = command.get("command", "").lower()
        
        score = 5.0  # Base score
        
        if platform == "windows":
            # Check for Windows-specific elements
            windows_indicators = [
                "powershell", ".exe", "cmd", "wmic", "reg", 
                "net ", "sc ", "schtasks", "\\"
            ]
            matches = sum(1 for ind in windows_indicators if ind in cmd_text)
            score += min(matches * 0.5, 5.0)
            
        elif platform == "linux":
            # Check for Linux-specific elements
            linux_indicators = [
                "bash", "sh", "chmod", "chown", "sudo",
                "/bin/", "/etc/", "/var/", "apt", "yum"
            ]
            matches = sum(1 for ind in linux_indicators if ind in cmd_text)
            score += min(matches * 0.5, 5.0)
        
        return min(score, 10.0)
    
    def _check_completeness(self, command: Dict[str, Any]) -> float:
        """Check command completeness"""
        score = 0.0
        
        # Check required fields
        if command.get("name"):
            score += 2.0
        if command.get("command"):
            score += 2.0
        if command.get("explanation"):
            score += 2.0
        if command.get("indicators") and len(command["indicators"]) > 0:
            score += 2.0
        if command.get("prerequisites") and len(command["prerequisites"]) > 0:
            score += 1.0
        if command.get("cleanup"):
            score += 1.0
        
        return min(score, 10.0)
    
    def _check_controlled_impact(self, command: Dict[str, Any]) -> float:
        """Check for controlled impact"""
        cmd_text = command.get("command", "").lower()
        cleanup = command.get("cleanup", "").lower()
        
        score = 10.0  # Start with full score
        
        # Dangerous patterns
        dangerous_patterns = [
            "rm -rf /", "format ", "del /f /s /q", 
            "shutdown", "reboot", "mkfs", "> /dev/sd"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in cmd_text:
                score -= 3.0
        
        # Bonus for cleanup
        if "cleanup" in cleanup or "remove" in cleanup or "delete" in cleanup:
            score += 1.0
        
        return max(min(score, 10.0), 0.0)
    
    def _check_artifact_generation(self, command: Dict[str, Any]) -> float:
        """Check artifact generation quality"""
        indicators = command.get("indicators", [])
        
        if not indicators:
            return 3.0
        
        score = 5.0
        
        # Check for diverse indicator types
        has_process = any("process" in str(ind).lower() for ind in indicators)
        has_file = any("file" in str(ind).lower() for ind in indicators)
        has_network = any("network" in str(ind).lower() or "connection" in str(ind).lower() for ind in indicators)
        has_registry = any("registry" in str(ind).lower() for ind in indicators)
        
        if has_process:
            score += 1.0
        if has_file:
            score += 1.0
        if has_network:
            score += 1.5
        if has_registry:
            score += 1.5
        
        return min(score, 10.0)
    
    def _get_platform_explanation(self, command: Dict[str, Any], score: float) -> str:
        """Get platform compatibility explanation"""
        platform = command.get("platform", "unknown")
        if score >= 8.0:
            return f"Command is well-suited for {platform} platform with appropriate syntax"
        elif score >= 6.0:
            return f"Command is compatible with {platform} but could use more platform-specific features"
        else:
            return f"Command shows limited {platform} platform compatibility"
    
    def _get_completeness_explanation(self, command: Dict[str, Any], score: float) -> str:
        """Get completeness explanation"""
        if score >= 9.0:
            return "Command is complete with all required fields and documentation"
        elif score >= 7.0:
            return "Command is mostly complete but missing some optional fields"
        else:
            return "Command is incomplete and missing critical fields"
    
    def _get_impact_explanation(self, command: Dict[str, Any], score: float) -> str:
        """Get impact explanation"""
        if score >= 8.0:
            return "Command has controlled impact and is safe for testing"
        elif score >= 6.0:
            return "Command has mostly controlled impact with minor concerns"
        else:
            return "Command may have uncontrolled impact and safety concerns"
    
    def _get_artifact_explanation(self, command: Dict[str, Any], score: float) -> str:
        """Get artifact generation explanation"""
        num_indicators = len(command.get("indicators", []))
        if score >= 8.0:
            return f"Command generates {num_indicators} diverse detection artifacts"
        elif score >= 6.0:
            return f"Command generates {num_indicators} detection artifacts but could be more diverse"
        else:
            return f"Command generates limited detection artifacts ({num_indicators})"
    
    def _generate_summary(
        self,
        command: Dict[str, Any],
        overall_score: float,
        category_scores: Dict[str, float]
    ) -> str:
        """Generate evaluation summary"""
        
        name = command.get("name", "Unknown")
        attack_id = command.get("mitre_attack_id", "Unknown")
        
        summary_parts = [
            f"Evaluation Summary for: {name} ({attack_id})",
            f"Overall Score: {overall_score:.3f}/1.0",
            "",
            "Category Scores:"
        ]
        
        for category, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
            summary_parts.append(f"  - {category}: {score:.3f}")
        
        # Add assessment
        if overall_score >= 0.85:
            assessment = "EXCELLENT - High quality attack command"
        elif overall_score >= 0.75:
            assessment = "GOOD - Solid attack command with minor improvements needed"
        elif overall_score >= 0.65:
            assessment = "FAIR - Acceptable but needs improvements"
        else:
            assessment = "POOR - Significant improvements required"
        
        summary_parts.extend([
            "",
            f"Assessment: {assessment}"
        ])
        
        return "\n".join(summary_parts)
    
    async def evaluate_comparison(
        self,
        command_a: Dict[str, Any],
        command_b: Dict[str, Any],
        criteria: str = "overall quality"
    ) -> Dict[str, Any]:
        """
        Compare two commands.
        
        Args:
            command_a: First command
            command_b: Second command
            criteria: Comparison criteria
            
        Returns:
            Comparison result
        """
        if not self.use_llm_judge or not self.llm_judge:
            return {
                "preference": "neutral",
                "reasoning": "LLM Judge not available",
                "confidence": 0.0
            }
        
        # Prepare items
        item_a = {
            "name": command_a.get("name"),
            "command": command_a.get("command"),
            "explanation": command_a.get("explanation"),
            "platform": command_a.get("platform")
        }
        
        item_b = {
            "name": command_b.get("name"),
            "command": command_b.get("command"),
            "explanation": command_b.get("explanation"),
            "platform": command_b.get("platform")
        }
        
        return await self.llm_judge.compare(item_a, item_b, criteria)