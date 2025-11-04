"""
RuleGen Benchmark - benchmark/rulegen_benchmark.py
Evaluates detection rule generation quality using LLM-as-Judge
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from benchmark.benchmark_base import (
    BaseBenchmark,
    BenchmarkMetric,
    BenchmarkResult,
    EvaluationResult,
    MetricCategory
)
from benchmark.llm_judge import LLMJudge


class RuleGenBenchmark(BaseBenchmark):
    """
    Benchmark for RuleGen Agent outputs.
    
    Evaluates:
    - Sigma rule quality and completeness
    - Platform-specific rule correctness
    - Detection logic effectiveness
    - False positive/negative potential
    - Operational readiness
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Initialize LLM Judge if enabled
        if self.use_llm_judge:
            self.llm_judge = LLMJudge(self.llm_judge_config)
        else:
            self.llm_judge = None
        
        # RuleGen-specific config
        self.platforms = config.get("platforms", ["splunk", "elasticsearch"])
        self.evaluate_sigma = config.get("evaluate_sigma", True)
        self.evaluate_platforms = config.get("evaluate_platforms", True)
        self.enable_syntactic_validation = config.get("syntactic_validation", True)
    
    def _initialize_metrics(self) -> None:
        """Initialize RuleGen-specific metrics"""
        
        # 1. Correctness Metrics
        self.metrics.extend([
            BenchmarkMetric(
                name="sigma_completeness",
                category=MetricCategory.CORRECTNESS,
                description="Sigma rule has all required fields and proper structure",
                weight=2.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="detection_logic_correctness",
                category=MetricCategory.CORRECTNESS,
                description="Detection logic correctly identifies the TTP",
                weight=3.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="platform_syntax_correctness",
                category=MetricCategory.CORRECTNESS,
                description="Platform-specific queries have valid syntax",
                weight=2.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="field_mapping_accuracy",
                category=MetricCategory.CORRECTNESS,
                description="Field mappings are accurate for target platforms",
                weight=2.0,
                max_score=10.0
            )
        ])
        
        # 2. Quality Metrics
        self.metrics.extend([
            BenchmarkMetric(
                name="detection_specificity",
                category=MetricCategory.QUALITY,
                description="Rule is specific enough to minimize false positives",
                weight=3.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="detection_sensitivity",
                category=MetricCategory.QUALITY,
                description="Rule is sensitive enough to catch variations",
                weight=2.5,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="metadata_richness",
                category=MetricCategory.QUALITY,
                description="Rule includes comprehensive metadata (references, tags, etc.)",
                weight=1.5,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="optimization_level",
                category=MetricCategory.QUALITY,
                description="Rule is optimized for performance",
                weight=1.5,
                max_score=10.0
            )
        ])
        
        # 3. Effectiveness Metrics
        self.metrics.extend([
            BenchmarkMetric(
                name="attack_coverage",
                category=MetricCategory.EFFECTIVENESS,
                description="Rule covers relevant attack techniques and variations",
                weight=3.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="false_positive_resistance",
                category=MetricCategory.EFFECTIVENESS,
                description="Rule includes filters to reduce false positives",
                weight=2.5,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="contextual_awareness",
                category=MetricCategory.EFFECTIVENESS,
                description="Rule considers threat actor TTPs and campaign context",
                weight=2.0,
                max_score=10.0
            )
        ])
        
        # 4. Realism Metrics
        self.metrics.extend([
            BenchmarkMetric(
                name="operational_deployability",
                category=MetricCategory.REALISM,
                description="Rule is ready for deployment in production SIEM",
                weight=2.5,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="performance_efficiency",
                category=MetricCategory.REALISM,
                description="Rule query is efficient and won't overload SIEM",
                weight=2.0,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="analyst_actionability",
                category=MetricCategory.REALISM,
                description="Alerts from this rule provide actionable information",
                weight=2.0,
                max_score=10.0
            )
        ])
        
        # 5. Detectability Metrics
        self.metrics.extend([
            BenchmarkMetric(
                name="evasion_resistance",
                category=MetricCategory.DETECTABILITY,
                description="Rule is robust against common evasion techniques",
                weight=2.5,
                max_score=10.0
            ),
            BenchmarkMetric(
                name="multi_stage_detection",
                category=MetricCategory.DETECTABILITY,
                description="Rule can detect attack at multiple stages",
                weight=2.0,
                max_score=10.0
            )
        ])
    
    async def evaluate_item(self, item: Dict[str, Any]) -> BenchmarkResult:
        """
        Evaluate a single rule generation result.
        
        Args:
            item: Rule generation result from RuleGen agent
            
        Returns:
            BenchmarkResult with detailed evaluation
        """
        print(f"\n🔍 Evaluating rule: {item.get('attack_id', 'UNKNOWN')}")
        
        metric_results = []
        
        # Extract rule components
        sigma_rule = item.get("sigma_rule", {})
        platform_rules = item.get("platform_rules", {})
        ttp_info = {
            "attack_id": item.get("attack_id"),
            "technique_name": item.get("technique_name"),
            "tactic": item.get("tactic"),
            "confidence_score": item.get("confidence_score")
        }
        
        # 1. Evaluate Sigma rule (if enabled)
        if self.evaluate_sigma and sigma_rule:
            sigma_results = await self._evaluate_sigma_rule(sigma_rule, ttp_info)
            metric_results.extend(sigma_results)
        
        # 2. Evaluate platform rules (if enabled)
        if self.evaluate_platforms and platform_rules:
            platform_results = await self._evaluate_platform_rules(
                platform_rules, sigma_rule, ttp_info
            )
            metric_results.extend(platform_results)
        
        # 3. Syntactic validation (if enabled)
        if self.enable_syntactic_validation:
            syntax_results = self._validate_syntax(platform_rules)
            metric_results.extend(syntax_results)
        
        # Calculate scores
        overall_score = self.calculate_overall_score(metric_results)
        category_scores = self.calculate_category_scores(metric_results)
        
        # Generate summary
        summary = self._generate_summary(
            item, overall_score, category_scores, metric_results
        )
        
        # Create result
        result = BenchmarkResult(
            benchmark_id=self.benchmark_id,
            item_id=item.get("ttp_id", "unknown"),
            item_type="detection_rule",
            overall_score=overall_score,
            category_scores=category_scores,
            metric_results=metric_results,
            summary=summary,
            metadata={
                "attack_id": item.get("attack_id"),
                "technique_name": item.get("technique_name"),
                "tactic": item.get("tactic"),
                "platforms_evaluated": list(platform_rules.keys()),
                "llm_generated": item.get("metadata", {}).get("llm_generated", False)
            }
        )
        
        print(f"   ✓ Score: {overall_score:.2f}/1.0")
        
        return result
    
    async def _evaluate_sigma_rule(
        self, 
        sigma_rule: Dict[str, Any],
        ttp_info: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Evaluate Sigma rule quality using LLM Judge"""
        
        results = []
        
        if not self.llm_judge:
            return self._fallback_sigma_evaluation(sigma_rule)
        
        # Build evaluation criteria
        criteria = [
            {
                "name": "sigma_completeness",
                "description": "Rule has all required fields (title, id, status, description, references, author, date, tags, logsource, detection, falsepositives, level)",
                "weight": 2.0
            },
            {
                "name": "detection_logic_correctness",
                "description": f"Detection logic correctly identifies {ttp_info['attack_id']} - {ttp_info['technique_name']} with appropriate selection criteria and conditions",
                "weight": 3.0
            },
            {
                "name": "detection_specificity",
                "description": "Rule is specific enough to minimize false positives, using exact matches where possible and appropriate filters",
                "weight": 3.0
            },
            {
                "name": "detection_sensitivity",
                "description": "Rule is broad enough to catch variations and evasion attempts while maintaining accuracy",
                "weight": 2.5
            },
            {
                "name": "metadata_richness",
                "description": "Rule includes comprehensive metadata: MITRE tags, threat actor info, campaign context, tools, references",
                "weight": 1.5
            }
        ]
        
        # Context for evaluation
        context = {
            "ttp": ttp_info,
            "mitre_reference": f"https://attack.mitre.org/techniques/{ttp_info['attack_id']}/",
            "evaluation_focus": "Detection quality for real-world threat hunting"
        }
        
        try:
            # Call LLM Judge
            evaluation = await self.llm_judge.evaluate(
                item=sigma_rule,
                criteria=criteria,
                context=context
            )
            
            # Parse results
            for eval_item in evaluation.get("evaluations", []):
                metric = self.get_metric_by_name(eval_item["criterion"])
                if metric:
                    score = eval_item["score"]
                    normalized = metric.normalize_score(score)
                    
                    results.append(EvaluationResult(
                        metric_name=eval_item["criterion"],
                        score=score,
                        normalized_score=normalized,
                        explanation=eval_item.get("explanation", ""),
                        confidence=eval_item.get("confidence", 0.8),
                        metadata={
                            "strengths": eval_item.get("strengths", []),
                            "weaknesses": eval_item.get("weaknesses", [])
                        }
                    ))
            
        except Exception as e:
            print(f"   ⚠️ LLM evaluation failed: {e}")
            results = self._fallback_sigma_evaluation(sigma_rule)
        
        return results
    
    def _fallback_sigma_evaluation(
        self, 
        sigma_rule: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Fallback heuristic evaluation when LLM is unavailable"""
        
        results = []
        
        # 1. Completeness check
        required_fields = [
            "title", "id", "status", "description", "references",
            "author", "date", "tags", "logsource", "detection",
            "falsepositives", "level"
        ]
        present = sum(1 for field in required_fields if sigma_rule.get(field))
        completeness_score = (present / len(required_fields)) * 10
        
        metric = self.get_metric_by_name("sigma_completeness")
        results.append(EvaluationResult(
            metric_name="sigma_completeness",
            score=completeness_score,
            normalized_score=metric.normalize_score(completeness_score),
            explanation=f"{present}/{len(required_fields)} required fields present",
            confidence=1.0
        ))
        
        # 2. Detection logic check
        detection = sigma_rule.get("detection", {})
        has_selection = bool(detection.get("selection"))
        has_condition = bool(detection.get("condition"))
        has_filter = any("filter" in k for k in detection.keys())
        
        logic_score = (
            (5 if has_selection else 0) +
            (3 if has_condition else 0) +
            (2 if has_filter else 0)
        )
        
        metric = self.get_metric_by_name("detection_logic_correctness")
        results.append(EvaluationResult(
            metric_name="detection_logic_correctness",
            score=logic_score,
            normalized_score=metric.normalize_score(logic_score),
            explanation=f"Selection: {has_selection}, Condition: {has_condition}, Filter: {has_filter}",
            confidence=0.7
        ))
        
        # 3. Metadata richness
        metadata = sigma_rule.get("metadata", {})
        has_threat_actor = bool(metadata.get("threat_actor"))
        has_tools = bool(metadata.get("tools"))
        has_campaign = bool(metadata.get("campaign"))
        has_refs = len(sigma_rule.get("references", [])) > 0
        
        metadata_score = (
            (3 if has_threat_actor else 0) +
            (2 if has_tools else 0) +
            (2 if has_campaign else 0) +
            (3 if has_refs else 0)
        )
        
        metric = self.get_metric_by_name("metadata_richness")
        results.append(EvaluationResult(
            metric_name="metadata_richness",
            score=metadata_score,
            normalized_score=metric.normalize_score(metadata_score),
            explanation=f"Threat actor: {has_threat_actor}, Tools: {has_tools}, Campaign: {has_campaign}, Refs: {has_refs}",
            confidence=1.0
        ))
        
        return results
    
    async def _evaluate_platform_rules(
        self,
        platform_rules: Dict[str, Any],
        sigma_rule: Dict[str, Any],
        ttp_info: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Evaluate platform-specific rule conversions"""
        
        results = []
        
        for platform, rule_data in platform_rules.items():
            if rule_data.get("status") != "success":
                continue
            
            rule = rule_data.get("rule", {})
            query = rule.get("query")
            
            if not query:
                continue
            
            # Evaluate using LLM Judge if available
            if self.llm_judge:
                platform_results = await self._evaluate_platform_query_llm(
                    platform, query, sigma_rule, ttp_info
                )
                results.extend(platform_results)
            else:
                # Fallback heuristics
                platform_results = self._evaluate_platform_query_heuristic(
                    platform, query, rule_data
                )
                results.extend(platform_results)
        
        return results
    
    async def _evaluate_platform_query_llm(
        self,
        platform: str,
        query: Any,
        sigma_rule: Dict[str, Any],
        ttp_info: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Evaluate platform query using LLM"""
        
        criteria = [
            {
                "name": "platform_syntax_correctness",
                "description": f"Query uses correct {platform.upper()} syntax and will execute without errors",
                "weight": 2.0
            },
            {
                "name": "field_mapping_accuracy",
                "description": f"Field mappings from Sigma to {platform.upper()} are accurate and follow best practices",
                "weight": 2.0
            },
            {
                "name": "performance_efficiency",
                "description": "Query is optimized for performance and won't cause SIEM overload",
                "weight": 2.0
            }
        ]
        
        context = {
            "platform": platform,
            "sigma_rule_title": sigma_rule.get("title"),
            "ttp": ttp_info
        }
        
        try:
            evaluation = await self.llm_judge.evaluate(
                item={"query": query, "platform": platform},
                criteria=criteria,
                context=context
            )
            
            results = []
            for eval_item in evaluation.get("evaluations", []):
                metric = self.get_metric_by_name(eval_item["criterion"])
                if metric:
                    score = eval_item["score"]
                    normalized = metric.normalize_score(score)
                    
                    results.append(EvaluationResult(
                        metric_name=eval_item["criterion"],
                        score=score,
                        normalized_score=normalized,
                        explanation=f"[{platform.upper()}] {eval_item.get('explanation', '')}",
                        confidence=eval_item.get("confidence", 0.8),
                        metadata={"platform": platform}
                    ))
            
            return results
            
        except Exception as e:
            print(f"   ⚠️ LLM platform evaluation failed for {platform}: {e}")
            return []
    
    def _evaluate_platform_query_heuristic(
        self,
        platform: str,
        query: Any,
        rule_data: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Heuristic evaluation of platform query"""
        
        results = []
        
        # Basic syntax check
        is_validated = rule_data.get("validated", False)
        syntax_score = 10.0 if is_validated else 5.0
        
        metric = self.get_metric_by_name("platform_syntax_correctness")
        results.append(EvaluationResult(
            metric_name="platform_syntax_correctness",
            score=syntax_score,
            normalized_score=metric.normalize_score(syntax_score),
            explanation=f"[{platform.upper()}] Validated: {is_validated}",
            confidence=0.8 if is_validated else 0.5,
            metadata={"platform": platform}
        ))
        
        return results
    
    def _validate_syntax(
        self, 
        platform_rules: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Perform syntactic validation of platform rules"""
        
        results = []
        
        for platform, rule_data in platform_rules.items():
            if rule_data.get("status") != "success":
                continue
            
            is_validated = rule_data.get("validated", False)
            
            # Syntax validation score
            if is_validated:
                score = 10.0
                explanation = f"{platform.upper()} query passed validation"
            else:
                score = 0.0
                explanation = f"{platform.upper()} query failed validation"
            
            metric = self.get_metric_by_name("platform_syntax_correctness")
            if metric:
                results.append(EvaluationResult(
                    metric_name="platform_syntax_correctness",
                    score=score,
                    normalized_score=metric.normalize_score(score),
                    explanation=explanation,
                    confidence=1.0,
                    metadata={"platform": platform, "validation": "syntactic"}
                ))
        
        return results
    
    def _generate_summary(
        self,
        item: Dict[str, Any],
        overall_score: float,
        category_scores: Dict[str, float],
        metric_results: List[EvaluationResult]
    ) -> str:
        """Generate human-readable summary"""
        
        attack_id = item.get("attack_id", "UNKNOWN")
        technique = item.get("technique_name", "Unknown Technique")
        
        # Score grade
        if overall_score >= 0.9:
            grade = "Excellent"
        elif overall_score >= 0.8:
            grade = "Good"
        elif overall_score >= 0.7:
            grade = "Fair"
        elif overall_score >= 0.6:
            grade = "Below Average"
        else:
            grade = "Poor"
        
        # Category highlights
        best_category = max(category_scores.items(), key=lambda x: x[1])
        worst_category = min(category_scores.items(), key=lambda x: x[1])
        
        summary_parts = [
            f"Rule for {attack_id} ({technique}) scored {overall_score:.2f}/1.0 ({grade}).",
            f"Best performance in {best_category[0]} ({best_category[1]:.2f}).",
            f"Needs improvement in {worst_category[0]} ({worst_category[1]:.2f})."
        ]
        
        # Add specific issues
        low_scoring = [r for r in metric_results if r.normalized_score < 0.6]
        if low_scoring:
            issues = [r.metric_name for r in low_scoring[:3]]
            summary_parts.append(f"Issues found in: {', '.join(issues)}")
        
        return " ".join(summary_parts)
    
    def export_results_with_recommendations(
        self, 
        filepath: str
    ) -> None:
        """Export results with actionable recommendations"""
        
        output = {
            "benchmark_id": self.benchmark_id,
            "timestamp": datetime.utcnow().isoformat(),
            "config": self.config,
            "statistics": self.get_statistics(),
            "results": [r.to_dict() for r in self.results],
            "recommendations": self._generate_aggregate_recommendations()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
    
    def _generate_aggregate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations across all evaluated rules"""
        
        recommendations = []
        
        stats = self.get_statistics()
        metric_avgs = stats.get("metric_averages", {})
        
        # Check for common issues
        for metric_name, avg_score in metric_avgs.items():
            if avg_score < 0.6:
                recommendations.append({
                    "priority": "high",
                    "metric": metric_name,
                    "issue": f"Low average score ({avg_score:.2f}) across all rules",
                    "recommendation": self._get_metric_recommendation(metric_name)
                })
            elif avg_score < 0.7:
                recommendations.append({
                    "priority": "medium",
                    "metric": metric_name,
                    "issue": f"Below target score ({avg_score:.2f})",
                    "recommendation": self._get_metric_recommendation(metric_name)
                })
        
        return recommendations
    
    def _get_metric_recommendation(self, metric_name: str) -> str:
        """Get specific recommendation for a metric"""
        
        recommendations = {
            "sigma_completeness": "Ensure all required Sigma fields are populated in prompts",
            "detection_logic_correctness": "Improve LLM prompts to generate more accurate detection conditions",
            "platform_syntax_correctness": "Review and fix platform converters for syntax errors",
            "detection_specificity": "Add more filters and exclusions to reduce false positives",
            "metadata_richness": "Include more context (threat actor, campaign, tools) in rule generation",
            "performance_efficiency": "Optimize queries to use indexed fields and avoid wildcards",
            "false_positive_resistance": "Implement better filter logic in Sigma rules"
        }
        
        return recommendations.get(
            metric_name, 
            "Review and improve rule generation logic"
        )