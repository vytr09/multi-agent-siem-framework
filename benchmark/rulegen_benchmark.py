"""
RuleGen Benchmark - benchmark/rulegen_benchmark.py
Complete implementation with ALL 15 metrics
Evaluates detection rule generation quality using LLM-as-Judge
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from dotenv import load_dotenv
load_dotenv()

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
    
    Evaluates ALL 15 metrics:
    - Correctness (4): sigma_completeness, detection_logic_correctness, 
                       platform_syntax_correctness, field_mapping_accuracy
    - Quality (4): detection_specificity, detection_sensitivity, 
                   metadata_richness, optimization_level
    - Effectiveness (3): attack_coverage, false_positive_resistance, 
                         contextual_awareness
    - Realism (3): operational_deployability, performance_efficiency, 
                   analyst_actionability
    - Detectability (2): evasion_resistance, multi_stage_detection
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Initialize LLM Judge if enabled
        if self.use_llm_judge:
            self.llm_judge = LLMJudge(self.llm_judge_config)
            # ADD THIS LINE:
            self.llm_batch_size = self.llm_judge_config.get("batch_size", 4)
        else:
            self.llm_judge = None
            # ADD THIS LINE:
            self.llm_batch_size = 4
        
        # RuleGen-specific config
        self.platforms = config.get("platforms", ["splunk", "elasticsearch"])
        self.evaluate_sigma = config.get("evaluate_sigma", True)
        self.evaluate_platforms = config.get("evaluate_platforms", True)
        self.enable_syntactic_validation = config.get("syntactic_validation", True)
    
    def _initialize_metrics(self) -> None:
        """Initialize ALL 15 RuleGen-specific metrics"""
        
        # ============================================================
        # 1. CORRECTNESS METRICS (4 metrics)
        # ============================================================
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
        
        # ============================================================
        # 2. QUALITY METRICS (4 metrics)
        # ============================================================
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
        
        # ============================================================
        # 3. EFFECTIVENESS METRICS (3 metrics)
        # ============================================================
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
        
        # ============================================================
        # 4. REALISM METRICS (3 metrics)
        # ============================================================
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
        
        # ============================================================
        # 5. DETECTABILITY METRICS (2 metrics)
        # ============================================================
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
        
        # 1. Evaluate Sigma rule (if enabled) - 11 metrics
        if self.evaluate_sigma and sigma_rule:
            sigma_results = await self._evaluate_sigma_rule(sigma_rule, ttp_info)
            metric_results.extend(sigma_results)
        
        # 2. Evaluate platform rules (if enabled) - 3 metrics per platform
        if self.evaluate_platforms and platform_rules:
            platform_results = await self._evaluate_platform_rules(
                platform_rules, sigma_rule, ttp_info
            )
            metric_results.extend(platform_results)
        
        # 3. Syntactic validation (if enabled) - additional validation
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
        """
        Evaluate Sigma rule quality using LLM Judge
        Evaluates ALL 11 Sigma-level metrics
        """
        
        results = []
        
        if not self.llm_judge:
            return self._fallback_sigma_evaluation(sigma_rule)
        
        # ============================================================
        # ALL 11 SIGMA-LEVEL METRICS WITH DETAILED PROMPTS
        # ============================================================
        criteria = [
            # CORRECTNESS (2 metrics)
            {
                "name": "sigma_completeness",
                "description": (
                    "Rule has all required Sigma fields: title, id, status, description, "
                    "references, author, date, tags (including MITRE ATT&CK), logsource "
                    "(product, category, service), detection (selection, condition), "
                    "falsepositives, level. Check if each field is properly populated "
                    "with meaningful content, not just placeholders."
                ),
                "weight": 2.0
            },
            {
                "name": "detection_logic_correctness",
                "description": (
                    f"Detection logic correctly identifies {ttp_info['attack_id']} - {ttp_info['technique_name']}. "
                    f"Evaluate: (1) Selection criteria accurately match the TTP behavior and indicators, "
                    f"(2) Condition logic is sound and not overly complex or redundant, "
                    f"(3) Field names are standard Sigma fields (not made-up or platform-specific), "
                    f"(4) Logic would realistically trigger on actual attacks but not benign activity, "
                    f"(5) Filters appropriately exclude false positives without missing attacks."
                ),
                "weight": 3.0
            },
            
            # QUALITY (4 metrics)
            {
                "name": "detection_specificity",
                "description": (
                    "Rule is specific enough to minimize false positives in production. "
                    "Evaluate: (1) Uses exact matches where possible, not just wildcards everywhere, "
                    "(2) Includes appropriate filters to exclude benign activity and legitimate tools, "
                    "(3) Multiple conditions combined with AND/OR logic for precision, "
                    "(4) Considers legitimate use cases (admin tools, system processes) and excludes them, "
                    "(5) Not overly broad that it catches normal business operations, "
                    "(6) Includes context like parent process, user, or path to improve specificity."
                ),
                "weight": 3.0
            },
            {
                "name": "detection_sensitivity",
                "description": (
                    "Rule is sensitive enough to catch attack variations and evasion attempts. "
                    "Evaluate: (1) Covers multiple indicators of the same attack technique, "
                    "(2) Uses wildcards or regex appropriately to catch variations (encoded commands, different paths), "
                    "(3) Considers different tools and techniques that achieve the same TTP, "
                    "(4) Not so narrow that simple evasions (renaming, obfuscation) bypass it, "
                    "(5) Includes case-insensitive matching where needed (Windows paths, commands), "
                    "(6) Detects both common and advanced variants of the technique."
                ),
                "weight": 2.5
            },
            {
                "name": "metadata_richness",
                "description": (
                    "Rule includes comprehensive metadata for context and investigation. "
                    "Evaluate: (1) MITRE ATT&CK tags present and correct (technique, tactic, sub-technique), "
                    "(2) References to authoritative sources (MITRE, vendor blogs, security research, CVEs), "
                    "(3) Threat actor information if known (APT groups known to use this TTP), "
                    "(4) Campaign names or operation names if applicable, "
                    "(5) Tools and malware families associated with the technique, "
                    "(6) Clear and detailed description explaining what the rule detects and why, "
                    "(7) False positive guidance is helpful, specific, and actionable for analysts."
                ),
                "weight": 1.5
            },
            {
                "name": "optimization_level",
                "description": (
                    "Rule is optimized for SIEM performance and efficient execution. "
                    "Evaluate: (1) Uses indexed fields first (EventID, EventCode, Image, CommandLine), "
                    "(2) Avoids leading wildcards (e.g., '*powershell' is bad, 'powershell*' or '*powershell.exe' is OK), "
                    "(3) Most specific and restrictive filters come first in detection logic, "
                    "(4) Not using overly complex or nested regex that slows query execution, "
                    "(5) Appropriate use of 'contains' vs 'startswith' vs 'endswith' operators, "
                    "(6) Logsource is specific enough to limit the volume of data to scan, "
                    "(7) Avoids unnecessary OR conditions that can be combined."
                ),
                "weight": 1.5
            },
            
            # EFFECTIVENESS (3 metrics)
            {
                "name": "attack_coverage",
                "description": (
                    f"Rule covers relevant attack techniques and variations for {ttp_info['technique_name']}. "
                    f"Evaluate: (1) Covers the main attack vectors and methods for this TTP, "
                    f"(2) Includes sub-techniques if applicable (e.g., T1059.001, T1059.003), "
                    f"(3) Detects both common/basic and advanced/sophisticated variants, "
                    f"(4) Considers different tools and frameworks (Cobalt Strike, Metasploit, Empire, custom tools), "
                    f"(5) Multi-stage attacks are considered (not just initial execution but follow-on actions), "
                    f"(6) Covers both automated and manual attacker techniques."
                ),
                "weight": 3.0
            },
            {
                "name": "false_positive_resistance",
                "description": (
                    "Rule includes effective filters and exclusions to reduce false positives. "
                    "Evaluate: (1) Filters exclude known legitimate processes, users, or paths (system accounts, admin tools), "
                    "(2) Time-based or frequency-based logic where appropriate (not single event but pattern), "
                    "(3) Parent-child process relationships considered (suspicious parent spawning child), "
                    "(4) Whitelisting of admin tools when used from legitimate paths or by authorized users, "
                    "(5) False positive guidance in metadata is specific and actionable (not generic advice), "
                    "(6) Rule has been tuned based on common FP scenarios."
                ),
                "weight": 2.5
            },
            {
                "name": "contextual_awareness",
                "description": (
                    f"Rule demonstrates awareness of threat actor TTPs and campaign context. "
                    f"Evaluate: (1) Detection logic aligns with how real threat actors actually use {ttp_info['technique_name']}, "
                    f"(2) Considers threat actor preferences (specific tools, parameters, timing, targets), "
                    f"(3) Metadata references specific campaigns, APT groups, or operations, "
                    f"(4) Detection patterns match real-world attack chains and kill chain stages, "
                    f"(5) Not just textbook examples but incorporates operational intelligence from threat reports, "
                    f"(6) Considers geographic or industry-specific targeting patterns if relevant."
                ),
                "weight": 2.0
            },
            
            # REALISM (2 metrics - performance_efficiency evaluated at platform level)
            {
                "name": "operational_deployability",
                "description": (
                    "Rule is ready for immediate deployment in production SIEM environment. "
                    "Evaluate: (1) No syntax errors or undefined fields in the Sigma rule, "
                    "(2) Logsource is realistic and available in most enterprise environments, "
                    "(3) Detection logic has been tested or validated (not experimental), "
                    "(4) Severity level is appropriate for SOC triage and prioritization, "
                    "(5) False positive rate is acceptable for production (not excessive alerts), "
                    "(6) Alert fatigue is minimized through good specificity and appropriate severity, "
                    "(7) Rule doesn't require exotic log sources or custom configurations."
                ),
                "weight": 2.5
            },
            {
                "name": "analyst_actionability",
                "description": (
                    "Alerts from this rule provide actionable information for security analysts. "
                    "Evaluate: (1) Rule title clearly and concisely describes what was detected, "
                    "(2) Description provides sufficient context for investigation and response, "
                    "(3) Fields in detection are useful for pivoting and investigation (process, user, IP, hash), "
                    "(4) References guide next steps in investigation and remediation, "
                    "(5) Severity level helps analysts prioritize their response appropriately, "
                    "(6) False positive guidance helps analysts tune the rule for their environment, "
                    "(7) Alert provides enough information to make a quick triage decision."
                ),
                "weight": 2.0
            },
            
            # DETECTABILITY (2 metrics)
            {
                "name": "evasion_resistance",
                "description": (
                    "Rule is robust against common attacker evasion techniques. "
                    "Evaluate: (1) Not easily bypassed by simply renaming executables or files, "
                    "(2) Detects behavior patterns and relationships, not just static indicators, "
                    "(3) Uses multiple detection points (process creation + network + file activity), "
                    "(4) Considers obfuscation attempts (encoding, encryption, compression), "
                    "(5) Not relying solely on command-line arguments (can be hidden or obfuscated), "
                    "(6) Robust against living-off-the-land (LOLBin) evasions and legitimate tool abuse, "
                    "(7) Detects the technique regardless of the specific tool used."
                ),
                "weight": 2.5
            },
            {
                "name": "multi_stage_detection",
                "description": (
                    f"Rule can detect {ttp_info['technique_name']} at multiple stages of the attack lifecycle. "
                    f"Evaluate: (1) Detects initial execution or access of the technique, "
                    f"(2) Detects persistence mechanisms if the TTP is used for persistence, "
                    f"(3) Detects lateral movement activities if applicable to this TTP, "
                    f"(4) Detects data collection, exfiltration, or impact activities, "
                    f"(5) Logic can correlate across multiple related events or stages, "
                    f"(6) Not just single-event detection but understands attack sequence awareness, "
                    f"(7) Can detect both atomic indicators and behavioral chains."
                ),
                "weight": 2.0
            }
        ]
        
        # Context for evaluation
        context = {
            "ttp": ttp_info,
            "mitre_reference": f"https://attack.mitre.org/techniques/{ttp_info['attack_id']}/",
            "evaluation_focus": "Production-ready detection for real-world threat hunting and incident response",
            "sigma_rule_structure": {
                "title": sigma_rule.get("title"),
                "logsource": sigma_rule.get("logsource"),
                "detection": sigma_rule.get("detection"),
                "level": sigma_rule.get("level"),
                "tags": sigma_rule.get("tags", [])
            }
        }
        
        try:
            # Call LLM Judge for comprehensive Sigma evaluation
            evaluation = await self.llm_judge.evaluate(
                item=sigma_rule,
                criteria=criteria,
                context=context,
                batch_size=self.llm_batch_size  # ADD THIS LINE
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
            print(f"   ⚠️ LLM Sigma evaluation failed: {e}")
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
        """
        Evaluate platform-specific rule conversions
        Evaluates 3 metrics per platform: syntax, field_mapping, performance
        """
        
        results = []
        
        for platform, rule_data in platform_rules.items():
            if rule_data.get("status") != "success":
                continue
            
            rule = rule_data.get("rule", {})
            query = rule.get("query")
            
            if not query:
                continue
            
            # Platform-specific syntax guides
            syntax_guides = {
                "splunk": (
                    "Splunk SPL syntax: uses pipes (|) for commands, "
                    "field=value or field IN (...) for filtering, "
                    "index and sourcetype for data source specification, "
                    "wildcard * for pattern matching, "
                    "stats/table/chart for aggregation and display"
                ),
                "elasticsearch": (
                    "Elasticsearch KQL/Lucene syntax: uses field:value notation, "
                    "boolean operators (AND, OR, NOT) for logic, "
                    "wildcards (*) for pattern matching, "
                    "parentheses for grouping expressions, "
                    "quotes for exact phrase matching"
                ),
                "qradar": (
                    "QRadar AQL syntax: SQL-like with SELECT/FROM/WHERE, "
                    "LIKE operator for pattern matching, "
                    "wildcards (%), "
                    "AND/OR for boolean logic"
                ),
                "sentinel": (
                    "Azure Sentinel KQL: table | where field == value, "
                    "operators (and, or, not, contains, startswith), "
                    "pipe (|) for chaining operations"
                )
            }
            syntax_guide = syntax_guides.get(
                platform.lower(), 
                f"{platform} query syntax with appropriate operators and structure"
            )
            
            # Evaluate using LLM Judge if available
            if self.llm_judge:
                criteria = [
                    {
                        "name": "platform_syntax_correctness",
                        "description": (
                            f"Query uses correct {platform.upper()} syntax and will execute without errors. "
                            f"{syntax_guide}. "
                            f"Evaluate: (1) No syntax errors (missing quotes, brackets, operators), "
                            f"(2) Field names are properly formatted for {platform} data model, "
                            f"(3) Operators and functions are valid for {platform} query language, "
                            f"(4) Special characters are properly escaped or quoted, "
                            f"(5) Query structure follows {platform} best practices and conventions, "
                            f"(6) Parentheses and logic grouping are correct and balanced."
                        ),
                        "weight": 2.0
                    },
                    {
                        "name": "field_mapping_accuracy",
                        "description": (
                            f"Field mappings from Sigma to {platform.upper()} are accurate and follow platform conventions. "
                            f"Evaluate: (1) Sigma fields correctly mapped to {platform} data model and schema, "
                            f"(2) Field names match actual log sources and field names available in {platform}, "
                            f"(3) Data types are compatible (string to string, numeric to numeric, timestamp handling), "
                            f"(4) Nested fields use correct notation (dot notation, brackets, or platform-specific syntax), "
                            f"(5) No unmapped or missing critical fields from the Sigma rule, "
                            f"(6) Field mappings align with standard {platform} security log sources (Sysmon, Windows Security, etc.)."
                        ),
                        "weight": 2.0
                    },
                    {
                        "name": "performance_efficiency",
                        "description": (
                            f"Query is optimized for {platform.upper()} performance and won't cause SIEM overload. "
                            f"Evaluate: (1) Uses indexed fields first for fast filtering (EventID, EventCode, SourceName), "
                            f"(2) Most restrictive and selective filters applied early in the query, "
                            f"(3) Avoids expensive operations (leading wildcards like '*powershell', complex regex, nested queries), "
                            f"(4) Time range is specified to limit the volume of data to scan, "
                            f"(5) Aggregations and statistical operations are efficient and necessary, "
                            f"(6) Query won't cause memory/CPU spikes or timeouts on large datasets, "
                            f"(7) Uses {platform}-specific optimizations (summary indexes in Splunk, data streams in Elasticsearch)."
                        ),
                        "weight": 2.0
                    }
                ]
                
                context = {
                    "platform": platform,
                    "sigma_rule_title": sigma_rule.get("title"),
                    "sigma_detection_logic": sigma_rule.get("detection"),
                    "ttp": ttp_info,
                    "expected_log_source": sigma_rule.get("logsource"),
                    "platform_best_practices": f"Follow {platform} security detection best practices"
                }
                
                try:
                    evaluation = await self.llm_judge.evaluate(
                        item={"query": query, "platform": platform},
                        criteria=criteria,
                        context=context,
                        batch_size=3  # Use smaller batch for platform queries (only 3 criteria)
                    )
                    
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
                                metadata={
                                    "platform": platform,
                                    "strengths": eval_item.get("strengths", []),
                                    "weaknesses": eval_item.get("weaknesses", [])
                                }
                            ))
                
                except Exception as e:
                    print(f"   ⚠️ LLM platform evaluation failed for {platform}: {e}")
                    # Fallback to heuristic if LLM fails
                    platform_results = self._evaluate_platform_query_heuristic(
                        platform, query, rule_data
                    )
                    results.extend(platform_results)
            else:
                # Fallback heuristics when LLM is not available
                platform_results = self._evaluate_platform_query_heuristic(
                    platform, query, rule_data
                )
                results.extend(platform_results)
        
        return results
    
    def _evaluate_platform_query_heuristic(
        self,
        platform: str,
        query: Any,
        rule_data: Dict[str, Any]
    ) -> List[EvaluationResult]:
        """Heuristic evaluation of platform query when LLM is unavailable"""
        
        results = []
        
        # Basic syntax check
        is_validated = rule_data.get("validated", False)
        syntax_score = 10.0 if is_validated else 5.0
        
        metric = self.get_metric_by_name("platform_syntax_correctness")
        if metric:
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
        """Generate human-readable summary of evaluation results"""
        
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
        if category_scores:
            best_category = max(category_scores.items(), key=lambda x: x[1])
            worst_category = min(category_scores.items(), key=lambda x: x[1])
            
            summary_parts = [
                f"Rule for {attack_id} ({technique}) scored {overall_score:.2f}/1.0 ({grade}).",
                f"Best performance in {best_category[0]} ({best_category[1]:.2f}).",
                f"Needs improvement in {worst_category[0]} ({worst_category[1]:.2f})."
            ]
        else:
            summary_parts = [
                f"Rule for {attack_id} ({technique}) scored {overall_score:.2f}/1.0 ({grade})."
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
        
        print(f"\n📁 Results exported to: {filepath}")
    
    def _generate_aggregate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate actionable recommendations across all evaluated rules"""
        
        recommendations = []
        
        stats = self.get_statistics()
        metric_avgs = stats.get("metric_averages", {})
        
        # Check for common issues across all rules
        for metric_name, avg_score in metric_avgs.items():
            if avg_score < 0.6:
                recommendations.append({
                    "priority": "high",
                    "metric": metric_name,
                    "issue": f"Low average score ({avg_score:.2f}) across all rules",
                    "recommendation": self._get_metric_recommendation(metric_name),
                    "affected_rules": self._get_affected_rules(metric_name, threshold=0.6)
                })
            elif avg_score < 0.7:
                recommendations.append({
                    "priority": "medium",
                    "metric": metric_name,
                    "issue": f"Below target score ({avg_score:.2f})",
                    "recommendation": self._get_metric_recommendation(metric_name),
                    "affected_rules": self._get_affected_rules(metric_name, threshold=0.7)
                })
        
        # Add category-level recommendations
        category_avgs = stats.get("category_averages", {})
        for category, avg_score in category_avgs.items():
            if avg_score < 0.7:
                recommendations.append({
                    "priority": "high" if avg_score < 0.6 else "medium",
                    "category": category,
                    "issue": f"Category '{category}' needs improvement ({avg_score:.2f})",
                    "recommendation": self._get_category_recommendation(category)
                })
        
        return recommendations
    
    def _get_affected_rules(self, metric_name: str, threshold: float) -> List[str]:
        """Get list of rules affected by low metric score"""
        affected = []
        for result in self.results:
            for metric_result in result.metric_results:
                if (metric_result.metric_name == metric_name and 
                    metric_result.normalized_score < threshold):
                    attack_id = result.metadata.get("attack_id", "unknown")
                    affected.append(attack_id)
                    break
        return affected
    
    def _get_metric_recommendation(self, metric_name: str) -> str:
        """Get specific recommendation for a metric"""
        
        recommendations = {
            # Correctness
            "sigma_completeness": (
                "Ensure all required Sigma fields are populated in the rule generation prompt. "
                "Include templates or schemas to guide LLM output. Validate output against Sigma specification."
            ),
            "detection_logic_correctness": (
                "Improve LLM prompts to generate more accurate detection conditions. "
                "Provide examples of correct detection logic. Include MITRE ATT&CK technique descriptions in prompts. "
                "Validate selection criteria against known attack indicators."
            ),
            "platform_syntax_correctness": (
                "Review and fix platform converters for syntax errors. "
                "Test queries against actual SIEM instances. Use platform-specific validators. "
                "Consider using platform-specific libraries for query generation."
            ),
            "field_mapping_accuracy": (
                "Validate field mappings against platform schemas. "
                "Use standardized field mapping tables (ECS, OSSEM). "
                "Test mapped queries with sample data to ensure fields exist."
            ),
            
            # Quality
            "detection_specificity": (
                "Add more filters and exclusions to reduce false positives. "
                "Include context (parent process, user, path) in detection logic. "
                "Provide legitimate use case examples to the LLM for exclusion. "
                "Use exact matches instead of wildcards where possible."
            ),
            "detection_sensitivity": (
                "Expand detection criteria to cover more attack variations. "
                "Include multiple tools and techniques for the same TTP. "
                "Add case-insensitive matching and wildcards for variations. "
                "Consider obfuscation and evasion techniques in detection logic."
            ),
            "metadata_richness": (
                "Include more context in rule generation: threat actor, campaign, tools, references. "
                "Add MITRE ATT&CK tags and technique descriptions. "
                "Link to authoritative sources (MITRE, vendor blogs, research papers). "
                "Provide specific false positive guidance and tuning recommendations."
            ),
            "optimization_level": (
                "Optimize queries to use indexed fields first. "
                "Avoid leading wildcards and complex regex. "
                "Place most restrictive filters early in query logic. "
                "Specify time ranges to limit data volume. Use platform-specific optimizations."
            ),
            
            # Effectiveness
            "attack_coverage": (
                "Expand rule coverage to include sub-techniques and variations. "
                "Consider different tools and frameworks for the same TTP. "
                "Include both common and advanced attack variants. "
                "Cover multiple stages of the attack lifecycle."
            ),
            "false_positive_resistance": (
                "Implement better filter logic in Sigma rules to exclude benign activity. "
                "Add whitelisting for known legitimate processes and users. "
                "Consider parent-child process relationships. "
                "Provide actionable false positive guidance in metadata."
            ),
            "contextual_awareness": (
                "Incorporate threat intelligence into rule generation. "
                "Align detection logic with known threat actor TTPs. "
                "Reference specific campaigns and APT groups in metadata. "
                "Use operational intelligence from threat reports, not just textbook examples."
            ),
            
            # Realism
            "operational_deployability": (
                "Ensure rules are tested and validated before production deployment. "
                "Use realistic log sources available in most environments. "
                "Set appropriate severity levels for SOC triage. "
                "Minimize alert fatigue through good specificity."
            ),
            "performance_efficiency": (
                "Optimize queries for efficient execution on large datasets. "
                "Use indexed fields and avoid expensive operations. "
                "Test query performance with realistic data volumes. "
                "Consider SIEM resource constraints in query design."
            ),
            "analyst_actionability": (
                "Provide clear, concise rule titles and descriptions. "
                "Include useful fields for investigation and pivoting. "
                "Add references for next steps in investigation. "
                "Ensure alerts provide sufficient context for quick triage decisions."
            ),
            
            # Detectability
            "evasion_resistance": (
                "Design rules to detect behavior patterns, not just static indicators. "
                "Use multiple detection points (process, network, file). "
                "Consider obfuscation and renaming evasions. "
                "Test rules against common evasion techniques."
            ),
            "multi_stage_detection": (
                "Expand detection to cover multiple attack lifecycle stages. "
                "Include correlation across related events. "
                "Detect both atomic indicators and behavioral chains. "
                "Consider persistence, lateral movement, and exfiltration stages."
            )
        }
        
        return recommendations.get(
            metric_name, 
            "Review and improve rule generation logic for this metric. "
            "Analyze low-scoring examples and adjust prompts or validation accordingly."
        )
    
    def _get_category_recommendation(self, category: str) -> str:
        """Get recommendation for an entire category"""
        
        recommendations = {
            "correctness": (
                "Focus on technical accuracy: validate Sigma syntax, detection logic, "
                "and platform query correctness. Use validators and test with real data."
            ),
            "quality": (
                "Improve detection quality: balance specificity and sensitivity, "
                "enrich metadata, optimize for performance. Tune based on production feedback."
            ),
            "effectiveness": (
                "Enhance real-world effectiveness: expand attack coverage, "
                "reduce false positives, incorporate threat intelligence and operational context."
            ),
            "realism": (
                "Ensure production readiness: test deployability, optimize performance, "
                "provide actionable alerts. Consider SOC workflows and analyst needs."
            ),
            "detectability": (
                "Strengthen detection capabilities: improve evasion resistance, "
                "enable multi-stage detection. Test against adversary simulation frameworks."
            )
        }
        
        return recommendations.get(
            category,
            f"Improve overall quality in the '{category}' category by reviewing "
            f"and enhancing relevant metrics."
        )
    
    async def evaluate_batch(
        self, 
        items: List[Dict[str, Any]]
    ) -> List[BenchmarkResult]:
        """
        Evaluate multiple rules in batch
        
        Args:
            items: List of rule generation results
            
        Returns:
            List of BenchmarkResults
        """
        print(f"\n🚀 Evaluating {len(items)} rules...")
        
        for item in items:
            result = await self.evaluate_item(item)
            self.results.append(result)
        
        print(f"\n✅ Evaluation complete: {len(self.results)} rules evaluated")
        
        return self.results
    
    def print_summary_report(self) -> None:
        """Print a comprehensive summary report to console"""
        
        if not self.results:
            print("\n⚠️  No results to report")
            return
        
        stats = self.get_statistics()
        
        print("\n" + "="*80)
        print("📊 RULEGEN BENCHMARK SUMMARY REPORT")
        print("="*80)
        
        # Overall statistics
        print(f"\n📈 Overall Statistics:")
        print(f"   Total Evaluations:     {stats['total_evaluations']}")
        print(f"   Average Score:         {stats['average_score']:.3f}/1.0")
        
        # Score distribution
        print(f"\n📊 Score Distribution:")
        dist = stats.get('score_distribution', {})
        for grade, count in dist.items():
            bar = "█" * int(count * 40 / max(dist.values(), 1))
            print(f"   {grade:20s} {count:2d} {bar}")
        
        # Category averages
        print(f"\n🎯 Category Averages:")
        cat_avgs = stats.get('category_averages', {})
        for category, avg_score in sorted(cat_avgs.items(), key=lambda x: x[1], reverse=True):
            bar_length = int(avg_score * 40)
            bar = "█" * bar_length + "░" * (40 - bar_length)
            print(f"   {category:20s} {avg_score:.3f} [{bar}]")
        
        # Top metrics
        print(f"\n🏆 Top 10 Metrics:")
        metric_avgs = stats.get('metric_averages', {})
        sorted_metrics = sorted(metric_avgs.items(), key=lambda x: x[1], reverse=True)[:10]
        for metric, avg_score in sorted_metrics:
            bar_length = int(avg_score * 40)
            bar = "█" * bar_length + "░" * (40 - bar_length)
            print(f"   {metric:30s} {avg_score:.3f} [{bar}]")
        
        # Top performers
        print(f"\n🥇 Top 3 Rules:")
        top_3 = self.get_top_performers(n=3)
        for i, result in enumerate(top_3, 1):
            attack_id = result.metadata.get('attack_id', 'UNKNOWN')
            technique = result.metadata.get('technique_name', 'Unknown')
            print(f"   {i}. {attack_id:12s} Score: {result.overall_score:.3f} - {technique}")
        
        # Bottom performers
        print(f"\n⚠️  Bottom 3 Rules (Need Improvement):")
        bottom_3 = self.get_bottom_performers(n=3)
        for i, result in enumerate(bottom_3, 1):
            attack_id = result.metadata.get('attack_id', 'UNKNOWN')
            technique = result.metadata.get('technique_name', 'Unknown')
            print(f"   {i}. {attack_id:12s} Score: {result.overall_score:.3f} - {technique}")
        
        # Recommendations
        recommendations = self._generate_aggregate_recommendations()
        if recommendations:
            print(f"\n💡 Top Recommendations:")
            high_priority = [r for r in recommendations if r.get('priority') == 'high'][:3]
            for i, rec in enumerate(high_priority, 1):
                metric = rec.get('metric', rec.get('category', 'unknown'))
                issue = rec.get('issue', '')
                print(f"   {i}. [{metric}] {issue}")
        
        print("\n" + "="*80)


# ============================================================
# CONVENIENCE FUNCTIONS FOR DIRECT USAGE
# ============================================================

async def run_rulegen_benchmark(
    rules_file: str,
    output_file: str = None,
    llm_api_key: str = None,
    platforms: List[str] = None
) -> RuleGenBenchmark:
    """
    Convenience function to run complete RuleGen benchmark
    
    Args:
        rules_file: Path to RuleGen output JSON file
        output_file: Path for results export (optional)
        llm_api_key: Gemini API key (optional, uses env var if not provided)
        platforms: List of platforms to evaluate (default: ["splunk", "elasticsearch"])
        
    Returns:
        RuleGenBenchmark instance with results
    """
    
    # Load rules
    with open(rules_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    rules = data.get("rule_generation_results", [])
    
    # Configure
    config = {
        "platforms": platforms or ["splunk", "elasticsearch"],
        "evaluate_sigma": True,
        "evaluate_platforms": True,
        "syntactic_validation": True,
        "llm_judge": {
            "enabled": True,
            "api_key": llm_api_key,
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3,
            "max_tokens": 4000,
            "batch_size": 4,     # ADD THIS - evaluate 4 criteria per call
            "persona": "expert SIEM engineer and threat detection specialist",
            "detailed_feedback": True,
            "confidence_scores": True
        }
    }
    
    # Initialize and evaluate
    benchmark = RuleGenBenchmark(config)
    await benchmark.evaluate_batch(rules)
    
    # Print summary
    benchmark.print_summary_report()
    
    # Export if requested
    if output_file:
        benchmark.export_results_with_recommendations(output_file)
    
    return benchmark


if __name__ == "__main__":
    """
    Example usage:
    
    python rulegen_benchmark.py
    """
    
    import os
    
    async def main():
        # Example: Run benchmark on RuleGen output
        benchmark = await run_rulegen_benchmark(
            rules_file="data/generated_rules/rulegen_llm_output.json",
            output_file="data/benchmark_results/rulegen_complete_benchmark.json",
            llm_api_key=os.getenv("GEMINI_API_KEY"),
            platforms=["splunk", "elasticsearch"]
        )
        
        # Access results programmatically
        stats = benchmark.get_statistics()
        print(f"\n📊 Final Average Score: {stats['average_score']:.3f}")
    
    # Run
    asyncio.run(main())