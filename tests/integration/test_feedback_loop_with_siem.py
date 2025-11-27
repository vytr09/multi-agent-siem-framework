#!/usr/bin/env python3
"""
Test Feedback Loop WITH SIEM Integration (Full LangChain Stack)
Tests the complete feedback loop using LangChain-powered agents: 
RuleGen (LC) -> AttackGen (LC) -> SIEM Verification -> Evaluator (LC) -> Feedback -> RuleGen (iterative)

Flow:
1. LangChain RuleGen generates detection rules from CTI data
2. LangChain AttackGen generates attack commands for those rules
3. SIEM Integration executes attacks and verifies rule detection
4. LangChain Evaluator calculates:
   - Benchmark metrics (quality, correctness, etc.) via LLM-as-Judge
   - SIEM metrics (F1, Precision, Recall, Accuracy) from detection results
5. Feedback is generated and sent back to RuleGen
6. Loop continues until stopping condition (max iterations or min score threshold)

All agents use LangChain for:
- Structured outputs with Pydantic models
- Better prompt engineering and consistency
- Automatic retries and error handling
- Unified LLM interaction patterns
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from agents.attackgen.langchain_agent import LangChainAttackGenAgent
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent
from agents.evaluator.feedback_manager import FeedbackManager
from core.siem_integration import SIEMIntegrator, DetectionResult
from config.settings import settings


@dataclass
class SIEMMetrics:
    """SIEM-specific detection metrics"""
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    detection_rate: float
    false_positive_rate: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'accuracy': self.accuracy,
            'detection_rate': self.detection_rate,
            'false_positive_rate': self.false_positive_rate
        }


class SIEMMetricsCalculator:
    """Calculate F1, Precision, Recall, Accuracy from SIEM detection results"""
    
    @staticmethod
    def calculate_metrics(detection_results: List[Dict[str, Any]]) -> SIEMMetrics:
        """
        Calculate SIEM metrics from detection results
        
        Args:
            detection_results: List of dicts with 'detected', 'events_found', 'historical_events'
            
        Returns:
            SIEMMetrics with calculated values
        """
        true_positives = 0   # Attack detected correctly
        false_positives = 0  # Rule triggered without attack (historical events)
        false_negatives = 0  # Attack not detected
        true_negatives = 0   # No attack, no detection (baseline)
        
        for result in detection_results:
            detected = result.get('detected', False)
            events_found = result.get('events_found', 0)
            historical_events = result.get('historical_events', 0)
            
            if detected and events_found > 0:
                true_positives += 1
            else:
                false_negatives += 1
            
            # Historical events indicate false positives (rule triggered without our attack)
            if historical_events > 0:
                false_positives += historical_events
        
        # Calculate metrics
        total = true_positives + false_positives + false_negatives + true_negatives
        
        # Precision: TP / (TP + FP)
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        
        # Recall (Detection Rate): TP / (TP + FN)
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        
        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Accuracy: (TP + TN) / (TP + TN + FP + FN)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0.0
        
        # Detection Rate (same as recall)
        detection_rate = recall
        
        # False Positive Rate: FP / (FP + TN)
        false_positive_rate = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0.0
        
        return SIEMMetrics(
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate
        )


class FeedbackLoopOrchestrator:
    """Orchestrates the feedback loop with SIEM integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.repo_root = Path(__file__).resolve().parents[2]
        self.output_dir = self.repo_root / "data" / "output" / "feedback_loop_siem"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Agents (All LangChain versions)
        self.rulegen: Optional[LangChainRuleGenAgent] = None
        self.attackgen: Optional[LangChainAttackGenAgent] = None
        self.evaluator: Optional[LangChainEvaluatorAgent] = None
        
        # SIEM Integration
        self.siem_integrator: Optional[SIEMIntegrator] = None
        
        # Feedback manager
        self.feedback_manager = FeedbackManager()
        
        # Loop config
        self.max_iterations = config.get('feedback', {}).get('max_iterations', 3)
        self.min_score_threshold = config.get('feedback', {}).get('minimum_score', 0.8)
        self.min_detection_rate = config.get('feedback', {}).get('minimum_detection_rate', 0.9)
        
        # Statistics
        self.iteration_results = []
    
    async def initialize(self):
        """Initialize all agents and SIEM integration"""
        print("\n[INIT] Initializing Feedback Loop Orchestrator with SIEM...")
        
        # Initialize RuleGen (LangChain version)
        print("   • Initializing LangChain RuleGen agent...")
        rulegen_config = self.config.get('agents', {}).get('rulegen', {})
        rulegen_config['use_langchain'] = True  # Enable LangChain
        rulegen_config['use_feedback'] = True  # Enable feedback
        self.rulegen = LangChainRuleGenAgent("rulegen", rulegen_config)
        await self.rulegen.start()
        
        # Initialize AttackGen (LangChain version)
        print("   • Initializing LangChain AttackGen agent...")
        attackgen_config = self.config.get('agents', {}).get('attackgen', {})
        attackgen_config['use_langchain'] = True  # Enable LangChain
        self.attackgen = LangChainAttackGenAgent("attackgen", attackgen_config)
        await self.attackgen.start()
        
        # Initialize Evaluator (LangChain version)
        print("   • Initializing LangChain Evaluator agent...")
        evaluator_config = self.config.get('agents', {}).get('evaluator', {})
        evaluator_config['use_langchain'] = True  # Enable LangChain
        self.evaluator = LangChainEvaluatorAgent("evaluator", evaluator_config)
        await self.evaluator.start()
        
        # Initialize SIEM Integration
        print("   • Initializing SIEM Integration...")
        siem_config = self.config.get('siem', {})
        self.siem_integrator = SIEMIntegrator(siem_config)
        
        if self.siem_integrator.simulation_mode:
            print("   ⚠️  SIEM running in SIMULATION MODE (no real connection)")
        else:
            print("   ✓  SIEM connected to real Splunk instance")
        
        print("[INIT] Initialization complete!\n")
    
    async def run_feedback_loop(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the complete feedback loop with SIEM integration
        
        Args:
            extraction_data: Extracted CTI data for rule generation
            
        Returns:
            Complete feedback loop results
        """
        print("="*100)
        print("STARTING FEEDBACK LOOP WITH SIEM INTEGRATION")
        print("="*100)
        print(f"   • Max iterations: {self.max_iterations}")
        print(f"   • Min score threshold: {self.min_score_threshold}")
        print(f"   • Min Detection Rate: {self.min_detection_rate}")
        print(f"   • SIEM mode: {'SIMULATION' if self.siem_integrator.simulation_mode else 'REAL'}")
        print("="*100)
        
        iteration = 1
        best_score = 0.0
        best_detection_rate = 0.0
        
        while iteration <= self.max_iterations:
            print(f"\n{'='*100}")
            print(f"ITERATION {iteration}/{self.max_iterations}")
            print(f"{'='*100}")
            
            iteration_result = await self._run_single_iteration(extraction_data, iteration)
            self.iteration_results.append(iteration_result)
            
            # Get scores
            overall_score = iteration_result.get('evaluation_metrics', {}).get('average_score', 0.0)
            detection_rate = iteration_result.get('siem_metrics', {}).get('detection_rate', 0.0)
            
            print(f"\n[ITERATION {iteration}] Results:")
            print(f"   • Overall Score: {overall_score:.3f}")
            print(f"   • Detection Rate: {detection_rate:.3f}")
            print(f"   • Rules Generated: {iteration_result.get('rules_generated', 0)}")
            print(f"   • Attacks Generated: {iteration_result.get('attacks_generated', 0)}")
            
            # Update best scores
            if overall_score > best_score:
                best_score = overall_score
            if detection_rate > best_detection_rate:
                best_detection_rate = detection_rate
            
            # Check stopping conditions
            if overall_score >= self.min_score_threshold and detection_rate >= self.min_detection_rate:
                print(f"\n✓ Stopping condition met:")
                print(f"   • Score {overall_score:.3f} >= {self.min_score_threshold}")
                print(f"   • Detection Rate {detection_rate:.3f} >= {self.min_detection_rate}")
                break
            
            if iteration < self.max_iterations:
                print(f"\n→ Scores below threshold, continuing to iteration {iteration + 1}...")
            
            iteration += 1
        
        # Generate final report
        final_result = self._generate_final_report(iteration)
        
        print(f"\n{'='*100}")
        print("FEEDBACK LOOP COMPLETE")
        print(f"{'='*100}")
        print(f"   • Total Iterations: {len(self.iteration_results)}")
        print(f"   • Best Overall Score: {best_score:.3f}")
        print(f"   • Best Detection Rate: {best_detection_rate:.3f}")
        print(f"   • Final Status: {final_result['status']}")
        
        return final_result
    
    async def _run_single_iteration(self, extraction_data: Dict[str, Any], iteration: int) -> Dict[str, Any]:
        """Run a single iteration of the feedback loop"""
        
        print(f"\n[STEP 1] Generating rules from CTI data (using LangChain)...")
        # Stage 1: Generate Rules with LangChain
        
        # Extract TTPs from the extraction data structure
        # The extraction data has: {'extraction_results': [{'extracted_ttps': [...]}]}
        ttps = []
        if 'extraction_results' in extraction_data:
            for result in extraction_data['extraction_results']:
                ttps.extend(result.get('extracted_ttps', []))
        elif 'extracted_ttps' in extraction_data:
            ttps = extraction_data['extracted_ttps']
        elif isinstance(extraction_data, list):
            ttps = extraction_data
        
        if not ttps:
            print(f"   ⚠️  No TTPs found in extraction data")
            return {
                'status': 'error',
                'iteration': iteration,
                'error': 'No TTPs found in extraction data'
            }
        
        print(f"   • Found {len(ttps)} TTPs from extraction data")
        
        # Pass TTPs to RuleGen
        rulegen_result = await self.rulegen.execute({'ttps': ttps})
        
        if rulegen_result['status'] != 'success':
            return {
                'status': 'error',
                'iteration': iteration,
                'error': f"RuleGen failed: {rulegen_result.get('message', 'Unknown error')}"
            }
        
        # Extract rules from LangChain agent result
        rules = rulegen_result.get('rules', rulegen_result.get('rule_generation_results', []))
        print(f"   ✓ Generated {len(rules)} rules (via LangChain)")
        
        # Save rules
        rules_file = self.output_dir / f'iteration_{iteration}' / 'rules.json'
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=2)
        
        print(f"\n[STEP 2] Generating attack commands for rules (using LangChain)...")
        # Stage 2: Generate Attacks with LangChain
        attack_results = []
        for rule in rules:
            # Extract TTP/technique from rule
            ttp_data = {
                'technique_id': rule.get('mitre_attack', {}).get('technique_id', 'T1059'),
                'technique_name': rule.get('mitre_attack', {}).get('technique', 'Command Execution'),
                'tactic': rule.get('mitre_attack', {}).get('tactic', 'execution'),
                'description': rule.get('description', ''),
                'platform': rule.get('platform', 'windows')
            }
            
            attack_result = await self.attackgen.execute({'ttps': [ttp_data]})
            if attack_result['status'] == 'success':
                # Extract commands from LangChain agent result
                commands = attack_result.get('attack_commands', [])
                attack_results.extend(commands)
        
        print(f"   ✓ Generated {len(attack_results)} attack commands (via LangChain)")
        
        # Save attacks
        attacks_file = self.output_dir / f'iteration_{iteration}' / 'attacks.json'
        with open(attacks_file, 'w') as f:
            json.dump(attack_results, f, indent=2)
        
        print(f"\n[STEP 3] Executing attacks and verifying rules in SIEM...")
        # Stage 3: SIEM Verification
        siem_results = []
        for i, (rule, attack) in enumerate(zip(rules, attack_results[:len(rules)])):
            print(f"   • Verifying rule {i+1}/{len(rules)}...", end=' ')
            
            detection_result = self.siem_integrator.verify_rule(rule, attack)
            
            siem_results.append({
                'rule_id': rule.get('id', f'rule_{i}'),
                'attack_id': attack.get('id', f'attack_{i}'),
                'detected': detection_result.detected,
                'events_found': detection_result.events_found,
                'historical_events': detection_result.historical_events,
                'query_time_ms': detection_result.query_time_ms,
                'status': detection_result.status,
                'message': detection_result.message
            })
            
            status_icon = "✓" if detection_result.detected else "✗"
            print(f"{status_icon} (events: {detection_result.events_found})")
        
        # Save SIEM results
        siem_file = self.output_dir / f'iteration_{iteration}' / 'siem_results.json'
        with open(siem_file, 'w') as f:
            json.dump(siem_results, f, indent=2)
        
        print(f"\n[STEP 4] Calculating SIEM metrics (Detection Rate, False Positive Rate)...")
        # Stage 4: Calculate SIEM Metrics
        siem_metrics = SIEMMetricsCalculator.calculate_metrics(siem_results)
        print(f"   • Detection Rate: {siem_metrics.detection_rate:.3f}")
        print(f"   • False Positive Rate: {siem_metrics.false_positive_rate:.3f}")
        
        print(f"\n[STEP 5] Evaluating rules with benchmark metrics (using LangChain)...")
        # Stage 5: Evaluate with Benchmark + SIEM metrics using LangChain
        # Attach SIEM results to rules for evaluation
        for rule, siem_result in zip(rules, siem_results):
            rule['siem_verification'] = siem_result
        
        evaluation_result = await self.evaluator.execute({'rules': rules})
        
        # Get summary data (not 'metrics') for proper score display
        eval_summary = evaluation_result.get('summary', {})
        eval_metrics = {  # Build metrics dict for compatibility
            'average_score': eval_summary.get('average_quality_score', 0),
            'total_evaluations': eval_summary.get('rules_evaluated', 0),
            'passing_rules': eval_summary.get('passing_rules', 0),
            'failing_rules': eval_summary.get('failing_rules', 0)
        }
        print(f"   • Average Benchmark Score: {eval_metrics['average_score']:.3f} (via LangChain)")
        print(f"   • Rules Evaluated: {eval_metrics['total_evaluations']}")
        
        print(f"\n[STEP 6] Generating feedback for RuleGen...")
        # Stage 6: Generate Combined Feedback
        combined_feedback = self._generate_combined_feedback(
            evaluation_result=evaluation_result,
            siem_metrics=siem_metrics,
            siem_results=siem_results,
            iteration=iteration
        )
        
        # Write feedback
        self.feedback_manager.write_feedback("rulegen", combined_feedback)
        print(f"   ✓ Feedback generated with {len(combined_feedback.get('improvements_needed', []))} improvement areas")
        
        # Save combined feedback
        feedback_file = self.output_dir / f'iteration_{iteration}' / 'feedback.json'
        with open(feedback_file, 'w') as f:
            json.dump(combined_feedback, f, indent=2)
        
        return {
            'status': 'success',
            'iteration': iteration,
            'rules_generated': len(rules),
            'attacks_generated': len(attack_results),
            'siem_verifications': len(siem_results),
            'siem_metrics': siem_metrics.to_dict(),
            'evaluation_metrics': eval_metrics,
            'feedback': combined_feedback,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _generate_combined_feedback(self, 
                                    evaluation_result: Dict[str, Any],
                                    siem_metrics: SIEMMetrics,
                                    siem_results: List[Dict[str, Any]],
                                    iteration: int) -> Dict[str, Any]:
        """Generate combined feedback from benchmark and SIEM metrics"""
        
        improvements_needed = []
        actionable_suggestions = []
        
        # Analyze SIEM metrics
        if siem_metrics.detection_rate < 0.9:
            improvements_needed.append({
                'area': 'detection_rate',
                'current_value': siem_metrics.detection_rate,
                'target_value': 0.9,
                'severity': 'high',
                'description': 'Detection rate is low, missing attack detections'
            })
            actionable_suggestions.append(
                "Broaden rule coverage to catch more attack variants. "
                "Review missed detections and add additional detection patterns."
            )
        
        # Analyze detection failures
        failed_detections = [r for r in siem_results if not r['detected']]
        if failed_detections:
            improvements_needed.append({
                'area': 'detection_failures',
                'current_value': len(failed_detections),
                'target_value': 0,
                'severity': 'critical',
                'description': f'{len(failed_detections)} rules failed to detect their attacks'
            })
            
            # Provide specific feedback for failed rules
            for failure in failed_detections[:3]:  # Top 3 failures
                actionable_suggestions.append(
                    f"Rule '{failure['rule_id']}' failed detection. "
                    f"Review query logic and ensure it matches the attack pattern. "
                    f"Message: {failure.get('message', 'No details')}"
                )
        
        # Combine with benchmark feedback
        benchmark_feedback = evaluation_result.get('feedback', {})
        if benchmark_feedback:
            improvements_needed.extend(benchmark_feedback.get('improvements_needed', []))
            actionable_suggestions.extend(benchmark_feedback.get('actionable_suggestions', []))
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'iteration': iteration,
            'agent_id': 'rulegen',
            'feedback_type': 'combined_siem_benchmark',
            'siem_metrics': siem_metrics.to_dict(),
            'improvements_needed': improvements_needed,
            'actionable_suggestions': actionable_suggestions,
            'overall_assessment': self._generate_overall_assessment(siem_metrics, evaluation_result),
            'metadata': {
                'failed_detections': len(failed_detections),
                'total_verifications': len(siem_results),
                'benchmark_score': evaluation_result.get('metrics', {}).get('average_score', 0)
            }
        }
    
    def _generate_overall_assessment(self, 
                                    siem_metrics: SIEMMetrics,
                                    evaluation_result: Dict[str, Any]) -> str:
        """Generate overall assessment summary"""
        
        benchmark_score = evaluation_result.get('metrics', {}).get('average_score', 0)
        
        if siem_metrics.detection_rate >= 0.9 and benchmark_score >= 0.8:
            return "Excellent: Rules demonstrate strong detection capabilities and high quality."
        elif siem_metrics.detection_rate >= 0.7 and benchmark_score >= 0.7:
            return "Good: Rules are performing well but have room for improvement."
        elif siem_metrics.detection_rate >= 0.5 or benchmark_score >= 0.6:
            return "Fair: Rules need significant improvement in either detection or quality."
        else:
            return "Poor: Rules require major revisions to meet detection and quality standards."
    
    def _generate_final_report(self, total_iterations: int) -> Dict[str, Any]:
        """Generate final feedback loop report"""
        
        # Calculate improvements across iterations
        first_iteration = self.iteration_results[0] if self.iteration_results else {}
        last_iteration = self.iteration_results[-1] if self.iteration_results else {}
        
        first_dr = first_iteration.get('siem_metrics', {}).get('detection_rate', 0)
        last_dr = last_iteration.get('siem_metrics', {}).get('detection_rate', 0)
        dr_improvement = last_dr - first_dr
        
        first_score = first_iteration.get('evaluation_metrics', {}).get('average_score', 0)
        last_score = last_iteration.get('evaluation_metrics', {}).get('average_score', 0)
        score_improvement = last_score - first_score
        
        # Determine final status
        if last_dr >= self.min_detection_rate and last_score >= self.min_score_threshold:
            status = 'success'
            message = 'Feedback loop converged successfully'
        elif total_iterations >= self.max_iterations:
            status = 'max_iterations_reached'
            message = 'Maximum iterations reached without full convergence'
        else:
            status = 'incomplete'
            message = 'Feedback loop incomplete'
        
        final_report = {
            'status': status,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'total_iterations': total_iterations,
            'improvements': {
                'detection_rate': {
                    'initial': first_dr,
                    'final': last_dr,
                    'improvement': dr_improvement,
                    'percent_change': (dr_improvement / first_dr * 100) if first_dr > 0 else 0
                },
                'benchmark_score': {
                    'initial': first_score,
                    'final': last_score,
                    'improvement': score_improvement,
                    'percent_change': (score_improvement / first_score * 100) if first_score > 0 else 0
                }
            },
            'iteration_history': self.iteration_results,
            'final_metrics': {
                'siem': last_iteration.get('siem_metrics', {}),
                'benchmark': last_iteration.get('evaluation_metrics', {})
            }
        }
        
        # Save final report
        report_file = self.output_dir / 'final_report.json'
        with open(report_file, 'w') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)
        
        print(f"\n[OUTPUT] Final report saved to: {report_file}")
        
        return final_report
    
    async def cleanup(self):
        """Cleanup all resources"""
        print("\n[CLEANUP] Shutting down LangChain agents...")
        if self.rulegen:
            await self.rulegen.stop()
        if self.attackgen:
            await self.attackgen.stop()
        if self.evaluator:
            await self.evaluator.stop()
        if self.siem_integrator and self.siem_integrator.ssh:
            self.siem_integrator.ssh.close()
        print("[CLEANUP] Complete")


async def main():
    """Main test function"""
    
    # Load test data
    repo_root = Path(__file__).resolve().parents[2]
    data_path = repo_root / "data" / "extracted" / "hybrid_extraction_results.json"
    
    if not data_path.exists():
        print(f"[ERROR] Test data not found: {data_path}")
        return
    
    with open(data_path, 'r', encoding='utf-8') as f:
        extraction_data = json.load(f)
    
    hybrid_data = extraction_data.get('hybrid', {})
    
    # Configuration
    config = {
        'agents': {
            'rulegen': {
                'use_langchain': True,  # Enable LangChain
                'use_feedback': True,   # Enable feedback consumption
                'platforms': ['splunk', 'elasticsearch'],
                'optimize_rules': True,
                'validate_rules': True,
                'min_confidence_threshold': 0.7,
                'llm': {
                    'enabled': True,
                    'api_key': os.getenv('GEMINI_API_KEY'),
                    'model': 'gemini-2.0-flash-lite',
                    'temperature': 0.3,
                    'max_retries': 3
                }
            },
            'attackgen': {
                'use_langchain': True,  # Enable LangChain
                'platforms': ['windows', 'linux'],
                'llm': {
                    'enabled': True,
                    'api_key': os.getenv('GEMINI_API_KEY'),
                    'model': 'gemini-2.0-flash-lite',
                    'temperature': 0.7,
                    'max_retries': 3
                },
                'safety_level': 'medium',
                'max_commands_per_ttp': 2
            },
            'evaluator': {
                'use_langchain': True,  # Enable LangChain
                'platforms': ['splunk', 'elasticsearch'],
                'feedback_enabled': True,
                'llm': {
                    'enabled': True,
                    'api_key': os.getenv('GEMINI_API_KEY'),
                    'model': 'gemini-2.0-flash-lite',
                    'temperature': 0.2,
                    'max_retries': 3
                },
                'benchmark': {
                    'llm_api_key': os.getenv('GEMINI_API_KEY'),
                    'platforms': ['splunk', 'elasticsearch']
                }
            }
        },
        'siem': {
            'splunk': {
                'host': settings.get_splunk_config().get('splunk_host', 'localhost'),
                'port': settings.get_splunk_config().get('splunk_port', 8089),
                'user': settings.get_splunk_config().get('splunk_user', 'admin'),
                'password': settings.get_splunk_config().get('splunk_password', ''),
                'verify_ssl': settings.get_splunk_config().get('splunk_verify_ssl', False)
            },
            'ssh': {
                'host': settings.get_ssh_config().get('ssh_host', 'localhost'),
                'port': settings.get_ssh_config().get('ssh_port', 22),
                'user': settings.get_ssh_config().get('ssh_user', 'root'),
                'password': settings.get_ssh_config().get('ssh_password', '')
            },
            'indexing_wait_time': 10,
            'simulation_mode': False  # Set to True to skip real SIEM
        },
        'feedback': {
            'max_iterations': 3,
            'minimum_score': 0.8,  # Benchmark score threshold
            'minimum_detection_rate': 0.9     # SIEM Detection Rate threshold
        }
    }
    
    orchestrator = FeedbackLoopOrchestrator(config)
    
    try:
        await orchestrator.initialize()
        result = await orchestrator.run_feedback_loop(hybrid_data)
        
        print("\n" + "="*100)
        print("FINAL SUMMARY")
        print("="*100)
        print(f"Status: {result['status']}")
        print(f"Total Iterations: {result['total_iterations']}")
        print(f"\nDetection Rate:")
        print(f"   Initial: {result['improvements']['detection_rate']['initial']:.3f}")
        print(f"   Final: {result['improvements']['detection_rate']['final']:.3f}")
        print(f"   Improvement: {result['improvements']['detection_rate']['improvement']:.3f} ({result['improvements']['detection_rate']['percent_change']:.1f}%)")
        print(f"\nBenchmark Score:")
        print(f"   Initial: {result['improvements']['benchmark_score']['initial']:.3f}")
        print(f"   Final: {result['improvements']['benchmark_score']['final']:.3f}")
        print(f"   Improvement: {result['improvements']['benchmark_score']['improvement']:.3f} ({result['improvements']['benchmark_score']['percent_change']:.1f}%)")
        
    finally:
        await orchestrator.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
