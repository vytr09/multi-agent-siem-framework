"""
LangChain-Enabled Orchestrator
Supports both traditional and LangChain-powered agent pipelines
"""
import asyncio
import os
from pathlib import Path
import json
from typing import Dict, Any, List, Literal, Optional
from datetime import datetime

# Traditional agents
from agents.extractor.agent import ExtractorAgent
from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.evaluator.agent import EvaluatorAgent

# LangChain agents
from agents.extractor.langchain_agent import LangChainExtractorAgent
from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent
from agents.attackgen.langchain_agent import LangChainAttackGenAgent
from core.siem_integration import SIEMIntegrator, SIEMMetricsCalculator
from agents.attackgen.langchain_agent import LangChainAttackGenAgent
from core.siem_integration import SIEMIntegrator, SIEMMetricsCalculator

from core.config import get_config
from core.logging import get_agent_logger
from core.knowledge_base import get_kb_manager
from core.graph import SecurityWorkflow


AgentMode = Literal["traditional", "langchain", "hybrid"]


class LangChainOrchestrator:
    """
    Enhanced orchestrator supporting both traditional and LangChain agents
    
    Modes:
    - traditional: Uses direct Gemini API agents
    - langchain: Uses LangChain-powered agents
    - hybrid: Mixes both based on config
    """
    
    def __init__(self, config_path: str = "config/agents.yaml", mode: AgentMode = "langchain"):
        self.config = self._load_config(config_path)
        self.mode = mode
        self.logger = get_agent_logger("langchain_orchestrator")
        
        # Agents
        self.extractor = None
        self.rulegen = None
        self.evaluator = None
        self.attackgen = None
        self.siem_integrator = None
        self.attackgen = None
        self.siem_integrator = None
        
        # Paths
        self.output_dir = Path("data/output/")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Orchestrator created with mode: {mode}")
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load config from file with env var substitution"""
        from dotenv import load_dotenv
        load_dotenv()
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Substitute env vars
        content = os.path.expandvars(content)
        
        import yaml
        data = yaml.safe_load(content)
        
        # Handle root 'config' key if present
        if data and 'config' in data and 'agents' in data['config']:
            return data['config']
            
        return data
    
    async def initialize(self):
        """Initialize agents based on mode"""
        self.logger.info(f"Initializing agents in {self.mode} mode...")
        
        # Extract configs
        extractor_config = self.config.get('agents', {}).get('extractor', {})
        rulegen_config = self.config.get('agents', {}).get('rulegen', {})
        evaluator_config = self.config.get('agents', {}).get('evaluator', {})
        
        # Create agents based on mode
        if self.mode == "langchain":
            # Pure LangChain pipeline
            extractor_config["use_langchain"] = True
            rulegen_config["use_langchain"] = True
            evaluator_config["use_langchain"] = True
            
            self.extractor = LangChainExtractorAgent("langchain_extractor", extractor_config)
            self.rulegen = LangChainRuleGenAgent("langchain_rulegen", rulegen_config)
            self.evaluator = LangChainEvaluatorAgent("langchain_evaluator", evaluator_config)
            
            # Initialize AttackGen
            attackgen_config = self.config.get('agents', {}).get('attackgen', {})
            attackgen_config["use_langchain"] = True
            self.attackgen = LangChainAttackGenAgent("langchain_attackgen", attackgen_config)
            
            # Initialize SIEM Integrator
            siem_config = self.config.get('siem', {})
            self.siem_integrator = SIEMIntegrator(siem_config)
            
            # Initialize AttackGen
            attackgen_config = self.config.get('agents', {}).get('attackgen', {})
            attackgen_config["use_langchain"] = True
            self.attackgen = LangChainAttackGenAgent("langchain_attackgen", attackgen_config)
            
            # Initialize SIEM Integrator
            siem_config = self.config.get('siem', {})
            self.siem_integrator = SIEMIntegrator(siem_config)
            
        elif self.mode == "traditional":
            # Traditional direct API pipeline
            extractor_config["use_langchain"] = False
            rulegen_config["use_langchain"] = False
            evaluator_config["use_langchain"] = False
            
            self.extractor = ExtractorAgent("traditional_extractor", extractor_config)
            self.rulegen = RuleGenerationAgentWithLLM("traditional_rulegen", rulegen_config)
            self.evaluator = EvaluatorAgent("traditional_evaluator", evaluator_config)
            
        elif self.mode == "hybrid":
            # Mix: Use LangChain where it provides most benefit
            # LangChain for extraction and evaluation (structured outputs)
            # Traditional for rule generation (already optimized)
            extractor_config["use_langchain"] = True
            rulegen_config["use_langchain"] = False
            evaluator_config["use_langchain"] = True
            
            self.extractor = LangChainExtractorAgent("hybrid_extractor", extractor_config)
            self.rulegen = RuleGenerationAgentWithLLM("hybrid_rulegen", rulegen_config)
            self.evaluator = LangChainEvaluatorAgent("hybrid_evaluator", evaluator_config)
        
        # Start agents
        self.logger.info(f"All agents initialized ({self.mode} mode)")
    
    def _restore_agent(self, agent_name: str):
        """Re-create an agent instance if it was stopped/cleared"""
        agent_config = self.config.get('agents', {}).get(agent_name, {})
        
        # Determine mode-specific settings
        use_langchain = True
        if self.mode == "traditional":
            use_langchain = False
        elif self.mode == "hybrid" and agent_name == "rulegen":
            use_langchain = False
            
        agent_config["use_langchain"] = use_langchain
        name_prefix = self.mode
        
        if agent_name == "extractor":
            if use_langchain:
                self.extractor = LangChainExtractorAgent(f"{name_prefix}_extractor", agent_config)
            else:
                self.extractor = ExtractorAgent(f"{name_prefix}_extractor", agent_config)
        elif agent_name == "rulegen":
            if use_langchain:
                self.rulegen = LangChainRuleGenAgent(f"{name_prefix}_rulegen", agent_config)
            else:
                self.rulegen = RuleGenerationAgentWithLLM(f"{name_prefix}_rulegen", agent_config)
        elif agent_name == "evaluator":
            if use_langchain:
                self.evaluator = LangChainEvaluatorAgent(f"{name_prefix}_evaluator", agent_config)
            else:
                self.evaluator = EvaluatorAgent(f"{name_prefix}_evaluator", agent_config)
        elif agent_name == "attackgen":
            if self.mode == "langchain": 
                self.attackgen = LangChainAttackGenAgent(f"{name_prefix}_attackgen", agent_config)

    async def start_all(self):
        """Start all agents"""
        # Restore any missing agents first
        if not self.extractor: self._restore_agent("extractor")
        if not self.rulegen: self._restore_agent("rulegen")
        if not self.evaluator: self._restore_agent("evaluator")
        if not self.attackgen and self.mode == "langchain": self._restore_agent("attackgen")

        if self.extractor: await self.extractor.start()
        if self.rulegen: await self.rulegen.start()
        if self.evaluator: await self.evaluator.start()
        if self.attackgen: await self.attackgen.start()
            
    async def start_agent(self, agent_name: str):
        """Start a specific agent"""
        self.logger.info(f"Starting agent: {agent_name}")
        
        if agent_name == "extractor":
            if not self.extractor:
                self._restore_agent("extractor")
            if self.extractor:
                await self.extractor.start()
        elif agent_name == "rulegen":
            if not self.rulegen:
                self._restore_agent("rulegen")
            if self.rulegen:
                await self.rulegen.start()
        elif agent_name == "evaluator":
            if not self.evaluator:
                self._restore_agent("evaluator")
            if self.evaluator:
                await self.evaluator.start()
        elif agent_name == "attackgen":
            if not self.attackgen:
                self._restore_agent("attackgen")
            if self.attackgen:
                await self.attackgen.start()
        else:
            raise ValueError(f"Unknown agent: {agent_name}")

    async def run_pipeline(self, cti_reports: List[Dict], context: Optional[Dict[str, Any]] = None, status_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Run full pipeline with LangGraph (Parallel & Optimized)
        """
        self.logger.info(f"Running {self.mode} pipeline with LangGraph...")
        
        # Initialize SecurityWorkflow with current agents
        workflow = SecurityWorkflow(
            self.extractor, 
            self.rulegen, 
            self.attackgen, 
            self.evaluator, 
            self.siem_integrator,
            config=self.config,
            status_callback=status_callback
        )
        
        # Prepare input state
        input_state = {
            "cti_reports": cti_reports,
            "context": context if context else {},
            "extracted_ttps": [],
            "optimized_ttps": [],
            "processed_results": [],
            "final_report": {},
            "status": "starting",
            "errors": []
        }
        
        # Report SIEM status
        if status_callback:
            if self.siem_integrator and not self.siem_integrator.splunk_connected:
                await status_callback({
                    "step": "init", 
                    "status": "warning", 
                    "message": "SIEM Integration Disabled: Splunk connection failed. Verification will be skipped."
                })
            elif not self.siem_integrator:
                await status_callback({
                    "step": "init", 
                    "status": "warning", 
                    "message": "SIEM Integration Disabled: Not initialized."
                })

        # Execute Graph
        final_state = await workflow.run(input_state)
        
        # Extract results for backward compatibility
        results = final_state.get('processed_results', [])
        final_rules = []
        final_attacks = []
        siem_verification_list = []
        extracted_ttps = final_state.get('extracted_ttps', [])
        
        for res in results:
            if res.get('status') == 'success':
                final_rules.extend(res.get('rules', []))
                final_attacks.extend(res.get('attacks', []))
                
                # Extract SIEM verification from rules for backward compatibility
                for rule in res.get('rules', []):
                    siem_ver = rule.get('siem_verification')
                    if siem_ver:
                        siem_verification_list.append({
                            'rule_id': rule.get('id', 'unknown'),
                            'ttp_id': res.get('ttp_id', 'unknown'),
                            'detected': siem_ver.get('detected', False),
                            'events_found': siem_ver.get('events_found', 0),
                            'query_time_ms': siem_ver.get('query_time_ms', 0),
                            'status': siem_ver.get('status', 'unknown'),
                            'message': siem_ver.get('message', '')
                        })
        
        # Reconstruct extraction result to match legacy schema
        # Group TTPs by report_id
        from collections import defaultdict
        ttps_by_report = defaultdict(list)
        for ttp in extracted_ttps:
            r_id = ttp.get('report_id', 'unknown')
            ttps_by_report[r_id].append(ttp)
            
        extraction_results = []
        for r_id, ttps in ttps_by_report.items():
            extraction_results.append({
                "report_id": r_id,
                "extracted_ttps": ttps
            })
            
        legacy_extraction_output = {
            "status": "success",
            "extraction_summary": {
                "reports_processed": len(extraction_results),
                "total_ttps_extracted": len(extracted_ttps),
                "processing_time_ms": 0  # Placeholder or calculate if start/end times tracked
            },
            "extraction_results": extraction_results
        }
        
        # Calculate full SIEM metrics using the existing calculator
        siem_metrics_obj = {}
        if siem_verification_list:
            # Adapt the list to what calculator expects (it expects objects with 'detected' attribute or dict key)
            # The calculator usually works with objects, let's verify if it handles dicts.
            # Looking at code: SIEMMetricsCalculator.calculate_metrics(siem_results)
            # where siem_results is a list of dicts.
            try:
                metrics = SIEMMetricsCalculator.calculate_metrics(siem_verification_list)
                siem_metrics_obj = metrics.to_dict()
            except Exception as e:
                self.logger.warning(f"Failed to calculate detailed SIEM metrics: {e}")
                # Fallbck to simple metrics
                total = len(siem_verification_list)
                detected = sum(1 for v in siem_verification_list if v.get('detected'))
                siem_metrics_obj = {
                    'total_verifications': total,
                    'detected_count': detected,
                    'detection_rate': detected / total if total > 0 else 0
                }
        
        # Calculate Aggregated Score
        scores = []
        iterations_max = 1
        for res in results:
            if 'evaluation' in res:
                s = res['evaluation'].get('summary', {}).get('average_quality_score')
                if s is not None:
                    scores.append(s)
            # Estimate iterations: if feedback exists, it was > 1
            # In graph, we don't explicitly return iteration count per TTP easy, assume 1 unless we track it
            pass
            
        avg_score = sum(scores) / len(scores) if scores else 0.0

        # Construct final result dictionary to match old contract EXACTLY
        final_result = {
            'status': 'success',
            'mode': self.mode,
            'extraction': legacy_extraction_output,  # Updated structure
            'rules': {'rules': final_rules, 'status': 'success'},
            'evaluation': {'status': 'success', 'summary': {'average_quality_score': avg_score}},
            'attacks': final_attacks,
            'siem_verification': siem_verification_list,
            'siem_metrics': siem_metrics_obj,
            'iterations': iterations_max, # Placeholder for graph
            'final_score': avg_score,
            'final_report': final_state.get('final_report', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        # Knowledge Base Learning (Preserved)
        kb = get_kb_manager()
        if kb and kb.enabled:
            for rule in final_rules:
                siem_ver = rule.get('siem_verification', {})
                if siem_ver.get('detected', False):
                    self.logger.info(f"Learning verified rule: {rule.get('title')}")
                    await kb.add_sigma_rule(rule, status="verified")

        # Write final result
        final_file = self.output_dir / self.mode / 'pipeline_result.json'
        final_file.parent.mkdir(parents=True, exist_ok=True)
        with open(final_file, 'w') as f:
            json.dump(final_result, f, indent=2)
            
        return final_result

    # OLD Sequential Pipeline (Renamed for reference or fallback)
    async def run_pipeline_legacy(self, cti_reports: List[Dict], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run full pipeline with feedback loop
        """
        self.logger.info(f"Running {self.mode} pipeline with {len(cti_reports)} CTI reports")
        
        if context is None:
            context = {}
        
        # Stage 1: Extract TTPs
        self.logger.info("Stage 1: Extracting TTPs...")
        
        # Merge context into input payload
        extraction_payload = {'reports': cti_reports}
        if context:
            extraction_payload.update(context)
            
        extraction_result = await self.extractor.execute(extraction_payload)
        
        if extraction_result['status'] != 'success':
            return extraction_result
        
        # Write extraction output
        extraction_file = self.output_dir / self.mode / 'extractor' / 'extracted_ttps.json'
        extraction_file.parent.mkdir(parents=True, exist_ok=True)
        with open(extraction_file, 'w') as f:
            json.dump(extraction_result, f, indent=2)
        
        # Stage 2: Generate Rules
        self.logger.info("Stage 2: Generating rules...")
        rulegen_result = await self.rulegen.execute({
            'ttps': extraction_result.get('ttps', [])
        })
        
        if rulegen_result['status'] != 'success':
            return rulegen_result
        
        # Write rulegen output
        rulegen_file = self.output_dir / self.mode / 'rulegen' / 'generated_rules.json'
        rulegen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rulegen_file, 'w') as f:
            json.dump(rulegen_result, f, indent=2)
        
        # Stage 3: Generate Attacks (Practical Verification)
        self.logger.info("Stage 3: Generating attacks for verification...")
        rules = rulegen_result.get('rules', [])
        attack_results = []
        
        if self.attackgen:
            async def generate_attack_for_rule(rule):
                # Extract TTP/technique from rule
                ttp_data = {
                    'technique_id': rule.get('ttp_id', 'T1059'),
                    'technique_name': rule.get('technique_name', 'Command Execution'),
                    'tactic': 'execution', # Default
                    'description': rule.get('description', ''),
                    'platform': rule.get('logsource', {}).get('product', 'windows')
                }
                return await self.attackgen.execute({'ttps': [ttp_data]})

            # Parallel execution
            tasks = [generate_attack_for_rule(rule) for rule in rules]
            # Use Semaphore inside agent if needed, but here we just blast it 
            # (Orchestrator level concurrency)
            # Actually, let's limit it slightly here too if rules > 5 to be safe?
            # Or trust the agent's internal handling. 
            # Let's trust the agent or adding a simple semaphore here too is safer.
            
            # Simple parallel execution for now
            results = await asyncio.gather(*tasks)
            
            for attack_res in results:
                if attack_res['status'] == 'success':
                    attack_results.extend(attack_res.get('attack_commands', []))
        
        # Stage 4: SIEM Verification
        self.logger.info("Stage 4: Verifying rules in SIEM...")
        siem_results = []
        if self.siem_integrator:
            for i, (rule, attack) in enumerate(zip(rules, attack_results[:len(rules)])):
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
        
        # Calculate SIEM metrics
        siem_metrics = SIEMMetricsCalculator.calculate_metrics(siem_results)
        
        # Stage 5: Evaluate Rules (with feedback loop)
        self.logger.info("Stage 5: Evaluating rules...")
        
        # Attach SIEM results to rules for evaluation
        for rule, siem_result in zip(rules, siem_results):
            rule['siem_verification'] = siem_result
            
        evaluation_result = await self.evaluator.execute({
            'rules': rules
        })
        
        # Feedback loop
        score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
        detection_rate = siem_metrics.detection_rate
        
        # Track best result
        best_result = {
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'attacks': attack_results,
            'siem_verification': siem_results,
            'siem_metrics': siem_metrics,
            'score': score,
            'detection_rate': detection_rate
        }
        
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.75)
        # 0.9 allows for small rounding errors or partial detection if multiple attacks
        min_detection_rate = self.config.get('feedback', {}).get('minimum_detection_rate', 0.9)
        
        # Stop if we have 100% detection, even if score is slightly low
        # Functional success (detection) > Stylistic perfection (score)
        while (score < min_score or detection_rate < min_detection_rate) and iteration < max_iterations:
            if detection_rate >= 0.99:
                self.logger.info(f"Detection rate {detection_rate:.3f} is excellent. Stopping iterations despite score {score:.3f}.")
                break
                
            self.logger.info(f"Score {score:.3f} or DR {detection_rate:.3f} below threshold, re-running (iteration {iteration+1})...")
            
            # Generate combined feedback (simplified here, full logic in evaluator/orchestrator)
            feedback = {
                'evaluation': evaluation_result,
                'verification_results': siem_results,
                'metrics': siem_metrics.to_dict()
            }
            
            # Re-generate with updated feedback
            rulegen_result = await self.rulegen.execute({
                'ttps': extraction_result.get('ttps', []),
                'feedback': feedback
            })
            
            # Use the new rules
            rules = rulegen_result.get('rules', [])
            
            # We MUST re-verify because the rules changed (or at least re-evaluated)
            # Ideally we re-run attacks too, but let's assume TTP didn't change enough to invalidate attacks
            # Re-verify rules in SIEM
            if self.siem_integrator:
                self.logger.info(f"Stage 4 (Iter {iteration+1}): Verifying rules in SIEM...")
                # We reuse the previous attacks for now to save time/risk
                siem_results = []
                for i, (rule, attack) in enumerate(zip(rules, attack_results[:len(rules)])):
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
                siem_metrics = SIEMMetricsCalculator.calculate_metrics(siem_results)
            
            # Re-evaluate
            evaluation_result = await self.evaluator.execute({
                'rules': rules
            })
            
            score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
            detection_rate = siem_metrics.detection_rate
            
            # Update best object if this iteration is better
            # Priority: Detection Rate > Score
            current_dr = detection_rate
            best_dr = best_result['detection_rate']
            
            if current_dr > best_dr or (current_dr == best_dr and score > best_result['score']):
                best_result = {
                    'rules': rulegen_result,
                    'evaluation': evaluation_result,
                    'attacks': attack_results,
                    'siem_verification': siem_results,
                    'siem_metrics': siem_metrics,
                    'score': score,
                    'detection_rate': detection_rate
                }
                
            iteration += 1
            
        # Use the best result found
        rulegen_result = best_result['rules']
        evaluation_result = best_result['evaluation']
        siem_results = best_result['siem_verification']
        siem_metrics = best_result['siem_metrics']
        score = best_result['score']
        
        self.logger.info(f"{self.mode.upper()} pipeline completed (final score: {score:.3f}, best DR: {best_result['detection_rate']:.3f}, iterations: {iteration})")
        
        final_result = {
            'status': 'success',
            'mode': self.mode,
            'extraction': extraction_result,
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'attacks': best_result.get('attacks', []),
            'siem_verification': siem_results,
            'siem_metrics': siem_metrics.to_dict(),
            'iterations': iteration,
            'final_score': score,
            'timestamp': datetime.now().isoformat()
        }
        
        # Knowledge Base Learning
        kb = get_kb_manager()
        if kb and kb.enabled:
            # Learn from best result
            for rule in best_result.get('rules', {}).get('rules', []):
                siem_ver = rule.get('siem_verification', {})
                # If rule was verified by SIEM detection
                if siem_ver.get('detected', False):
                    self.logger.info(f"Learning verified rule: {rule.get('title')}")
                    await kb.add_sigma_rule(rule, status="verified")

        # Write final result
        final_file = self.output_dir / self.mode / 'pipeline_result.json'
        final_file.parent.mkdir(parents=True, exist_ok=True)
        with open(final_file, 'w') as f:
            json.dump(final_result, f, indent=2)
            
        return final_result
    
    async def run_agent(self, agent_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a specific agent in isolation
        """
        self.logger.info(f"Running agent: {agent_name}")
        
        if agent_name == "extractor":
            if not self.extractor:
                raise ValueError("Extractor agent not initialized")
            return await self.extractor.execute(input_data)
            
        elif agent_name == "rulegen":
            if not self.rulegen:
                raise ValueError("RuleGen agent not initialized")
            return await self.rulegen.execute(input_data)
            
        elif agent_name == "evaluator":
            if not self.evaluator:
                raise ValueError("Evaluator agent not initialized")
            return await self.evaluator.execute(input_data)
            
        elif agent_name == "attackgen":
            if not self.attackgen:
                raise ValueError("AttackGen agent not initialized")
            return await self.attackgen.execute(input_data)
            
        else:
            raise ValueError(f"Unknown agent: {agent_name}")

    async def stop_agent(self, agent_name: str):
        """Stop a specific agent"""
        self.logger.info(f"Stopping agent: {agent_name}")
        
        if agent_name == "extractor":
            if self.extractor:
                await self.extractor.stop()
                self.extractor = None
        elif agent_name == "rulegen":
            if self.rulegen:
                await self.rulegen.stop()
                self.rulegen = None
        elif agent_name == "evaluator":
            if self.evaluator:
                await self.evaluator.stop()
                self.evaluator = None
        elif agent_name == "attackgen":
            if self.attackgen:
                await self.attackgen.stop()
                self.attackgen = None
        else:
            raise ValueError(f"Unknown agent: {agent_name}")

    async def run_test_pipeline(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run test pipeline with pre-extracted data (simplified version without SIEM)
        
        For full SIEM integration, use tests/integration/test_feedback_loop_with_siem.py
        """
        self.logger.info(f"Running {self.mode} test pipeline with pre-extracted data")
        
        # Extract TTPs from input data
        ttps = extraction_data.get('ttps', extraction_data.get('extracted_ttps', []))
        
        # Stage 1: Generate Rules
        self.logger.info("Stage 1: Generating rules...")
        rulegen_result = await self.rulegen.execute({'ttps': ttps})
        
        if rulegen_result.get('status') != 'success':
            return rulegen_result
        
        # Write rulegen output
        # ... (rest of the function)
        return rulegen_result

    async def cleanup(self):
        """Cleanup resources"""
        if self.extractor:
            await self.extractor.stop()
        if self.rulegen:
            await self.rulegen.stop()
        if self.evaluator:
            await self.evaluator.stop()
        if self.attackgen:
            await self.attackgen.stop()
        if self.siem_integrator and self.siem_integrator.ssh:
            self.siem_integrator.ssh.close()
        
        self.logger.info("All agents cleaned up")
