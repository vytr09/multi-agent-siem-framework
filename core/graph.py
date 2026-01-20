import asyncio
from typing import TypedDict, List, Dict, Any, Optional, Annotated
import operator
from langgraph.graph import StateGraph, END
from datetime import datetime

from core.logging import get_agent_logger

# Define the shared state of the graph
class GraphState(TypedDict):
    # Input
    cti_reports: List[Dict]
    context: Dict[str, Any]
    
    # Intermediate
    extracted_ttps: List[Dict]
    optimized_ttps: List[Dict]
    
    # Output
    processed_results: List[Dict]
    final_report: Dict[str, Any]
    
    # Metadata
    status: str
    errors: List[str]

class SecurityWorkflow:
    """
    Manages the LangGraph workflow for the SIEM agents.
    """
    def __init__(self, extractor, rulegen, attackgen, evaluator, siem_integrator, config=None, status_callback=None):
        self.extractor = extractor
        self.rulegen = rulegen
        self.attackgen = attackgen
        self.evaluator = evaluator
        self.siem_integrator = siem_integrator
        self.config = config or {}
        self.status_callback = status_callback
        
        self.logger = get_agent_logger("security_graph")
        self.graph = self._build_graph()

    def _build_graph(self):
        """Build the StateGraph"""
        workflow = StateGraph(GraphState)
        
        # Add Nodes
        workflow.add_node("extractor", self.extractor_node)
        workflow.add_node("optimizer", self.optimizer_node)
        workflow.add_node("processor", self.parallel_processor_node)
        workflow.add_node("aggregator", self.aggregator_node)
        
        # Add Edges
        workflow.set_entry_point("extractor")
        workflow.add_edge("extractor", "optimizer")
        workflow.add_edge("optimizer", "processor")
        workflow.add_edge("processor", "aggregator")
        workflow.add_edge("aggregator", END)
        
        return workflow.compile()

    async def extractor_node(self, state: GraphState) -> Dict:
        """Node 1: Extract TTPs from CTI Reports"""
        self.logger.info("--- NODE: EXTRACTOR ---")
        if self.status_callback:
            await self.status_callback({
                "stage": "extraction", 
                "status": "running", 
                "message": "Extracting TTPs from CTI reports..."
            })

        try:
            reports = state.get("cti_reports", [])
            context = state.get("context", {})
            
            payload = {'reports': reports}
            payload.update(context)
            
            result = await self.extractor.execute(payload)
            
            if result['status'] == 'success':
                return {"extracted_ttps": result.get('ttps', [])}
            else:
                self.logger.error(f"Extraction failed: {result}")
                return {"extracted_ttps": [], "errors": [f"Extraction failed: {result.get('message')}"]}
                
        except Exception as e:
            self.logger.error(f"Extractor node error: {e}")
            return {"extracted_ttps": [], "errors": [str(e)]}

    async def optimizer_node(self, state: GraphState) -> Dict:
        """Node 2: Deduplicate and Filter TTPs"""
        self.logger.info("--- NODE: OPTIMIZER ---")
        if self.status_callback:
            await self.status_callback({
                "stage": "optimization", 
                "status": "running", 
                "message": "Optimizing and deduplicating extracted TTPs..."
            })

        ttps = state.get("extracted_ttps", [])
        
        # 1. Deduplication by ID
        unique_ttps = {}
        for ttp in ttps:
            # Use attack_id as primary key (standardized by mapper), fallback to technique_id
            t_id = ttp.get('attack_id') or ttp.get('technique_id')
            if not t_id:
                continue
                
            # If duplicate, keep higher confidence
            if t_id in unique_ttps:
                if ttp.get('confidence', 0) > unique_ttps[t_id].get('confidence', 0):
                    unique_ttps[t_id] = ttp
            else:
                unique_ttps[t_id] = ttp
        
        optimized = list(unique_ttps.values())
        
        # 2. Filter by threshold (optional, e.g. 0.5)
        # filtered = [t for t in optimized if t.get('confidence', 0) > 0.5]
        
        self.logger.info(f"Optimizer: Reduced {len(ttps)} TTPs to {len(optimized)} unique TTPs")
        return {"optimized_ttps": optimized}

    async def parallel_processor_node(self, state: GraphState) -> Dict:
        """Node 3: Process TTPs in Parallel (Map Step)"""
        self.logger.info("--- NODE: PARALLEL PROCESSOR ---")
        if self.status_callback:
            await self.status_callback({
                "stage": "processing", 
                "status": "running", 
                "message": "Generating rules and attacks for TTPs..."
            })

        ttps = state.get("optimized_ttps", [])
        
        if not ttps:
            return {"processed_results": []}

        # Create tasks for all TTPs
        self.logger.info(f"Starting parallel processing for {len(ttps)} TTPs...")
        tasks = [self._process_single_ttp(ttp) for ttp in ttps]
        
        # Capture all results
        results = await asyncio.gather(*tasks)
        
        return {"processed_results": results}

    async def _process_single_ttp(self, ttp: Dict) -> Dict:
        """
        Internal logic to process a single TTP:
        RuleGen || AttackGen -> Verify -> Evaluate -> Feedback Loop
        """
        """
        internal logic to process a single TTP:
        RuleGen || AttackGen -> Verify -> Evaluate -> Feedback Loop
        """
        ttp_id = ttp.get('attack_id') or ttp.get('technique_id')
        self.logger.info(f"[{ttp_id}] Starting processing flow")
        
        try:
            # Step 1: Parallel RuleGen & AttackGen
            async def run_rulegen():
                return await self.rulegen.execute({'ttps': [ttp]})
            
            async def run_attackgen():
                if self.attackgen:
                    return await self.attackgen.execute({'extracted_ttps': [ttp]})
                return {'attack_commands': []}

            # Run both concurrently
            rulegen_res, attackgen_res = await asyncio.gather(run_rulegen(), run_attackgen())
            
            # Extract artifacts
            rules = rulegen_res.get('rules', [])
            rule = rules[0] if rules else None
            
            attacks = attackgen_res.get('attack_commands', [])
            attack = attacks[0] if attacks else None
            
            if not rule:
                 self.logger.warning(f"[{ttp_id}] No rule generated")
                 return {"ttp_id": ttp_id, "status": "failed", "error": "No rule generated"}

            # Step 2: Verification (if we have rule & attack)
            verification_result = None
            if rule and attack and self.siem_integrator:
                 # self.logger.info(f"[{ttp_id}] Verifying rule vs attack")
                 verification_result = self.siem_integrator.verify_rule(rule, attack)
                 # Enrich rule with verification
                 rule['siem_verification'] = {
                     'detected': verification_result.detected,
                     'status': verification_result.status,
                     'message': verification_result.message,
                     'events_found': getattr(verification_result, 'events_found', 1 if verification_result.detected else 0),
                     'query_time_ms': getattr(verification_result, 'query_time_ms', 0)
                 }
            
            # Step 3: Evaluation
            eval_result = await self.evaluator.execute({'rules': [rule]})
            score = eval_result.get('summary', {}).get('average_quality_score', 0)
            
            # === RULE HISTORY TRACKING ===
            # Track each version of the rule for before/after comparison
            import copy
            rule_history = []
            
            # Save initial rule (iteration 0)
            initial_rule_snapshot = copy.deepcopy(rule)
            initial_rule_snapshot['_iteration'] = 0
            initial_rule_snapshot['_score'] = score
            initial_rule_snapshot['_is_initial'] = True
            rule_history.append(initial_rule_snapshot)
            
            # Step 4: Feedback Loop (Iterative Refinement)
            iteration = 0
            # Get config from instance or default
            feedback_config = self.config.get('feedback', {}) if self.config else {}
            max_iterations = feedback_config.get('max_iterations', 3)
            min_score_threshold = feedback_config.get('minimum_score', 0.8)
            
            while iteration < max_iterations:
                detected = rule.get('siem_verification', {}).get('detected', False)
                score = eval_result.get('summary', {}).get('average_quality_score', 0)
                
                # Exit condition: High score OR Detected (Functional success > Style)
                if score >= min_score_threshold or detected:
                    self.logger.info(f"[{ttp_id}] Success criteria met (Score: {score}, Detected: {detected}). Stopping iterations.")
                    break
                
                self.logger.info(f"[{ttp_id}] Iteration {iteration+1}/{max_iterations}: Score {score}, Detected {detected}. Refining...")
                
                feedback = {
                    'evaluation': eval_result,
                    'verification_results': [{'ttp_id': ttp_id, 'verification': rule.get('siem_verification')}]
                }
                
                # Retry RuleGen with feedback
                retry_res = await self.rulegen.execute({
                    'ttps': [ttp],
                    'feedback': feedback
                })
                
                # Use new rule if available
                new_rules = retry_res.get('rules', [])
                if new_rules:
                    rule = new_rules[0]
                    # Re-verify if possible (reuse attack)
                    if attack and self.siem_integrator:
                        v_res = self.siem_integrator.verify_rule(rule, attack)
                        rule['siem_verification'] = {
                            'detected': v_res.detected,
                            'status': v_res.status,
                            'message': v_res.message,
                            'events_found': getattr(v_res, 'events_found', 1 if v_res.detected else 0),
                            'query_time_ms': getattr(v_res, 'query_time_ms', 0)
                        }
                    
                    # Re-evaluate
                    eval_result = await self.evaluator.execute({'rules': [rule]})
                    new_score = eval_result.get('summary', {}).get('average_quality_score', 0)
                    
                    # Save this iteration's rule snapshot
                    rule_snapshot = copy.deepcopy(rule)
                    rule_snapshot['_iteration'] = iteration + 1
                    rule_snapshot['_score'] = new_score
                    rule_snapshot['_is_initial'] = False
                    rule_history.append(rule_snapshot)
                
                iteration += 1

            # === SELECT BEST RULE ===
            # Choose rule with highest score OR detected=True (detection takes priority)
            best_rule = rule  # Default to last
            best_score = 0
            
            for hist_rule in rule_history:
                hist_score = hist_rule.get('_score', 0)
                hist_detected = hist_rule.get('siem_verification', {}).get('detected', False)
                
                # Prefer detected rules, then highest score
                if hist_detected:
                    best_rule = hist_rule
                    best_score = hist_score
                    break  # Detected is highest priority
                elif hist_score > best_score:
                    best_rule = hist_rule
                    best_score = hist_score
            
            # Clean up internal fields before returning
            final_rule = {k: v for k, v in best_rule.items() if not k.startswith('_')}
            
            return {
                "ttp_id": ttp_id,
                "status": "success",
                "rules": [final_rule],
                "attacks": attacks,
                "verification": final_rule.get('siem_verification'),
                "evaluation": eval_result,
                "rule_history": rule_history,
                "iterations_used": len(rule_history),
                "best_iteration": best_rule.get('_iteration', 0),
                "best_score": best_score
            }
            
        except Exception as e:
            self.logger.error(f"[{ttp_id}] Processing failed: {e}")
            return {"ttp_id": ttp_id, "status": "error", "error": str(e)}

    async def aggregator_node(self, state: GraphState) -> Dict:
        """Node 4: Aggregate Results"""
        self.logger.info("--- NODE: AGGREGATOR ---")
        if self.status_callback:
            await self.status_callback({
                "stage": "aggregation", 
                "status": "running", 
                "message": "Aggregating final results and metrics..."
            })

        results = state.get("processed_results", [])
        
        final_rules = []
        final_attacks = []
        
        for res in results:
            if res.get('status') == 'success':
                final_rules.extend(res.get('rules', []))
                final_attacks.extend(res.get('attacks', []))
        
        report = {
            "total_ttps": len(state.get("extracted_ttps", [])),
            "optimized_ttps": len(state.get("optimized_ttps", [])),
            "generated_rules": len(final_rules),
            "generated_attacks": len(final_attacks),
            "timestamp": datetime.now().isoformat()
        }
        
        return {"final_report": report, "processed_results": results}

    async def run(self, input_data: Dict) -> Dict:
        """Run the workflow"""
        return await self.graph.ainvoke(input_data)
