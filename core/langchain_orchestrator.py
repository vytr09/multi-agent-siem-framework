"""
LangChain-Enabled Orchestrator
Supports both traditional and LangChain-powered agent pipelines
"""
import asyncio
from pathlib import Path
import json
from typing import Dict, Any, List, Literal

# Traditional agents
from agents.extractor.agent import ExtractorAgent
from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.evaluator.agent import EvaluatorAgent

# LangChain agents
from agents.extractor.langchain_agent import LangChainExtractorAgent
from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent

from core.config import get_config
from core.logging import get_agent_logger


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
        
        # Paths
        self.output_dir = Path("data/output/")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Orchestrator created with mode: {mode}")
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load config from file"""
        with open(path, 'r', encoding='utf-8') as f:
            import yaml
            return yaml.safe_load(f)
    
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
        await self.extractor.start()
        await self.rulegen.start()
        await self.evaluator.start()
        
        self.logger.info(f"All agents initialized ({self.mode} mode)")
    
    async def run_pipeline(self, cti_reports: List[Dict]) -> Dict[str, Any]:
        """
        Run full pipeline with feedback loop
        """
        self.logger.info(f"Running {self.mode} pipeline with {len(cti_reports)} CTI reports")
        
        # Stage 1: Extract TTPs
        self.logger.info("Stage 1: Extracting TTPs...")
        extraction_result = await self.extractor.execute({
            'reports': cti_reports
        })
        
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
        
        # Stage 3: Evaluate Rules (with feedback loop)
        self.logger.info("Stage 3: Evaluating rules...")
        evaluation_result = await self.evaluator.execute({
            'rules': rulegen_result.get('rules', [])
        })
        
        # Feedback loop
        score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.75)
        
        while score < min_score and iteration < max_iterations:
            self.logger.info(f"Score {score:.3f} < {min_score}, re-running (iteration {iteration+1})...")
            
            # Re-generate with updated feedback
            rulegen_result = await self.rulegen.execute({
                'ttps': extraction_result.get('ttps', [])
            })
            
            # Re-evaluate
            evaluation_result = await self.evaluator.execute({
                'rules': rulegen_result.get('rules', [])
            })
            
            score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
            iteration += 1
        
        self.logger.info(f"{self.mode.upper()} pipeline completed (final score: {score:.3f}, iterations: {iteration})")
        
        return {
            'status': 'success',
            'mode': self.mode,
            'extraction': extraction_result,
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'iterations': iteration,
            'final_score': score
        }
    
    async def run_test_pipeline(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run test pipeline with pre-extracted data
        """
        self.logger.info(f"Running {self.mode} test pipeline with pre-extracted data")
        
        # Stage 1: Generate Rules
        self.logger.info("Stage 1: Generating rules...")
        rulegen_result = await self.rulegen.execute(extraction_data)
        
        if rulegen_result['status'] != 'success':
            return rulegen_result
        
        # Write rulegen output
        rulegen_file = self.output_dir / self.mode / 'rulegen' / 'generated_rules.json'
        rulegen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rulegen_file, 'w') as f:
            json.dump(rulegen_result, f, indent=2)
        
        # Stage 2: Evaluate Rules
        self.logger.info("Stage 2: Evaluating rules...")
        evaluation_result = await self.evaluator.execute({
            'rules': rulegen_result.get('rules', [])
        })
        
        # Feedback loop
        # Feedback loop with SIEM integration
        score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.8)
        min_detection_rate = 0.9  # 90% detection rate threshold
        
        # Initial check - if score is good enough, we might still want to verify with SIEM if enabled
        # For now, we enter the loop if score is low OR if we haven't verified yet
        
        while iteration <= max_iterations:
            # 1. Generate Attacks for the current rules (TTPs)
            self.logger.info(f"Stage 3 (Iteration {iteration}): Generating attack commands...")
            attackgen_result = await self.attackgen.execute({
                'ttps': extraction_result.get('ttps', []),
                'platform': 'windows' # Default to windows for now
            })
            
            attacks = attackgen_result.get('commands', [])
            self.logger.info(f"Generated {len(attacks)} attack commands")
            
            # 2. Verify in SIEM
            self.logger.info(f"Stage 4 (Iteration {iteration}): Verifying rules in SIEM...")
            verification_results = []
            
            rules = rulegen_result.get('rules', [])
            for rule in rules:
                # Find matching attack
                ttp_id = rule.get('metadata', {}).get('ttp_id')
                matching_attack = next((a for a in attacks if a.get('mitre_attack_id') == ttp_id), None)
                
                if matching_attack:
                    self.logger.info(f"Verifying Rule {rule.get('title')} vs Attack {matching_attack.get('name')}")
                    # Execute attack and verify
                    result = self.siem_integrator.verify_rule(rule, matching_attack)
                    verification_results.append({
                        'rule_id': rule.get('id'),
                        'ttp_id': ttp_id,
                        'verification': result
                    })
                else:
                    self.logger.warning(f"No matching attack found for rule {rule.get('title')} (TTP: {ttp_id})")
            
            # 3. Evaluate with SIEM results
            self.logger.info(f"Stage 5 (Iteration {iteration}): Evaluating with SIEM feedback...")
            evaluation_result = await self.evaluator.execute({
                'rules': rules,
                'verification_results': verification_results
            })
            
            # Check metrics
            metrics = evaluation_result.get('metrics', {})
            score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
            detection_rate = metrics.get('detection_rate', 0)
            
            self.logger.info(f"Iteration {iteration} Results: Score={score:.3f}, Detection Rate={detection_rate:.2%}")
            
            # Stopping conditions
            if score >= min_score and detection_rate >= min_detection_rate:
                self.logger.info(f"Success! Score {score:.3f} >= {min_score} and Detection Rate {detection_rate:.2%} >= {min_detection_rate}")
                break
                
            if iteration >= max_iterations:
                self.logger.info("Max iterations reached. Stopping.")
                break
                
            self.logger.info(f"Criteria not met. Re-generating rules with feedback...")
            
            # 4. Re-generate with updated feedback
            rulegen_result = await self.rulegen.execute({
                'ttps': extraction_result.get('ttps', []),
                'feedback': {
                    'evaluation': evaluation_result,
                    'verification_results': verification_results
                }
            })
            
            iteration += 1
        
        self.logger.info(f"{self.mode.upper()} test pipeline completed (final score: {score:.3f}, iterations: {iteration})")
        
        return {
            'status': 'success',
            'mode': self.mode,
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'iterations': iteration,
            'final_score': score
        }
    
    async def cleanup(self):
        """Cleanup agents"""
        if self.extractor:
            await self.extractor.stop()
        if self.rulegen:
            await self.rulegen.stop()
        if self.evaluator:
            await self.evaluator.stop()
        
        self.logger.info("All agents cleaned up")


async def main():
    """Main entry point - demonstrates all modes"""
    
    # Test data
    sample_reports = [
        {
            "text": """
            APT29 conducted a spear-phishing campaign targeting government organizations.
            The attack chain involved:
            1. Initial access via malicious email attachment (T1566.001)
            2. Execution of PowerShell scripts for reconnaissance (T1059.001)
            3. Credential dumping using Mimikatz (T1003.001)
            4. Lateral movement via Remote Desktop Protocol (T1021.001)
            """
        }
    ]
    
    # Run in LangChain mode
    print("\n" + "="*80)
    print("RUNNING LANGCHAIN MODE")
    print("="*80)
    
    orchestrator_lc = LangChainOrchestrator(mode="langchain")
    try:
        await orchestrator_lc.initialize()
        result_lc = await orchestrator_lc.run_pipeline(sample_reports)
        
        print(f"\nLangChain Result:")
        print(f"  Status: {result_lc['status']}")
        print(f"  Final Score: {result_lc['final_score']:.3f}")
        print(f"  Iterations: {result_lc['iterations']}")
        
    finally:
        await orchestrator_lc.cleanup()
    
    # Run in Traditional mode for comparison
    print("\n" + "="*80)
    print("RUNNING TRADITIONAL MODE")
    print("="*80)
    
    orchestrator_trad = LangChainOrchestrator(mode="traditional")
    try:
        await orchestrator_trad.initialize()
        result_trad = await orchestrator_trad.run_pipeline(sample_reports)
        
        print(f"\nTraditional Result:")
        print(f"  Status: {result_trad['status']}")
        print(f"  Final Score: {result_trad['final_score']:.3f}")
        print(f"  Iterations: {result_trad['iterations']}")
        
    finally:
        await orchestrator_trad.cleanup()
    
    # Compare
    print("\n" + "="*80)
    print("COMPARISON")
    print("="*80)
    print(f"LangChain Score: {result_lc['final_score']:.3f}")
    print(f"Traditional Score: {result_trad['final_score']:.3f}")
    print(f"Winner: {'LangChain' if result_lc['final_score'] > result_trad['final_score'] else 'Traditional'}")


if __name__ == "__main__":
    asyncio.run(main())
