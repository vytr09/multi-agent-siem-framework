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
from agents.attackgen.agent import AttackGenAgent

# LangChain agents
from agents.extractor.langchain_agent import LangChainExtractorAgent
from agents.rulegen.langchain_agent import LangChainRuleGenAgent
from agents.evaluator.langchain_agent import LangChainEvaluatorAgent
from agents.attackgen.langchain_agent import LangChainAttackGenAgent

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
        self.attackgen = None
        
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
        attackgen_config = self.config.get('agents', {}).get('attackgen', {})
        
        # Create agents based on mode
        if self.mode == "langchain":
            # Pure LangChain pipeline
            extractor_config["use_langchain"] = True
            rulegen_config["use_langchain"] = True
            evaluator_config["use_langchain"] = True
            
            self.extractor = LangChainExtractorAgent("langchain_extractor", extractor_config)
            self.rulegen = LangChainRuleGenAgent("langchain_rulegen", rulegen_config)
            self.evaluator = LangChainEvaluatorAgent("langchain_evaluator", evaluator_config)
            self.attackgen = LangChainAttackGenAgent("langchain_attackgen", attackgen_config)
            
        elif self.mode == "traditional":
            # Traditional direct API pipeline
            extractor_config["use_langchain"] = False
            rulegen_config["use_langchain"] = False
            evaluator_config["use_langchain"] = False
            
            self.extractor = ExtractorAgent("traditional_extractor", extractor_config)
            self.rulegen = RuleGenerationAgentWithLLM("traditional_rulegen", rulegen_config)
            self.evaluator = EvaluatorAgent("traditional_evaluator", evaluator_config)
            self.attackgen = AttackGenAgent("traditional_attackgen", attackgen_config)
            
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
            self.attackgen = LangChainAttackGenAgent("hybrid_attackgen", attackgen_config)
        
        # Start agents
        await self.extractor.start()
        await self.rulegen.start()
        await self.evaluator.start()
        await self.attackgen.start()
        
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
        
        # Stage 4: Attack Generation
        self.logger.info("Stage 4: Generating attack commands...")
        attackgen_result = await self.attackgen.execute({
            'extracted_ttps': extraction_result.get('ttps', [])
        })
        
        # Write attackgen output
        attackgen_file = self.output_dir / self.mode / 'attackgen' / 'generated_attacks.json'
        attackgen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(attackgen_file, 'w') as f:
            json.dump(attackgen_result, f, indent=2)

        self.logger.info(f"{self.mode.upper()} pipeline completed (final score: {score:.3f}, iterations: {iteration})")
        
        return {
            'status': 'success',
            'mode': self.mode,
            'extraction': extraction_result,
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'attacks': attackgen_result,
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
        score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.8)
        
        while score < min_score and iteration < max_iterations:
            self.logger.info(f"Score {score:.3f} < {min_score}, re-running (iteration {iteration+1})...")
            
            # Re-generate with updated feedback
            rulegen_result = await self.rulegen.execute(extraction_data)
            
            # Re-evaluate
            evaluation_result = await self.evaluator.execute({
                'rules': rulegen_result.get('rules', [])
            })
            
            score = evaluation_result.get('summary', {}).get('average_quality_score', 0)
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
        if self.attackgen:
            await self.attackgen.stop()
        
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
