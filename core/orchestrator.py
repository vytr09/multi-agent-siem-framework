# orchestrator_hybrid.py
"""
Hybrid Orchestrator
- Coordinates multi-agent pipeline execution
- Direct agent communication with file persistence
- Iterative feedback loop between RuleGen and Evaluator agents
"""
import asyncio
from pathlib import Path
import json
from typing import Dict, Any, List

from agents.extractor.agent import ExtractorAgent
from agents.rulegen.agent import RuleGenerationAgentWithLLM
from agents.evaluator.agent import EvaluatorAgent
from core.config import get_config
from core.logging import get_agent_logger

class HybridOrchestrator:
    """
    Orchestrator coordinating Extractor → RuleGen → Evaluator pipeline
    with iterative feedback loop for rule quality improvement
    """
    def __init__(self, config_path: str = "config/agents.yaml"):
        self.config = self._load_config(config_path)
        self.logger = get_agent_logger("orchestrator")
        
        # Agents
        self.extractor = None
        self.rulegen = None
        self.evaluator = None
        
        # Paths
        self.output_dir = Path("data/output/")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load config từ file"""
        with open(path, 'r', encoding='utf-8') as f:
            import yaml
            return yaml.safe_load(f)
    
    async def initialize(self):
        """Initialize all agents"""
        self.logger.info("Initializing agents...")
        
        # Extract configs
        extractor_config = self.config.get('agents', {}).get('extractor', {})
        rulegen_config = self.config.get('agents', {}).get('rulegen', {})
        evaluator_config = self.config.get('agents', {}).get('evaluator', {})
        
        # Create agents
        self.extractor = ExtractorAgent("extractor", extractor_config)
        self.rulegen = RuleGenerationAgentWithLLM("rulegen", rulegen_config)
        self.evaluator = EvaluatorAgent("evaluator", evaluator_config)
        
        # Start agents
        await self.extractor.start()
        await self.rulegen.start()
        await self.evaluator.start()
        
        self.logger.info("All agents initialized")
    
    async def run_pipeline(self, cti_reports: List[Dict]) -> Dict[str, Any]:
        """
        Run full pipeline với feedback loop
        """
        self.logger.info(f"Running pipeline với {len(cti_reports)} CTI reports")
        
        # Stage 1: Extract TTPs
        self.logger.info("Stage 1: Extracting TTPs...")
        extraction_result = await self.extractor.execute({
            'reports': cti_reports
        })
        
        if extraction_result['status'] != 'success':
            return extraction_result
        
        # Write extraction output
        extraction_file = self.output_dir / 'extractor' / 'extracted_ttps.json'
        extraction_file.parent.mkdir(parents=True, exist_ok=True)
        with open(extraction_file, 'w') as f:
            json.dump(extraction_result, f, indent=2)
        
        # Stage 2: Generate Rules (with feedback)
        self.logger.info("Stage 2: Generating rules...")
        rulegen_result = await self.rulegen.execute({
            'extracted_ttps': extraction_result.get('ttps', [])
        })
        
        if rulegen_result['status'] != 'success':
            return rulegen_result
        
        # Write rulegen output
        rulegen_file = self.output_dir / 'rulegen' / 'generated_rules.json'
        rulegen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rulegen_file, 'w') as f:
            json.dump(rulegen_result, f, indent=2)
        
        # Stage 3: Evaluate Rules
        self.logger.info("Stage 3: Evaluating rules...")
        evaluation_result = await self.evaluator.execute({
            'rules': rulegen_result.get('rules', [])
        })
        
        # Check if feedback loop needed
        score = evaluation_result.get('metrics', {}).get('average_score', 0)
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.7)
        
        while score < min_score and iteration < max_iterations:
            self.logger.info(f"Score {score} < {min_score}, re-running (iteration {iteration+1})...")
            
            # Re-generate với updated feedback
            rulegen_result = await self.rulegen.execute({
                'extracted_ttps': extraction_result.get('ttps', [])
            })
            
            # Re-evaluate
            evaluation_result = await self.evaluator.execute({
                'rules': rulegen_result.get('rules', [])
            })
            
            score = evaluation_result.get('metrics', {}).get('average_score', 0)
            iteration += 1
        
        self.logger.info(f"Pipeline completed (final score: {score}, iterations: {iteration})")
        
        return {
            'status': 'success',
            'extraction': extraction_result,
            'rules': rulegen_result,
            'evaluation': evaluation_result,
            'iterations': iteration,
            'final_score': score
        }
    
    async def run_test_pipeline(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run test pipeline with pre-extracted data (for testing feedback loop)
        """
        self.logger.info("Running test pipeline with pre-extracted data")

        # Skip extraction, use provided data
        self.logger.info("Using pre-extracted TTPs...")

        # Stage 1: Generate Rules (with feedback)
        self.logger.info("Stage 1: Generating rules...")
        rulegen_result = await self.rulegen.process(extraction_data)

        if rulegen_result['status'] != 'success':
            return rulegen_result

        # Write rulegen output
        rulegen_file = self.output_dir / 'rulegen' / 'generated_rules.json'
        rulegen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rulegen_file, 'w') as f:
            json.dump(rulegen_result, f, indent=2)

        # Stage 2: Evaluate Rules
        self.logger.info("Stage 2: Evaluating rules...")
        evaluation_result = await self.evaluator.execute({
            'rules': rulegen_result
        })

        # Check if feedback loop needed
        score = evaluation_result.get('metrics', {}).get('average_score', 0)
        iteration = 1
        max_iterations = self.config.get('feedback', {}).get('max_iterations', 3)
        min_score = self.config.get('feedback', {}).get('minimum_score', 0.8)

        while score < min_score and iteration < max_iterations:
            self.logger.info(f"Score {score:.3f} < {min_score}, re-running (iteration {iteration+1})...")

            # Re-generate with updated feedback
            rulegen_result = await self.rulegen.process(extraction_data)

            # Re-evaluate
            evaluation_result = await self.evaluator.execute({
                'rules': rulegen_result
            })

            score = evaluation_result.get('metrics', {}).get('average_score', 0)
            iteration += 1

        self.logger.info(f"Test pipeline completed (final score: {score:.3f}, iterations: {iteration})")

        return {
            'status': 'success',
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

async def main():
    """Main entry point"""
    orchestrator = HybridOrchestrator()
    
    try:
        await orchestrator.initialize()
        
        # Load CTI reports (from file or database)
        cti_reports = [
            # Your CTI reports here
        ]
        
        result = await orchestrator.run_pipeline(cti_reports)
        
        print(f"Pipeline result: {result['status']}")
        print(f"Final score: {result['final_score']}")
        print(f"Iterations: {result['iterations']}")
        
    finally:
        await orchestrator.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
