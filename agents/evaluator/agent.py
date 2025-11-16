# agents/evaluator/agent.py
"""
Evaluator Agent
- Evaluates Sigma rule quality using benchmark framework
- Custom memory integration for feedback tracking
- Generates actionable feedback for rule improvement
"""
from typing import Dict, Any, List, Optional
import json
from pathlib import Path
from datetime import datetime

from agents.base.agent import BaseAgent, AgentStatus
from agents.evaluator.feedback_manager import FeedbackManager
from benchmark.rulegen_benchmark import RuleGenBenchmark
from benchmark.benchmark_base import BenchmarkResult
from core.logging import get_agent_logger
from core.memory import get_memory_manager

class EvaluatorAgent(BaseAgent):
    """
    Evaluates generated Sigma rules using comprehensive benchmark metrics
    Provides feedback to RuleGen agent for iterative rule improvement
    Uses custom memory system for feedback history and agent communication
    """
    def __init__(self, name: str, config: Dict[str, Any]):
        # Enable memory
        config['memory_enabled'] = True
        super().__init__(name, config)
        
        # Directories
        self.input_dir = Path(config.get('input_dir', 'data/output/rulegen/'))
        self.output_dir = Path(config.get('output_dir', 'data/output/evaluator/'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Components
        self.benchmark = RuleGenBenchmark(config.get('benchmark', {}))
        self.feedback_manager = FeedbackManager()
        
        # Config
        self.feedback_enabled = config.get('feedback_enabled', True)
        self.auto_iterate = config.get('auto_iterate', False)
        self.max_iterations = config.get('max_iterations', 3)
        
        self.logger = get_agent_logger(f"evaluator-{self.id}")
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        if isinstance(data, str):
            return Path(data).exists()
        return isinstance(data, dict) or isinstance(data, list)
    
    async def _execute_with_context(self, 
                                    input_data: Dict[str, Any],
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute evaluation với memory context"""
        try:
            self.set_status(AgentStatus.RUNNING)
            
            # Load rules
            rules = self._load_rules(input_data)
            if not rules:
                return {
                    'status': 'error',
                    'message': 'No rules to evaluate'
                }
            
            # Get feedback history from context
            history = context.get('history', [])
            self.logger.info(f"Evaluating {len(rules)} rules (history: {len(history)} items)")
            
            # Evaluate
            evaluation_results = await self._evaluate_batch(rules)
            
            # Generate feedback using benchmark's built-in method
            feedback = None
            if self.feedback_enabled:
                feedback = self.benchmark.generate_feedback(evaluation_results, "rulegen", history)
                
                # Write feedback to file using feedback manager
                self.feedback_manager.write_feedback("rulegen", feedback)
            
            # Use benchmark's built-in statistics instead of re-aggregating
            benchmark_stats = self.benchmark.get_statistics()
            metrics = {
                'average_score': benchmark_stats.get('average_score', 0.0),
                'total_evaluations': benchmark_stats.get('total_evaluations', 0),
                'category_averages': benchmark_stats.get('category_averages', {}),
                'metric_averages': benchmark_stats.get('metric_averages', {}),
                'score_distribution': benchmark_stats.get('score_distribution', {})
            }
            
            result = {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'rules_evaluated': len(rules),
                'metrics': metrics,
                'feedback_generated': feedback is not None,
                'history_context_size': len(history),
                'output_path': str(self.output_dir / 'evaluation_results.json')
            }
            
            self.set_status(AgentStatus.IDLE)
            return result
            
        except Exception as e:
            self.logger.error(f"Evaluation failed: {e}")
            self.set_status(AgentStatus.ERROR, str(e))
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _load_rules(self, input_data: Dict[str, Any]) -> List[Dict]:
        """Load rules từ file hoặc dict"""
        if isinstance(input_data, str):
            # File path
            filepath = Path(input_data)
            if not filepath.exists():
                # Try input_dir
                filepath = self.input_dir / input_data
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            return data.get('rules', data)
        
        elif isinstance(input_data, dict):
            return input_data.get('rules', [input_data])
        
        elif isinstance(input_data, list):
            return input_data
        
        return []
    
    async def _evaluate_batch(self, rules: List[Dict]) -> List[BenchmarkResult]:
        """Evaluate rules using benchmark framework"""
        results = await self.benchmark.evaluate_batch(rules)
        return results
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics"""
        health = await self.health_check()
        
        return {
            'agent_id': self.id,
            'agent_name': self.name,
            'status': health['status'],
            'uptime_seconds': health['uptime_seconds'],
            'benchmark_enabled': self.benchmark is not None,
            'feedback_enabled': self.feedback_enabled,
            'output_dir': str(self.output_dir),
            'input_dir': str(self.input_dir)
        }
