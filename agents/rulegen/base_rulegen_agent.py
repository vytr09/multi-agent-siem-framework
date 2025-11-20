"""
Base RuleGen Agent
Provides common functionality for rule generation, optimization, and platform conversion.
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from abc import abstractmethod

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import AgentException
from agents.rulegen.sigma.optimizer import RuleOptimizer
from agents.rulegen.platforms.splunk import SplunkConverter
from agents.rulegen.platforms.elasticsearch import ElasticsearchConverter
from agents.evaluator.feedback_manager import FeedbackManager
from core.logging import get_agent_logger

class BaseRuleGenAgent(BaseAgent):
    """
    Base class for Rule Generation Agents.
    Handles the common pipeline:
    1. Generate Sigma Rule (Abstract)
    2. Optimize Sigma Rule
    3. Convert to Platform Rules
    4. Track Statistics
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Configuration
        self.supported_platforms = config.get('platforms', ['splunk', 'elasticsearch'])
        self.min_confidence = config.get('min_confidence_threshold', 0.7)
        self.optimize_rules = config.get('optimize_rules', True)
        self.validate_rules = config.get('validate_rules', True)
        
        # Components
        self.platform_converters = {}
        self.optimizer = RuleOptimizer(config.get('optimizer', {})) if self.optimize_rules else None
        self.feedback_manager = FeedbackManager()
        self.use_feedback = config.get('use_feedback', True)
        
        # Metrics
        self.metrics = {
            'rules_generated': 0,
            'ttps_processed': 0,
            'errors': 0,
            'llm_generations': 0,
            'fallback_generations': 0,
            'platforms_supported': len(self.supported_platforms)
        }
        
        self.logger = get_agent_logger(f"{name}", self.id)

    async def start(self) -> None:
        """Start the agent and initialize components"""
        await super().start()
        
        self.logger.info("Initializing platform converters...")
        
        for platform in self.supported_platforms:
            try:
                if platform == 'splunk':
                    self.platform_converters[platform] = SplunkConverter(
                        self.config.get('splunk', {})
                    )
                    await self.platform_converters[platform].initialize()
                elif platform == 'elasticsearch':
                    self.platform_converters[platform] = ElasticsearchConverter(
                        self.config.get('elasticsearch', {})
                    )
                    # Elasticsearch converter might not have initialize, check first
                    if hasattr(self.platform_converters[platform], 'initialize'):
                        await self.platform_converters[platform].initialize()
                
                self.logger.info(f"{platform.upper()} converter ready")
            except Exception as e:
                self.logger.error(f"Failed to initialize {platform} converter: {e}")
        
        self.logger.info(f"Agent initialized with {len(self.platform_converters)} platforms")

    async def stop(self) -> None:
        """Stop the agent"""
        for platform, converter in self.platform_converters.items():
            if hasattr(converter, 'shutdown'):
                await converter.shutdown()
        await super().stop()

    @abstractmethod
    async def _generate_sigma_rule(self, ttp: Dict[str, Any], feedback: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate a Sigma rule from TTP data.
        Must be implemented by subclasses.
        """
        pass

    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rule generation pipeline"""
        start_time = datetime.now()
        
        # Load recent feedback
        recent_feedback = None
        if self.use_feedback:
            feedback_history = self.feedback_manager.get_feedback_history("rulegen", last_n=1)
            if feedback_history:
                recent_feedback = feedback_history[-1]
        
        # Parse TTPs
        ttps = self._parse_extraction_output(input_data)
        
        self.logger.info(f"Processing {len(ttps)} TTPs...")
        
        results = []
        errors = []
        
        for idx, ttp in enumerate(ttps, 1):
            try:
                self.logger.info(f"Processing {ttp.get('attack_id', 'Unknown')}: {ttp.get('technique_name', 'Unknown')}")
                result = await self._process_single_ttp(ttp, recent_feedback)
                results.append(result)
                
                if result['status'] == 'success':
                    self.metrics['rules_generated'] += len(result['platform_rules'])
                    
            except Exception as e:
                self.logger.error(f"Error processing TTP: {e}")
                errors.append({
                    'ttp_id': ttp.get('ttp_id'),
                    'attack_id': ttp.get('attack_id'),
                    'error': str(e)
                })
                self.metrics['errors'] += 1
        
        # Build summary
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        summary = self._build_summary(results, processing_time)
        platform_stats = self._build_platform_statistics(results)
        
        return {
            'agent_id': self.id,
            'status': 'success' if len(results) > 0 else 'failed',
            'summary': summary,
            'platform_statistics': platform_stats,
            'rule_generation_results': results,
            'errors': errors if errors else None,
            'agent_metrics': self.get_metrics(),
            'feedback_applied': recent_feedback is not None,
            'processing_time': processing_time,
            'timestamp': end_time.isoformat()
        }

    async def _process_single_ttp(self, ttp: Dict[str, Any], feedback: Optional[Dict] = None) -> Dict[str, Any]:
        """Process a single TTP through the pipeline"""
        
        # 1. Generate Sigma Rule
        sigma_rule = await self._generate_sigma_rule(ttp, feedback)
        
        # 2. Optimize Sigma Rule
        if self.optimize_rules and self.optimizer:
            sigma_rule = await self.optimizer.optimize(sigma_rule)
            self.logger.debug("Sigma rule optimized")
            
        # 3. Convert to Platforms
        platform_rules = {}
        
        for platform, converter in self.platform_converters.items():
            try:
                # Convert
                platform_rule = await converter.convert(sigma_rule)
                
                # Validate
                is_valid = False
                if self.validate_rules:
                    is_valid = await converter.validate(platform_rule)
                    platform_rule['validated'] = is_valid
                else:
                    platform_rule['validated'] = False
                
                platform_rules[platform] = {
                    'status': 'success',
                    'rule': platform_rule,
                    'syntax': converter.get_syntax_name(),
                    'validated': platform_rule.get('validated', False)
                }
                
            except Exception as e:
                self.logger.warning(f"{platform.upper()} conversion failed: {e}")
                platform_rules[platform] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        # 4. Build Result
        return {
            'ttp_id': ttp.get('ttp_id'),
            'ttp_name': ttp.get('technique_name'),
            'technique_name': ttp.get('technique_name'),
            'attack_id': ttp.get('attack_id'),
            'tactic': ttp.get('tactic'),
            'confidence_score': ttp.get('confidence_score'),
            'sigma_rule': sigma_rule,
            'platform_rules': platform_rules,
            'source_info': {
                'report_id': ttp.get('report_id'),
                'extraction_method': ttp.get('extraction_method'),
                'mapped_by': ttp.get('mapped_by'),
                'source_report': ttp.get('source_report', {}),
                'threat_actor': ttp.get('context', {}).get('threat_actor', '')
            },
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'processing_time': 0.0, # Can be refined
                'platforms_generated': [p for p, r in platform_rules.items() if r['status'] == 'success'],
                'rule_count': sum(1 for r in platform_rules.values() if r['status'] == 'success'),
                'optimized': self.optimize_rules,
                'validated': self.validate_rules,
                'feedback_applied': feedback is not None
            },
            'status': 'success'
        }

    def _parse_extraction_output(self, input_data: Dict) -> List[Dict]:
        """Parse extraction data into TTP list"""
        # Handle different input formats
        if "ttps" in input_data:
            ttps = input_data["ttps"]
        elif "extracted_ttps" in input_data:
            ttps = input_data["extracted_ttps"]
        elif "extraction_results" in input_data:
            ttps = []
            for result in input_data["extraction_results"]:
                ttps.extend(result.get("extracted_ttps", []))
        else:
            ttps = []
            
        # Filter by confidence
        return [t for t in ttps if t.get('confidence_score', 0) >= self.min_confidence]

    def _build_summary(self, results: List[Dict], processing_time: float) -> Dict:
        """Build summary statistics"""
        successful = sum(1 for r in results if r['status'] == 'success')
        failed = len(results) - successful
        
        total_rules = sum(
            r['metadata']['rule_count'] 
            for r in results 
            if r['status'] == 'success'
        )
        
        return {
            'total_ttps_processed': len(results),
            'successful': successful,
            'failed': failed,
            'total_rules_generated': total_rules,
            'platforms': self.supported_platforms,
            'processing_time': processing_time,
            'llm_generations': self.metrics['llm_generations'],
            'fallback_generations': self.metrics['fallback_generations']
        }

    def _build_platform_statistics(self, results: List[Dict]) -> Dict:
        """Build per-platform statistics"""
        stats = {p: {'total': 0, 'successful': 0, 'failed': 0, 'validated': 0} for p in self.supported_platforms}
        
        for result in results:
            if result['status'] == 'success':
                for platform, rule_data in result['platform_rules'].items():
                    if platform in stats:
                        stats[platform]['total'] += 1
                        if rule_data['status'] == 'success':
                            stats[platform]['successful'] += 1
                            if rule_data.get('validated', False):
                                stats[platform]['validated'] += 1
                        else:
                            stats[platform]['failed'] += 1
        return stats

    def get_metrics(self) -> Dict:
        """Get agent metrics"""
        return self.metrics
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        return any(k in data for k in ["extraction_results", "ttps", "extracted_ttps"])
