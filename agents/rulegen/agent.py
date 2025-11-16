"""
Updated RuleGen Agent with LLM-based Sigma generation
Replaces manual rule generation with Gemini API
"""

import sys
from pathlib import Path

# Add paths
sys.path.append(str(Path(__file__).resolve().parents[2]))

from typing import Dict, List, Any, Optional
import asyncio
from datetime import datetime

# Import LLM generator
from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator

# Import existing components
from agents.rulegen.sigma.optimizer import RuleOptimizer
from agents.rulegen.platforms.splunk import SplunkConverter
from agents.rulegen.platforms.elasticsearch import ElasticsearchConverter
from agents.evaluator.feedback_manager import FeedbackManager


class RuleGenerationAgentWithLLM:
    """
    RuleGen Agent with LLM-based Sigma generation
    Workflow: TTP → LLM (Gemini) → Sigma Rule → Platform Rules
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize RuleGen Agent with LLM
        
        Args:
            config: Configuration dict with:
                - platforms: List of target platforms
                - llm: LLM configuration (api_key, model, etc.)
                - optimize_rules: Enable rule optimization
                - validate_rules: Enable rule validation
                - min_confidence_threshold: Min confidence for TTPs
        """
        self.name = name
        self.config = config
        self.agent_id = 'rulegen_llm'
        
        # LLM configuration
        llm_config = config.get('llm', {})
        self.use_llm = llm_config.get('enabled', True)
        
        # Initialize LLM generator
        if self.use_llm:
            try:
                self.llm_generator = LLMSigmaGenerator(llm_config)
                print("LLM Generator initialized")
            except Exception as e:
                print(f"Failed to initialize LLM: {e}")
                print("   Falling back to manual generation")
                self.use_llm = False
                self.llm_generator = None
        else:
            self.llm_generator = None
            print("LLM generation disabled, using manual generation")
        
        # Platform converters
        self.supported_platforms = config.get('platforms', ['splunk', 'elasticsearch'])
        self.platform_converters = {}
        
        # Optimizer
        self.optimize_rules = config.get('optimize_rules', True)
        self.optimizer = RuleOptimizer(config.get('optimizer', {})) if self.optimize_rules else None
        
        # Validation
        self.validate_rules = config.get('validate_rules', True)
        
        # Thresholds
        self.min_confidence = config.get('min_confidence_threshold', 0.7)
        
        # Metrics
        self.metrics = {
            'rules_generated': 0,
            'ttps_processed': 0,
            'errors': 0,
            'llm_generations': 0,
            'fallback_generations': 0
        }

        # Feedback integration
        self.feedback_manager = FeedbackManager()
        self.use_feedback = config.get('use_feedback', True)
    
    async def _execute_with_context(self, 
                                    input_data: Dict[str, Any],
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute với feedback context"""
        # Load recent feedback
        recent_feedback = None
        if self.use_feedback:
            feedback_history = self.feedback_manager.get_feedback_history("rulegen", last_n=1)
            if feedback_history:
                recent_feedback = feedback_history[-1]
        
        # Parse TTPs (same as without feedback)
        ttps = self._parse_extraction_output(input_data)
        
        print(f"\nProcessing {len(ttps)} TTPs with feedback...")
        
        # Generate rules for each TTP with feedback
        results = []
        errors = []
        
        for idx, ttp in enumerate(ttps, 1):
            print(f"\n{idx}. Processing {ttp['attack_id']}: {ttp['technique_name']}")
            
            try:
                result = await self._generate_rule_with_feedback(ttp, recent_feedback)
                results.append(result)
                
                if result['status'] == 'success':
                    self.metrics['rules_generated'] += len(result['platform_rules'])
                    
            except Exception as e:
                print(f"   Error: {e}")
                errors.append({
                    'ttp_id': ttp.get('ttp_id'),
                    'attack_id': ttp.get('attack_id'),
                    'error': str(e)
                })
                self.metrics['errors'] += 1
        
        # Build summary and return same structure as without feedback
        summary = self._build_summary(results, 0.0)  # processing_time will be added later
        platform_stats = self._build_platform_statistics(results)
        
        return {
            'agent_id': self.agent_id,
            'status': 'success' if len(results) > 0 else 'failed',
            'summary': summary,
            'platform_statistics': platform_stats,
            'rule_generation_results': results,  # This is what the evaluator expects
            'errors': errors if errors else None,
            'agent_metrics': self.get_metrics(),
            'feedback_applied': recent_feedback is not None
        }
    
    async def _generate_rule_with_feedback(self, 
                                          ttp: Dict[str, Any],
                                          feedback: Optional[Dict]) -> Dict[str, Any]:
        """Generate rule with feedback applied - full processing like _process_single_ttp"""
        
        # Use LLM generator with feedback-enhanced TTP data
        enhanced_ttp = ttp.copy()
        if feedback:
            # Add feedback context to TTP for LLM processing
            enhanced_ttp['feedback_context'] = feedback
        
        # Step 1: Generate Sigma rule using LLM or fallback (same as _process_single_ttp)
        if self.use_llm and self.llm_generator:
            try:
                print(f"   Generating Sigma rule with LLM...")
                sigma_rule = await self.llm_generator.generate_sigma_rule(enhanced_ttp)
                self.metrics['llm_generations'] += 1
                print(f"   LLM generated: {sigma_rule.get('title')}")
            except Exception as e:
                print(f"   LLM generation failed: {e}")
                print(f"   Using fallback generation...")
                sigma_rule = self.llm_generator._generate_fallback_rule(enhanced_ttp)
                self.metrics['fallback_generations'] += 1
        else:
            # Manual fallback
            sigma_rule = self._generate_manual_sigma_rule(enhanced_ttp)
            self.metrics['fallback_generations'] += 1
        
        # Step 2: Optimize Sigma rule (same as _process_single_ttp)
        if self.optimize_rules and self.optimizer:
            sigma_rule = await self.optimizer.optimize(sigma_rule)
            print(f"   Sigma rule optimized")
        
        # Step 3: Convert to platform-specific rules (same as _process_single_ttp)
        platform_rules = {}
        
        for platform, converter in self.platform_converters.items():
            try:
                print(f"   Converting to {platform.upper()}...")
                
                # Convert
                platform_rule = await converter.convert(sigma_rule)
                
                # Validate if enabled
                if self.validate_rules:
                    is_valid = await converter.validate(platform_rule)
                    platform_rule['validated'] = is_valid
                else:
                    platform_rule['validated'] = False
                
                # Build platform_rules entry correctly
                platform_rules[platform] = {
                    'status': 'success',
                    'rule': platform_rule,
                    'syntax': converter.get_syntax_name(),
                    'validated': platform_rule.get('validated', False)
                }
                
                print(f"   {platform.upper()} rule generated")
                
            except Exception as e:
                print(f"   {platform.upper()} conversion failed: {e}")
                platform_rules[platform] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Build result (same structure as _process_single_ttp)
        result = {
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
                'processing_time': 0.0,
                'platforms_generated': [p for p, r in platform_rules.items() if r['status'] == 'success'],
                'rule_count': sum(1 for r in platform_rules.values() if r['status'] == 'success'),
                'optimized': self.optimize_rules,
                'validated': self.validate_rules,
                'llm_generated': self.use_llm,
                'feedback_applied': feedback is not None
            },
            'status': 'success'
        }
        
        self.metrics['ttps_processed'] += 1
        
        return result
    
    def _build_prompt_with_feedback(self, 
                                   ttp: Dict[str, Any],
                                   feedback: Dict[str, Any]) -> str:
        """Build prompt incorporating feedback"""
        base_prompt = self._build_prompt(ttp)
        
        # Add feedback context
        improvements = feedback.get('improvements_needed', [])
        suggestions = feedback.get('actionable_suggestions', [])
        
        feedback_context = "\n\n## Previous Feedback:\n"
        
        if improvements:
            feedback_context += "Areas to improve:\n"
            for imp in improvements:
                feedback_context += f"- {imp['metric']}: {imp['suggestion']}\n"
        
        if suggestions:
            feedback_context += "\nActionable suggestions:\n"
            for sug in suggestions:
                feedback_context += f"- {sug}\n"
        
        feedback_context += "\nPlease incorporate this feedback into the rule generation.\n"
        
        return base_prompt + feedback_context

    async def initialize(self):
        """Initialize platform converters"""
        print("\nInitializing platform converters...")
        
        for platform in self.supported_platforms:
            if platform == 'splunk':
                self.platform_converters[platform] = SplunkConverter(
                    self.config.get('splunk', {})
                )
            elif platform == 'elasticsearch':
                self.platform_converters[platform] = ElasticsearchConverter(
                    self.config.get('elasticsearch', {})
                )
            
            print(f"   {platform.upper()} converter ready")
        
        print(f"Agent initialized with {len(self.supported_platforms)} platforms")
    
    async def process(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process extraction data and generate rules
        
        Args:
            extraction_data: Output from Extractor Agent
            
        Returns:
            Rule generation results
        """
        start_time = datetime.now()
        
        print(f"\n{'='*80}")
        print(f"RULE GENERATION WITH LLM")
        print(f"{'='*80}")
        print(f"LLM Mode: {'Enabled' if self.use_llm else 'Disabled (Fallback)'}")
        print(f"Feedback Mode: {'Enabled' if self.use_feedback else 'Disabled'}")
        
        # Use feedback-enabled execution
        if self.use_feedback:
            result = await self._execute_with_context(extraction_data, {})
        else:
            # Fallback to original logic
            result = await self._execute_without_feedback(extraction_data)
        
        # Add timing and summary
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        result['processing_time'] = processing_time
        result['timestamp'] = end_time.isoformat()
        
        print(f"\nRule generation completed in {processing_time:.2f}s")
        print(f"   • Feedback applied: {result.get('feedback_applied', False)}")
        
        return result
    
    async def _execute_without_feedback(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute without feedback (original logic)"""
        # Parse TTPs
        ttps = self._parse_extraction_output(extraction_data)
        
        print(f"\nProcessing {len(ttps)} TTPs...")
        
        # Generate rules for each TTP
        results = []
        errors = []
        
        for idx, ttp in enumerate(ttps, 1):
            print(f"\n{idx}. Processing {ttp['attack_id']}: {ttp['technique_name']}")
            
            try:
                result = await self._process_single_ttp(ttp)
                results.append(result)
                
                if result['status'] == 'success':
                    self.metrics['rules_generated'] += len(result['platform_rules'])
                    
            except Exception as e:
                print(f"   Error: {e}")
                errors.append({
                    'ttp_id': ttp.get('ttp_id'),
                    'attack_id': ttp.get('attack_id'),
                    'error': str(e)
                })
                self.metrics['errors'] += 1
        
        # Build summary
        summary = self._build_summary(results, 0.0)  # processing_time will be added later
        platform_stats = self._build_platform_statistics(results)
        
        return {
            'agent_id': self.agent_id,
            'status': 'success' if len(results) > 0 else 'failed',
            'summary': summary,
            'platform_statistics': platform_stats,
            'rule_generation_results': results,
            'errors': errors if errors else None,
            'agent_metrics': self.get_metrics(),
            'feedback_applied': False
        }
    
    async def _process_single_ttp(self, ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single TTP and generate rules"""
        
        # Step 1: Generate Sigma rule using LLM or fallback
        if self.use_llm and self.llm_generator:
            try:
                print(f"   Generating Sigma rule with LLM...")
                sigma_rule = await self.llm_generator.generate_sigma_rule(ttp)
                self.metrics['llm_generations'] += 1
                print(f"   LLM generated: {sigma_rule.get('title')}")
            except Exception as e:
                print(f"   LLM generation failed: {e}")
                print(f"   Using fallback generation...")
                sigma_rule = self.llm_generator._generate_fallback_rule(ttp)
                self.metrics['fallback_generations'] += 1
        else:
            # Manual fallback
            sigma_rule = self._generate_manual_sigma_rule(ttp)
            self.metrics['fallback_generations'] += 1
        
        # Step 2: Optimize Sigma rule (FIXED - Added await)
        if self.optimize_rules and self.optimizer:
            sigma_rule = await self.optimizer.optimize(sigma_rule)
            print(f"   Sigma rule optimized")
        
        # Step 3: Convert to platform-specific rules
        platform_rules = {}
        
        for platform, converter in self.platform_converters.items():
            try:
                print(f"   Converting to {platform.upper()}...")
                
                # Convert (FIXED - Properly await and handle result)
                platform_rule = await converter.convert(sigma_rule)
                
                # Validate if enabled
                if self.validate_rules:
                    is_valid = await converter.validate(platform_rule)
                    # FIXED - Properly update the dictionary
                    platform_rule['validated'] = is_valid
                else:
                    platform_rule['validated'] = False
                
                # FIXED - Build platform_rules entry correctly
                platform_rules[platform] = {
                    'status': 'success',
                    'rule': platform_rule,
                    'syntax': converter.get_syntax_name(),
                    'validated': platform_rule.get('validated', False)
                }
                
                print(f"   {platform.upper()} rule generated")
                
            except Exception as e:
                print(f"   {platform.upper()} conversion failed: {e}")
                # Optional: Print full traceback for debugging
                import traceback
                traceback.print_exc()
                
                platform_rules[platform] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Build result
        result = {
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
                'processing_time': 0.0,
                'platforms_generated': [p for p, r in platform_rules.items() if r['status'] == 'success'],
                'rule_count': sum(1 for r in platform_rules.values() if r['status'] == 'success'),
                'optimized': self.optimize_rules,
                'validated': self.validate_rules,
                'llm_generated': self.use_llm
            },
            'status': 'success'
        }
        
        self.metrics['ttps_processed'] += 1
        
        return result
    
    def _generate_manual_sigma_rule(self, ttp: Dict[str, Any]) -> Dict:
        """Manual fallback Sigma rule generation (same as before)"""
        import uuid
        
        attack_id = ttp.get('attack_id', 'UNKNOWN')
        technique_name = ttp.get('technique_name', 'Unknown')
        description = ttp.get('description', '')
        tactic = ttp.get('tactic', 'Unknown')
        
        # Build detection based on IOCs
        indicators = self._build_indicators_from_ttp(ttp)
        
        detection = {'selection': {}, 'condition': 'selection'}
        
        # Process indicators
        process_images = [ind['value'] for ind in indicators if ind['type'] == 'process_image']
        if process_images:
            detection['selection']['Image|endswith'] = process_images[0] if len(process_images) == 1 else process_images
        
        cmdlines = [ind['value'] for ind in indicators if ind['type'] == 'command_line']
        if cmdlines:
            detection['selection']['CommandLine|contains'] = cmdlines
        
        return {
            'title': f"{technique_name} Detection",
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': description,
            'references': [f"https://attack.mitre.org/techniques/{attack_id}/"],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'modified': datetime.now().strftime('%Y/%m/%d'),
            'tags': [f"attack.{attack_id.lower()}", f"attack.{tactic.lower().replace(' ', '_')}"],
            'logsource': {'category': 'process_creation', 'product': 'windows'},
            'detection': detection,
            'falsepositives': ['Legitimate administrative activity'],
            'level': 'medium',
            'metadata': {
                'ttp_id': ttp.get('ttp_id'),
                'technique_id': attack_id,
                'confidence': ttp.get('confidence_score', 0.5),
                'generated_by': 'manual_fallback'
            }
        }
    
    def _build_indicators_from_ttp(self, ttp: Dict) -> List[Dict]:
        """Extract indicators from TTP (same as before)"""
        indicators = []
        
        # From IOCs
        iocs = ttp.get('iocs', {})
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for value in values:
                    indicators.append({'type': ioc_type, 'value': value})
        
        # From tools
        tools = ttp.get('tools', [])
        for tool in tools:
            indicators.append({'type': 'process_image', 'value': f'{tool}.exe'})
        
        return indicators
    
    def _parse_extraction_output(self, extraction_data: Dict) -> List[Dict]:
        """Parse extraction data into TTP list"""
        ttps = []
        
        extraction_results = extraction_data.get('extraction_results', [])
        
        for result in extraction_results:
            extracted_ttps = result.get('extracted_ttps', [])
            
            for ttp in extracted_ttps:
                # Filter by confidence
                if ttp.get('confidence_score', 0) >= self.min_confidence:
                    ttps.append(ttp)
        
        return ttps
    
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
        stats = {}
        
        for platform in self.supported_platforms:
            stats[platform] = {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'validated': 0
            }
        
        for result in results:
            if result['status'] == 'success':
                for platform, rule_data in result['platform_rules'].items():
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
        return {
            'agent_id': self.agent_id,
            'rules_generated': self.metrics['rules_generated'],
            'ttps_processed': self.metrics['ttps_processed'],
            'errors': self.metrics['errors'],
            'llm_generations': self.metrics['llm_generations'],
            'fallback_generations': self.metrics['fallback_generations'],
            'platforms_supported': len(self.supported_platforms),
            'optimization_enabled': self.optimize_rules,
            'validation_enabled': self.validate_rules,
            'min_confidence_threshold': self.min_confidence,
            'batch_processing_enabled': True
        }
    
    async def shutdown(self):
        """Cleanup resources"""
        print(f"\nShutting down RuleGen Agent...")
        print(f"   • Total rules generated: {self.metrics['rules_generated']}")
        print(f"   • LLM generations: {self.metrics['llm_generations']}")
        print(f"   • Fallback generations: {self.metrics['fallback_generations']}")


# Main script to test LLM integration
if __name__ == "__main__":
    import json
    import os
    
    async def test_llm_agent():
        """Test RuleGen agent with LLM"""
        
        print("\n" + "="*80)
        print("TESTING RULEGEN AGENT WITH LLM")
        print("="*80)
        
        # Load extraction data
        project_root = Path(__file__).resolve().parents[2]
        data_path = project_root / "data" / "extracted" / "hybrid_extraction_results.json"
        
        if not data_path.exists():
            print(f"Data file not found: {data_path}")
            return
        
        with open(data_path, 'r', encoding='utf-8') as f:
            extraction_data = json.load(f)
        
        hybrid_data = extraction_data.get('hybrid', {})
        
        # Configure agent with LLM
        config = {
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
            },
            'sigma': {},
            'optimizer': {},
            'splunk': {},
            'elasticsearch': {}
        }
        
        # Initialize and process
        agent = RuleGenerationAgentWithLLM(config)
        await agent.initialize()
        
        result = await agent.process(hybrid_data)
        
        # Save output
        output_dir = project_root / "data" / "generated_rules"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / "rulegen_llm_output.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        file_size = output_path.stat().st_size / 1024
        
        print("\n" + "="*80)
        print("LLM AGENT TEST COMPLETE")
        print("="*80)
        print(f"\nOutput saved to: {output_path}")
        print(f"File size: {file_size:.2f} KB")
        print(f"\nSummary:")
        print(f"  • TTPs processed: {result['summary']['total_ttps_processed']}")
        print(f"  • Rules generated: {result['summary']['total_rules_generated']}")
        print(f"  • LLM generations: {result['summary']['llm_generations']}")
        print(f"  • Fallback generations: {result['summary']['fallback_generations']}")
        
        await agent.shutdown()
    
    asyncio.run(test_llm_agent())