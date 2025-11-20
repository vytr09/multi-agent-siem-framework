"""
Updated RuleGen Agent with LLM-based Sigma generation
Replaces manual rule generation with Gemini API, inheriting from BaseRuleGenAgent.
"""

import sys
from pathlib import Path

# Add paths
sys.path.append(str(Path(__file__).resolve().parents[2]))

from typing import Dict, List, Any, Optional
import asyncio
from datetime import datetime
import uuid

from agents.rulegen.base_rulegen_agent import BaseRuleGenAgent
from agents.rulegen.llm_sigma_generator import LLMSigmaGenerator

class RuleGenerationAgentWithLLM(BaseRuleGenAgent):
    """
    RuleGen Agent with LLM-based Sigma generation
    Workflow: TTP → LLM (Gemini) → Sigma Rule → Platform Rules
    Inherits optimization and platform conversion from BaseRuleGenAgent.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.agent_id = 'rulegen_llm' # Keep for backward compatibility
        
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

    async def initialize(self):
        """Initialize platform converters (Compatibility alias)"""
        await self.start()

    async def process(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process extraction data (Compatibility alias for execute)
        """
        return await self.execute(extraction_data)

    async def _generate_sigma_rule(self, ttp: Dict[str, Any], feedback: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate Sigma rule using LLMSigmaGenerator or fallback.
        Implements abstract method from BaseRuleGenAgent.
        """
        # Prepare TTP with feedback
        enhanced_ttp = ttp.copy()
        if feedback:
            enhanced_ttp['feedback_context'] = feedback
            
        # Step 1: Generate Sigma rule using LLM or fallback
        if self.use_llm and self.llm_generator:
            try:
                print(f"   Generating Sigma rule with LLM...")
                sigma_rule = await self.llm_generator.generate_sigma_rule(enhanced_ttp)
                self.metrics['llm_generations'] += 1
                print(f"   LLM generated: {sigma_rule.get('title')}")
                return sigma_rule
            except Exception as e:
                print(f"   LLM generation failed: {e}")
                print(f"   Using fallback generation...")
                self.metrics['fallback_generations'] += 1
                return self.llm_generator._generate_fallback_rule(enhanced_ttp)
        else:
            # Manual fallback
            self.metrics['fallback_generations'] += 1
            return self._generate_manual_sigma_rule(enhanced_ttp)

    def _generate_manual_sigma_rule(self, ttp: Dict[str, Any]) -> Dict:
        """Manual fallback Sigma rule generation (same as before)"""
        
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

    async def shutdown(self):
        """Cleanup resources (Compatibility alias)"""
        await self.stop()
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
        agent = RuleGenerationAgentWithLLM("test_rulegen", config)
        await agent.start()
        
        result = await agent.execute(hybrid_data)
        
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
        
        await agent.stop()
    
    asyncio.run(test_llm_agent())