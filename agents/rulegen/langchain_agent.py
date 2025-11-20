"""
LangChain-Enhanced RuleGen Agent
Integrates LangChain for Sigma rule generation, inheriting from BaseRuleGenAgent.
"""

from typing import Dict, Any, Optional
import uuid

from agents.base.exceptions import AgentException
from agents.rulegen.base_rulegen_agent import BaseRuleGenAgent
from core.langchain_integration import (
    create_langchain_llm,
    create_sigma_rule_chain,
    SigmaRuleChain
)

class LangChainRuleGenAgent(BaseRuleGenAgent):
    """
    LangChain-powered Rule Generation Agent
    
    Uses LangChain for:
    - Structured Sigma rule generation
    - Automatic output parsing
    - Feedback-aware prompts
    
    Inherits optimization and platform conversion from BaseRuleGenAgent.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.sigma_chain: Optional[SigmaRuleChain] = None
        self.llm_config = config.get("llm", {})
        
    async def start(self) -> None:
        """Start the agent and initialize LangChain components"""
        await super().start()
        
        try:
            if self.langchain_enabled:
                # Initialize LangChain components
                llm_wrapper = create_langchain_llm(self.llm_config)
                self.sigma_chain = create_sigma_rule_chain(llm_wrapper)
                
                self.logger.info("LangChain RuleGen Agent started with LangChain integration")
            else:
                self.logger.info("LangChain RuleGen Agent started (LangChain disabled)")
                
        except Exception as e:
            raise AgentException(f"Failed to start LangChain components: {str(e)}")

    async def _generate_sigma_rule(self, ttp: Dict[str, Any], feedback: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate Sigma rule using LangChain.
        Implements abstract method from BaseRuleGenAgent.
        """
        ttp_id = ttp.get("technique_id", ttp.get("attack_id", "unknown"))
        
        # Prepare feedback text
        feedback_text = None
        if feedback:
            improvements = feedback.get("improvements_needed", [])
            suggestions = feedback.get("actionable_suggestions", [])
            
            if improvements or suggestions:
                feedback_text = "Previous feedback:\n"
                for imp in improvements[:3]:
                    feedback_text += f"- Improve {imp.get('metric')}: {imp.get('suggestion')}\n"
                for sug in suggestions[:3]:
                    feedback_text += f"- {sug}\n"
        
        # Generate with LangChain
        if self.langchain_enabled and self.sigma_chain:
            try:
                sigma_output = await self.sigma_chain.generate(ttp, feedback_text)
                
                # Convert Pydantic output to dict
                # SigmaRuleOutput only has: title, description, logsource, detection, falsepositives, level, tags
                from datetime import datetime
                rule = {
                    "title": sigma_output.title,
                    "id": str(uuid.uuid4()),
                    "status": "experimental",  # Default value
                    "description": sigma_output.description,
                    "references": [f"https://attack.mitre.org/techniques/{ttp_id}/"],  # Generate from TTP
                    "author": "Multi-Agent SIEM Framework",  # Default value
                    "date": datetime.now().strftime('%Y/%m/%d'),  # Generate current date
                    "modified": datetime.now().strftime('%Y/%m/%d'),  # Generate current date
                    "tags": sigma_output.tags,
                    "logsource": sigma_output.logsource,
                    "detection": sigma_output.detection,
                    "falsepositives": sigma_output.falsepositives,
                    "level": sigma_output.level,
                    "metadata": {
                        "ttp_id": ttp_id,
                        "technique_name": ttp.get("technique_name"),
                        "generation_method": "langchain"
                    }
                }
                
                self.metrics["llm_generations"] += 1
                return rule
                
            except Exception as e:
                self.logger.warning(f"LangChain generation failed for {ttp_id}: {e}, using fallback")
                return self._generate_fallback_rule(ttp)
        else:
            return self._generate_fallback_rule(ttp)

    def _generate_fallback_rule(self, ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Generate basic fallback rule"""
        self.metrics["fallback_generations"] += 1
        
        technique_name = ttp.get("technique_name", "Unknown Technique")
        attack_id = ttp.get("attack_id", "UNKNOWN")
        
        return {
            "title": f"Detection: {technique_name}",
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": ttp.get("description", f"Detects {technique_name} activity")[:200],
            "references": [f"https://attack.mitre.org/techniques/{attack_id}/"],
            "author": "Multi-Agent SIEM Framework",
            "date": "2024/01/01", # Placeholder
            "modified": "2024/01/01",
            "tags": [f"attack.{attack_id.lower()}"],
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": "suspicious"
                },
                "condition": "selection"
            },
            "falsepositives": ["Legitimate administrative activity"],
            "level": "medium",
            "metadata": {
                "ttp_id": ttp.get("ttp_id"),
                "technique_name": technique_name,
                "generation_method": "fallback"
            }
        }
