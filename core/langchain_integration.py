# -*- coding: utf-8 -*-
"""
LangChain Integration Module
Provides LangChain wrappers for the Multi-Agent SIEM Framework
"""

from typing import Dict, Any, List, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.callbacks import BaseCallbackHandler
from pydantic import BaseModel, Field
import os
import json
from datetime import datetime


# ============================================================================
# Output Models (Pydantic)
# ============================================================================

class TTPOutput(BaseModel):
    """Structured output for TTP extraction"""
    technique_name: str = Field(description="MITRE ATT&CK technique name")
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., T1566)")
    tactic: str = Field(description="MITRE ATT&CK tactic")
    description: str = Field(description="Detailed description of the technique")
    confidence: float = Field(description="Confidence score between 0 and 1", ge=0.0, le=1.0)
    indicators: List[str] = Field(default_factory=list, description="List of detection indicators")
    tools: List[str] = Field(default_factory=list, description="Tools/malware associated")


class TTPListOutput(BaseModel):
    """List of extracted TTPs"""
    ttps: List[TTPOutput] = Field(description="List of extracted TTPs")


class SigmaRuleOutput(BaseModel):
    """Structured output for Sigma rule"""
    title: str = Field(description="Rule title")
    description: str = Field(description="Rule description")
    logsource: Dict[str, str] = Field(description="Log source specification")
    detection: Dict[str, Any] = Field(description="Detection logic")
    falsepositives: List[str] = Field(default_factory=list, description="Known false positives")
    level: str = Field(description="Severity level: low, medium, high, critical")
    tags: List[str] = Field(default_factory=list, description="Rule tags")


class AttackCommandOutput(BaseModel):
    """Structured output for Attack Command"""
    name: str = Field(description="Descriptive name of the command")
    command: str = Field(description="The actual executable command")
    explanation: str = Field(description="Explanation of what the command does")
    indicators: List[str] = Field(default_factory=list, description="Expected detection indicators")
    prerequisites: List[str] = Field(default_factory=list, description="Prerequisites for execution")
    cleanup: str = Field(description="Cleanup instructions", default="No cleanup required")


class AttackCommandListOutput(BaseModel):
    """List of generated attack commands"""
    commands: List[AttackCommandOutput] = Field(description="List of attack commands")


# ============================================================================
# Custom Callbacks
# ============================================================================

class MetricsCallback(BaseCallbackHandler):
    """Callback to track LLM metrics"""
    
    def __init__(self):
        self.api_calls = 0
        self.total_tokens = 0
        self.errors = 0
        
    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """Track LLM start"""
        self.api_calls += 1
    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Track errors"""
        self.errors += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return {
            "api_calls": self.api_calls,
            "total_tokens": self.total_tokens,
            "errors": self.errors
        }


# ============================================================================
# LangChain LLM Wrapper
# ============================================================================

class LangChainLLMWrapper:
    """Wrapper for LangChain LLM integration"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize LangChain LLM"""
        self.config = config
        
        # Get API key
        api_key = config.get('api_key') or os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
        if not api_key:
            raise ValueError("API key required: set GEMINI_API_KEY or provide in config")
        
        # Create LLM
        self.llm = ChatGoogleGenerativeAI(
            model=config.get('model', 'gemini-2.0-flash-lite'),
            temperature=config.get('temperature', 0.3),
            max_tokens=config.get('max_output_tokens', 2000),
            google_api_key=api_key
        )
        
        # Metrics
        self.callback = MetricsCallback()
        
        print(f"[OK] LangChain LLM initialized: {config.get('model', 'gemini-2.0-flash-lite')}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics"""
        return self.callback.get_metrics()


# ============================================================================
# TTP Extraction Chain
# ============================================================================

class TTPExtractionChain:
    """Chain for extracting TTPs from text"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        self.llm = llm_wrapper.llm
        self.output_parser = PydanticOutputParser(pydantic_object=TTPListOutput)
        
        # Create prompt template
        self.prompt = PromptTemplate(
            template="""You are a cybersecurity expert analyzing threat intelligence reports.

Extract all TTPs (Tactics, Techniques, and Procedures) from the following text.
For each TTP, identify:
- MITRE ATT&CK technique ID (e.g., T1059.001)
- Technique name
- Brief description
- Confidence score (0.0 to 1.0)

Text: {text}

{format_instructions}
""",
            input_variables=["text"],
            partial_variables={"format_instructions": self.output_parser.get_format_instructions()}
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm | self.output_parser
        
        print("[OK] TTP Extraction Chain created")
    
    async def extract(self, text: str, context: Optional[str] = None) -> TTPListOutput:
        """Extract TTPs from text"""
        try:
            result = await self.chain.ainvoke({"text": text})
            return result
        except Exception as e:
            print(f"Extraction error: {e}")
            return TTPListOutput(ttps=[])


# ============================================================================
# Sigma Rule Generation Chain
# ============================================================================

class SigmaRuleChain:
    """Chain for generating Sigma rules"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        self.llm = llm_wrapper.llm
        self.parser = PydanticOutputParser(pydantic_object=SigmaRuleOutput)
        
        # Create prompt template
        self.prompt = PromptTemplate(
            input_variables=["ttp_name", "ttp_id", "tactic", "description", "indicators", "feedback"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()},
            template="""You are a SIEM detection engineer creating Sigma rules.

**MITRE ATT&CK Technique:**
- ID: {ttp_id}
- Name: {ttp_name}
- Tactic: {tactic}
- Description: {description}

**Indicators:**
{indicators}

**Feedback from Previous Iteration:**
{feedback}

Create a comprehensive Sigma rule with:
1. Clear title and description
2. Appropriate log source
3. Effective detection logic
4. Common false positives
5. Proper severity level
6. Relevant tags

{format_instructions}

Return valid JSON only."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm | self.parser
        
        print("[OK] Sigma Rule Chain created")
    
    async def generate(self, ttp_data: Dict[str, Any], feedback: Optional[str] = None) -> SigmaRuleOutput:
        """Generate Sigma rule"""
        try:
            indicators_text = "\n".join(f"- {ind}" for ind in ttp_data.get('indicators', []))
            feedback_text = feedback if feedback else "No previous feedback"
            
            result = await self.chain.ainvoke({
                "ttp_name": ttp_data.get('technique_name', ''),
                "ttp_id": ttp_data.get('technique_id', ''),
                "tactic": ttp_data.get('tactic', ''),
                "description": ttp_data.get('description', '')[:500],
                "indicators": indicators_text,
                "feedback": feedback_text
            })
            
            return result
            
        except Exception as e:
            print(f"Sigma generation error: {e}")
            # Return basic rule on error
            return SigmaRuleOutput(
                title=f"Detection: {ttp_data.get('technique_name', 'Unknown')}",
                description="Auto-generated rule",
                logsource={"category": "process_creation", "product": "windows"},
                detection={"selection": {"CommandLine|contains": "suspicious"}, "condition": "selection"},
                falsepositives=["Unknown"],
                level="medium",
                tags=[f"attack.{ttp_data.get('technique_id', 'unknown').lower()}"]
            )


# ============================================================================
# Rule Evaluation Chain
# ============================================================================

class RuleEvaluationChain:
    """LangChain chain for rule quality evaluation"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        """Initialize evaluation chain"""
        self.llm = llm_wrapper.llm
        
        # Create prompt
        self.prompt = PromptTemplate(
            input_variables=["rule_content", "ttp_info"],
            template="""You are a detection engineering expert evaluating SIEM rules.

Evaluate this Sigma rule for quality and effectiveness:

**Rule:**
{rule_content}

**Target TTP:**
{ttp_info}

Evaluate on these criteria:
1. Detection Coverage: Does it catch the technique? (0-10)
2. False Positive Rate: Low false positives? (0-10)
3. Performance: Efficient query? (0-10)
4. Completeness: All necessary fields? (0-10)

Respond in JSON format:
{{
    "detection_coverage": <score>,
    "false_positive_rate": <score>,
    "performance": <score>,
    "completeness": <score>,
    "overall_score": <average>,
    "strengths": ["list", "of", "strengths"],
    "weaknesses": ["list", "of", "weaknesses"],
    "suggestions": ["improvement", "suggestions"]
}}"""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
        print("[OK] Rule Evaluation Chain created")
    
    async def evaluate(self, rule: Dict[str, Any], ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate rule quality"""
        try:
            result = await self.chain.ainvoke({
                "rule_content": json.dumps(rule, indent=2),
                "ttp_info": json.dumps({
                    "name": ttp.get('technique_name', ''),
                    "id": ttp.get('technique_id', ''),
                    "tactic": ttp.get('tactic', '')
                }, indent=2)
            })
            
            # Parse JSON response (result is now AIMessage)
            if hasattr(result, 'content'):
                return json.loads(result.content)
            return json.loads(result)
            
        except Exception as e:
            print(f"Evaluation error: {e}")
            return {
                "detection_coverage": 5.0,
                "false_positive_rate": 5.0,
                "performance": 5.0,
                "completeness": 5.0,
                "overall_score": 5.0,
                "strengths": [],
                "weaknesses": [f"Evaluation failed: {str(e)}"],
                "suggestions": []
            }


# ============================================================================
# Attack Command Generation Chain
# ============================================================================

class AttackCommandGenerationChain:
    """Chain for generating attack commands"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        self.llm = llm_wrapper.llm
        self.parser = PydanticOutputParser(pydantic_object=AttackCommandListOutput)
        
        # Create prompt template
        self.prompt = PromptTemplate(
            input_variables=["technique_name", "technique_id", "tactic", "platform", "description", "confidence"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()},
            template="""You are a cybersecurity expert specializing in MITRE ATT&CK techniques.

Generate realistic and safe attack commands for testing purposes.

**Technique Details:**
- Name: {technique_name}
- ID: {technique_id}
- Tactic: {tactic}
- Platform: {platform}
- Description: {description}
- Confidence: {confidence}

**Requirements:**
1. Commands must be SAFE for testing environments
2. Include realistic execution methods for {platform}
3. Provide clear explanations and expected artifacts
4. Include prerequisites and cleanup instructions

{format_instructions}

Return valid JSON only."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm | self.parser
        
        print("[OK] Attack Command Generation Chain created")
    
    async def generate(self, ttp_data: Dict[str, Any], platform: str) -> AttackCommandListOutput:
        """Generate attack commands"""
        try:
            result = await self.chain.ainvoke({
                "technique_name": ttp_data.get('technique_name', ''),
                "technique_id": ttp_data.get('technique_id', '') or ttp_data.get('ttp_id', ''),
                "tactic": ttp_data.get('tactic', ''),
                "platform": platform,
                "description": ttp_data.get('description', '')[:500],
                "confidence": ttp_data.get('confidence_score', 0.5)
            })
            
            return result
            
        except Exception as e:
            print(f"Attack generation error: {e}")
            # Return empty list on error
            return AttackCommandListOutput(commands=[])


# ============================================================================
# Factory Functions
# ============================================================================

def create_langchain_llm(config: Dict[str, Any]) -> LangChainLLMWrapper:
    """Create LangChain LLM wrapper"""
    return LangChainLLMWrapper(config)


def create_ttp_extraction_chain(llm_wrapper: LangChainLLMWrapper) -> TTPExtractionChain:
    """Create TTP extraction chain"""
    return TTPExtractionChain(llm_wrapper)


def create_sigma_rule_chain(llm_wrapper: LangChainLLMWrapper) -> SigmaRuleChain:
    """Create Sigma rule generation chain"""
    return SigmaRuleChain(llm_wrapper)


def create_evaluation_chain(llm_wrapper: LangChainLLMWrapper) -> RuleEvaluationChain:
    """Create rule evaluation chain"""
    return RuleEvaluationChain(llm_wrapper)


def create_attack_gen_chain(llm_wrapper: LangChainLLMWrapper) -> AttackCommandGenerationChain:
    """Create attack command generation chain"""
    return AttackCommandGenerationChain(llm_wrapper)


# ============================================================================
# All-in-One Manager
# ============================================================================

class LangChainManager:
    """Manages all LangChain chains for the framework"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize LangChain manager"""
        print("\n" + "="*80)
        print("Initializing LangChain Integration")
        print("="*80)
        
        # Create LLM wrapper
        self.llm_wrapper = create_langchain_llm(config)
        
        # Create chains
        self.ttp_chain = create_ttp_extraction_chain(self.llm_wrapper)
        self.sigma_chain = create_sigma_rule_chain(self.llm_wrapper)
        self.evaluation_chain = create_evaluation_chain(self.llm_wrapper)
        self.attack_gen_chain = create_attack_gen_chain(self.llm_wrapper)
        
        print("\n[OK] LangChain Integration Ready")
        print("="*80 + "\n")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            "llm": self.llm_wrapper.get_metrics(),
            "timestamp": datetime.utcnow().isoformat()
        }
