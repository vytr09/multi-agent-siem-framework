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
    """Structured output for a single attack command"""
    command: str = Field(description="The executable attack command")
    platform: str = Field(description="Target platform: windows, linux, macos")
    description: str = Field(description="What this command does")
    technique_id: str = Field(description="MITRE ATT&CK technique ID")
    requires_admin: bool = Field(default=False, description="Requires elevated privileges")
    safety_level: str = Field(default="medium", description="Safety level: low, medium, high")
    expected_behavior: str = Field(description="Expected execution behavior")


class AttackCommandListOutput(BaseModel):
    """List of attack commands"""
    commands: List[AttackCommandOutput] = Field(description="List of generated attack commands")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class RuleEvaluationOutput(BaseModel):
    """Structured output for rule evaluation"""
    detection_coverage: float = Field(description="Detection coverage score (0-10)", ge=0.0, le=10.0)
    false_positive_rate: float = Field(description="False positive rate score (0-10)", ge=0.0, le=10.0)
    performance: float = Field(description="Performance score (0-10)", ge=0.0, le=10.0)
    completeness: float = Field(description="Completeness score (0-10)", ge=0.0, le=10.0)
    overall_score: float = Field(description="Overall average score (0-10)", ge=0.0, le=10.0)
    strengths: List[str] = Field(default_factory=list, description="List of strengths")
    weaknesses: List[str] = Field(default_factory=list, description="List of weaknesses")
    suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")


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
        # Use structured output with Gemini
        self.llm = llm_wrapper.llm.with_structured_output(TTPListOutput)
        
        # Create prompt template (no format_instructions needed)
        self.prompt = PromptTemplate(
            template="""You are a cybersecurity expert analyzing threat intelligence reports.

Extract all TTPs (Tactics, Techniques, and Procedures) from the following text.
For each TTP, identify:
- MITRE ATT&CK technique ID (e.g., T1059.001)
- Technique name
- Brief description
- Confidence score (0.0 to 1.0)

Text: {text}

Return a structured list of extracted TTPs.""",
            input_variables=["text"]
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
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
        # Use structured output with Gemini
        self.llm = llm_wrapper.llm.with_structured_output(SigmaRuleOutput)
        
        # Create prompt template (no format_instructions needed)
        self.prompt = PromptTemplate(
            input_variables=["ttp_name", "ttp_id", "tactic", "description", "indicators", "feedback"],
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

**1. Log Source (MANDATORY):**
   - category: process_creation (or network_connection, file_event, etc.)
   - product: windows (or linux, macos)
   - service: sysmon (if using Sysmon events)
   Example: {{"category": "process_creation", "product": "windows"}}

**2. Detection Logic (SPECIFIC):**
   - Use field names: Image, CommandLine, ParentImage, User, DestinationIp
   - Add multiple selection criteria for accuracy
   - Use 'contains', 'endswith', 'startswith' operators
   - Example: {{"selection": {{"Image|endswith": "\\\\powershell.exe", "CommandLine|contains": "Invoke-WebRequest"}}, "condition": "selection"}}

**3. False Positives:**
   - List legitimate scenarios that might trigger

**4. Severity:** low, medium, high, or critical

**5. Tags:** Include attack.{ttp_id} tag

Generate a complete, valid Sigma rule that will actually detect this technique."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
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
# Attack Command Generation Chain
# ============================================================================

class AttackCommandGenerationChain:
    """LangChain chain for generating attack commands"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        """Initialize attack command generation chain"""
        # Use structured output with Gemini
        self.llm = llm_wrapper.llm.with_structured_output(AttackCommandListOutput)
        
        # Create prompt template (no format_instructions needed)
        self.prompt = PromptTemplate(
            input_variables=["technique_name", "technique_id", "tactic", "platform", "description"],
            template="""You are a red team operator creating attack commands for testing detection rules.

**MITRE ATT&CK Technique:**
- ID: {technique_id}
- Name: {technique_name}
- Tactic: {tactic}
- Platform: {platform}
- Description: {description}

Generate 2-3 realistic attack commands that demonstrate this technique on {platform}.

**Requirements:**
1. Commands must be executable and realistic
2. Include variations (basic, intermediate, advanced)
3. Specify if admin/root privileges required
4. Describe expected behavior
5. Mark safety level appropriately

**Safety Guidelines:**
- Use test/benign strings where possible
- Avoid actual malicious payloads
- Mark destructive commands as high safety risk
- All commands are for TESTING ONLY in isolated environments

Return a list of attack commands with metadata."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
        print("[OK] Attack Command Generation Chain created")
    
    async def generate(self, ttp_data: Dict[str, Any]) -> AttackCommandListOutput:
        """Generate attack commands for a TTP"""
        try:
            platform = ttp_data.get('platform', 'windows')
            
            result = await self.chain.ainvoke({
                "technique_name": ttp_data.get('technique_name', ttp_data.get('name', 'Unknown')),
                "technique_id": ttp_data.get('technique_id', 'T1059'),
                "tactic": ttp_data.get('tactic', 'execution'),
                "platform": platform,
                "description": ttp_data.get('description', '')[:500]
            })
            
            return result
            
        except Exception as e:
            print(f"Attack generation error: {e}")
            # Return safe default command on error
            return AttackCommandListOutput(
                commands=[
                    AttackCommandOutput(
                        command="echo 'test_command'",
                        platform=ttp_data.get('platform', 'windows'),
                        description="Default test command (generation failed)",
                        technique_id=ttp_data.get('technique_id', 'T1059'),
                        requires_admin=False,
                        safety_level="low",
                        expected_behavior="Prints test string to console"
                    )
                ],
                metadata={"error": str(e), "fallback": True}
            )


# ============================================================================
# Rule Evaluation Chain
# ============================================================================

class RuleEvaluationChain:
    """LangChain chain for rule quality evaluation"""
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        """Initialize evaluation chain"""
        # Use structured output with Gemini
        self.llm = llm_wrapper.llm.with_structured_output(RuleEvaluationOutput)
        
        # Create prompt (no JSON format instructions needed)
        self.prompt = PromptTemplate(
            input_variables=["rule_content", "ttp_info"],
            template="""You are a detection engineering expert evaluating SIEM rules.

Evaluate this Sigma rule for quality and effectiveness:

**Rule:**
{rule_content}

**Target TTP:**
{ttp_info}

Evaluate on these criteria (score each 0-10):
1. Detection Coverage: Does it catch the technique?
2. False Positive Rate: Low false positives? (higher score = fewer false positives)
3. Performance: Efficient query?
4. Completeness: All necessary fields?

Provide:
- Scores for each criterion (0-10)
- Overall score (average of all criteria)
- List of strengths
- List of weaknesses  
- List of improvement suggestions"""
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
            
            # Convert Pydantic model to dict
            if isinstance(result, RuleEvaluationOutput):
                return result.model_dump()
            return result
            
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
        self.attack_chain = create_attack_gen_chain(self.llm_wrapper)
        self.evaluation_chain = create_evaluation_chain(self.llm_wrapper)
        
        print("\n[OK] LangChain Integration Ready")
        print("="*80 + "\n")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            "llm": self.llm_wrapper.get_metrics(),
            "timestamp": datetime.utcnow().isoformat()
        }
