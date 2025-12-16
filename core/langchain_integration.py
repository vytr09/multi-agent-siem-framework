# -*- coding: utf-8 -*-
"""
LangChain Integration Module
Provides LangChain wrappers for the Multi-Agent SIEM Framework
"""

from typing import Dict, Any, List, Optional
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel, Field
import os
import json
import ast
import random
from datetime import datetime
import logging
from dataclasses import dataclass
import yaml
from pathlib import Path


# ============================================================================
# Output Models (Pydantic)
# ============================================================================

class TTPOutput(BaseModel):
    """Structured output for TTP extraction"""
    technique_name: str = Field(description="MITRE ATT&CK technique name")
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., T1566)")
    tactic: str = Field(description="MITRE ATT&CK tactic")
    description: str = Field(description="Detailed description of the technique")
    confidence: float = Field(description="Confidence score between 0 and 1")
    indicators: List[str] = Field(default_factory=list, description="List of detection indicators")
    tools: List[str] = Field(default_factory=list, description="Tools/malware associated")


class TTPListOutput(BaseModel):
    """List of extracted TTPs"""
    ttps: List[TTPOutput] = Field(description="List of extracted TTPs")


class LogSourceOutput(BaseModel):
    """Log source specification"""
    category: str = Field(description="Event category (e.g., process_creation)")
    product: str = Field(description="Product (e.g., windows)")
    service: Optional[str] = Field(default=None, description="Service (e.g., sysmon)")


class SigmaRuleOutput(BaseModel):
    """Structured output for Sigma rule"""
    title: str = Field(description="Rule title")
    description: str = Field(description="Rule description")
    logsource: LogSourceOutput = Field(description="Log source specification")
    detection: str = Field(description="Detection logic as a valid JSON string. Example: '{\"selection\": {\"Image\": \"cmd.exe\"}, \"condition\": \"selection\"}'")
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
    # Removed metadata Dict[str, Any] to avoid schema issues


class RuleEvaluationOutput(BaseModel):
    """Structured output for rule evaluation"""
    detection_coverage: float = Field(description="Detection coverage score (0-10)")
    false_positive_rate: float = Field(description="False positive rate score (0-10)")
    performance: float = Field(description="Performance score (0-10)")
    completeness: float = Field(description="Completeness score (0-10)")
    overall_score: float = Field(description="Overall average score (0-10)")
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

# ============================================================================
# Provider Rotation Logic
# ============================================================================

@dataclass
class LLMProvider:
    name: str
    type: str  # 'openai', 'gemini'
    model: str
    api_key_env: str
    priority: int = 1
    base_url: Optional[str] = None
    
    def get_api_key(self) -> Optional[str]:
        return os.getenv(self.api_key_env)

class ProviderRotationManager:
    """Manages rotation between different LLM providers"""
    
    def __init__(self, config_path: str = "config/providers.yaml"):
        self.logger = logging.getLogger("provider_manager")
        self.providers: List[LLMProvider] = self._load_providers(config_path)
        self.current_index = 0

    def _load_providers(self, config_path: str) -> List[LLMProvider]:
        """Load providers from YAML file"""
        try:
            # Resolve path relative to project root
            root_dir = Path(__file__).resolve().parents[1]
            full_path = root_dir / config_path
            
            if not full_path.exists():
                self.logger.warning(f"Provider config not found at {full_path}. Using internal defaults.")
                return self._get_default_providers()
                
            with open(full_path, 'r') as f:
                data = yaml.safe_load(f)
                
            providers = []
            for p in data.get('providers', []):
                providers.append(LLMProvider(
                    name=p['name'],
                    type=p['type'],
                    model=p['model'],
                    api_key_env=p['api_key_env'],
                    priority=p.get('priority', 99),
                    base_url=p.get('base_url')
                ))
            
            # Sort by priority
            return sorted(providers, key=lambda x: x.priority)
            
        except Exception as e:
            self.logger.error(f"Failed to load provider config: {e}")
            return self._get_default_providers()

    def _get_default_providers(self) -> List[LLMProvider]:
        """Hardcoded defaults if config fails"""
        return [
            # Cerebras (Primary - Fast & High Quality)
            LLMProvider(
                name="cerebras",
                type="openai",
                model="llama-3.3-70b",
                api_key_env="CEREBRAS_API_KEY",
                priority=1,
                base_url="https://api.cerebras.ai/v1"
            ),
            # Gemini (Secondary - Default Free Tier)
            LLMProvider(
                name="gemini",
                type="gemini",
                model="gemini-2.0-flash-lite",
                api_key_env="GEMINI_API_KEY",
                priority=2
            ),
             # OpenAI (Fallback)
            LLMProvider(
                name="openai",
                type="openai",
                model="gpt-4o",
                api_key_env="OPENAI_API_KEY",
                priority=3
            )
        ]

    def get_current_provider(self) -> LLMProvider:
        """Get currently active provider"""
        # Ensure we have a valid provider with an API key
        for _ in range(len(self.providers)):
            provider = self.providers[self.current_index]
            if provider.get_api_key():
                return provider
            # Skip if no key
            self.current_index = (self.current_index + 1) % len(self.providers)
            
        raise ValueError("No valid LLM providers found (check your API keys in .env)")

    def rotate_provider(self) -> LLMProvider:
        """Switch to next available provider"""
        self.current_index = (self.current_index + 1) % len(self.providers)
        new_provider = self.get_current_provider()
        self.logger.warning(f"Switched LLM provider to: {new_provider.name} ({new_provider.model})")
        return new_provider


# ============================================================================
# LangChain LLM Wrapper
# ============================================================================

class LangChainLLMWrapper:
    """Wrapper for LangChain LLM integration with auto-rotation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize LangChain LLM"""
        self.config = config
        self.callback = MetricsCallback()
        self.provider_manager = ProviderRotationManager()
        self.logger = logging.getLogger("llm_wrapper")
        
        # Initialize initial LLM
        self._init_llm_from_config_or_manager()
        
    def _init_llm_from_config_or_manager(self):
        """Initialize LLM based on config or fallback to manager"""
        # Try to use specific config first
        try:
            self._create_llm_instance(self.config)
        except Exception as e:
            self.logger.warning(f"Initial config failed: {e}. Falling back to provider manager.")
            self._init_from_provider(self.provider_manager.get_current_provider())

    def _init_from_provider(self, provider: LLMProvider):
        """Initialize from a provider object"""
        config = {
            'provider': provider.type,
            'model': provider.model,
            'api_key': provider.get_api_key(),
            'base_url': provider.base_url,
            'temperature': self.config.get('temperature', 0.3),
            'max_tokens': self.config.get('max_tokens', 2000)
        }
        self._create_llm_instance(config)
        self.current_provider_name = provider.name

    def _create_llm_instance(self, config: Dict[str, Any]):
        """Internal method to create the LangChain object"""
        api_key = config.get('api_key')
        
        # Resolve config variables if needed (simplified here as usually done by caller)
        if not api_key:
            # Check for legacy fallback logic or assume resolved
            provider_type = config.get('provider', 'gemini').lower()
            if provider_type == 'openai':
                api_key = os.getenv('OPENAI_API_KEY')
            else:
                api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')

        if not api_key:
            raise ValueError(f"No API key for {config.get('provider')}")

        provider = config.get('provider', 'gemini').lower()
        
        if provider == 'openai':
            if ChatOpenAI is None:
                raise ImportError("langchain-openai not installed")
                
            llm_kwargs = {
                'model': config.get('model', 'gpt-4'),
                'temperature': config.get('temperature', 0.3),
                'api_key': api_key,
                'max_retries': 0,
                'timeout': 60.0, # Increased timeout for slower providers
            }
            
            # Handle max_tokens vs max_completion_tokens for Mistral/Others
            base_url = config.get('base_url', '')
            max_tokens = config.get('max_tokens', 2000)
            
            if base_url:
                llm_kwargs['base_url'] = base_url
                
            # Mistral (via codestral endpoint) rejects max_completion_tokens, requires max_tokens
            if 'mistral' in base_url or 'codestral' in base_url:
                # Pass via model_kwargs to bypass ChatOpenAI's auto-conversion to max_completion_tokens
                llm_kwargs['model_kwargs'] = {'max_tokens': max_tokens}
            else:
                # Standard behavior (OpenAI, Cerebras seems fine with it)
                llm_kwargs['max_tokens'] = max_tokens
                
            self.llm = ChatOpenAI(**llm_kwargs)
            
        else: # Gemini
            self.llm = ChatGoogleGenerativeAI(
                model=config.get('model', 'gemini-2.5-flash-lite'),
                temperature=config.get('temperature', 0.3),
                max_tokens=config.get('max_output_tokens', 2000),
                google_api_key=api_key
            )
            
        print(f"[LLM] Initialized {config.get('model')} via {provider}")

    def rotate_provider(self):
        """Manually trigger rotation (to be called by agents on error)"""
        new_provider = self.provider_manager.rotate_provider()
        self._init_from_provider(new_provider)
        return self.llm
    
    def get_llm(self, temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> BaseChatModel:
        """Get LLM instance with optional overrides"""
        # If no overrides, return current instance
        if temperature is None and max_tokens is None:
            return self.llm
            
        # Create new config with overrides
        current_config = self.config.copy()
        if temperature is not None:
            current_config['temperature'] = temperature
        if max_tokens is not None:
            current_config['max_tokens'] = max_tokens
            
        # Re-create LLM for this request (using current provider's credentials)
        # We need to manually construct it to avoid changing self.llm
        provider = self.provider_manager.get_current_provider()
        
        # Prepare temporary config
        temp_config = {
            'provider': provider.type,
            'model': provider.model,
            'api_key': provider.get_api_key(),
            'base_url': provider.base_url,
            'temperature': temperature if temperature is not None else self.config.get('temperature', 0.3),
            'max_tokens': max_tokens if max_tokens is not None else self.config.get('max_tokens', 2000)
        }
        
        # Helper to create instance without side effects
        return self._create_llm_instance_direct(temp_config)
    
    def _create_llm_instance_direct(self, config: Dict[str, Any]) -> BaseChatModel:
        """Create LLM instance without setting self.llm"""
        api_key = config.get('api_key')
        provider = config.get('provider', 'gemini').lower()
        
        if provider == 'openai':
            if ChatOpenAI is None:
                raise ImportError("langchain-openai not installed")
            
            llm_kwargs = {
                'model': config.get('model', 'gpt-4'),
                'temperature': config.get('temperature', 0.3),
                'api_key': api_key,
                'max_retries': 0,
                'timeout': 60.0,
            }
            base_url = config.get('base_url', '')
            max_tokens = config.get('max_tokens', 2000)
            if base_url:
                llm_kwargs['base_url'] = base_url
            if 'mistral' in base_url or 'codestral' in base_url:
                llm_kwargs['model_kwargs'] = {'max_tokens': max_tokens}
            else:
                llm_kwargs['max_tokens'] = max_tokens
                
            return ChatOpenAI(**llm_kwargs)
            
        else: # Gemini
            return ChatGoogleGenerativeAI(
                model=config.get('model', 'gemini-2.0-flash-lite'),
                temperature=config.get('temperature', 0.3),
                max_tokens=config.get('max_output_tokens', 2000),
                google_api_key=api_key
            )

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

{context}

For each TTP, identify:
- MITRE ATT&CK technique ID (e.g., T1059.001)
- Technique name
- Brief description
- Confidence score (0.0 to 1.0)
- List of indicators (file names, hashes, IPs, domains, commands)
- List of tools/malware used

Text: {text}

IMPORTANT: Even if the text is short, you MUST extract at least one TTP if any attack behavior is described.
If a technique ID is mentioned (e.g., T1059.001), use it.
If keywords like "PowerShell", "cmd", "malware" are present, infer the corresponding technique.

EXAMPLES:
Input: "The attacker used PowerShell to execute a base64 encoded command."
Output: [{{
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactic": "Execution",
    "description": "Attacker used PowerShell with base64 encoding",
    "confidence": 0.9,
    "indicators": ["powershell.exe", "-enc"],
    "tools": ["PowerShell"]
}}]

Return a structured list of extracted TTPs. Ensure the output matches the TTPListOutput schema.""",
            input_variables=["text", "context"]
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
        print("[OK] TTP Extraction Chain created")
    
    async def extract(self, text: str, context: Optional[str] = None) -> TTPListOutput:
        """Extract TTPs from text"""
        try:
            # Provide default empty context if None
            ctx = context if context else "No additional context."
            result = await self.chain.ainvoke({"text": text, "context": ctx})
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

**Similar Verified Rules (Examples):**
{examples}

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
    
    async def generate(self, ttp_data: Dict[str, Any], feedback: Optional[str] = None, examples: Optional[str] = None) -> SigmaRuleOutput:
        """Generate Sigma rule"""
        indicators_text = "\n".join(f"- {ind}" for ind in ttp_data.get('indicators', []))
        feedback_text = feedback if feedback else "No previous feedback"
        examples_text = examples if examples else "No examples available"
        
        result = await self.chain.ainvoke({
            "ttp_name": ttp_data.get('technique_name', ''),
            "ttp_id": ttp_data.get('technique_id', ''),
            "tactic": ttp_data.get('tactic', ''),
            "description": ttp_data.get('description', '')[:500],
            "indicators": indicators_text,
            "feedback": feedback_text,
            "examples": examples_text
        })
        
        # Post-process: Parse detection JSON string to dict
        # This is necessary because we changed the model to use str for detection
        if isinstance(result, SigmaRuleOutput):
            # Create a new object or modify the existing one (Pydantic models are immutable by default but we can dump to dict)
            result_dict = result.model_dump()
            try:
                if isinstance(result.detection, str):
                    # Clean markdown code blocks if present
                    detection_str = result.detection.strip()
                    if detection_str.startswith("```"):
                        detection_str = detection_str.split("```")[1]
                        if detection_str.startswith("json"):
                            detection_str = detection_str[4:]
                    detection_str = detection_str.strip()
                    
                    print(f"[DEBUG] Raw detection string: {detection_str}")
                    try:
                        parsed_detection = json.loads(detection_str)
                    except json.JSONDecodeError:
                        # Try ast.literal_eval for Python dict syntax (single quotes)
                        try:
                            parsed_detection = ast.literal_eval(detection_str)
                        except (ValueError, SyntaxError):
                            raise  # Re-raise to trigger the outer exception handler
                    
                    # Ensure it's a valid JSON string for the Pydantic model
                    result.detection = json.dumps(parsed_detection)
                    
            except (json.JSONDecodeError, ValueError, SyntaxError) as e:
                print(f"[ERROR] JSON/AST Decode Error: {e}")
                # Fallback if JSON is invalid
                result.detection = json.dumps({"selection": {"CommandLine|contains": "suspicious"}, "condition": "selection"})
        
        return result


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
- Platform: {platform}
- Description: {description}

**Verified Attack Examples (for reference):**
{examples}

Generate 2-3 realistic attack commands that demonstrate this technique on {platform}.

**Requirements:**
1. Commands must be executable and realistic
2. Include variations (basic, intermediate, advanced)
3. Specify if admin/root privileges required
4. Describe expected behavior
5. Mark safety level appropriately

**Platform Constraints (CRITICAL):**
- **Windows**: Use ONLY built-in tools (PowerShell, CMD, CertUtil, Bitsadmin).
- **Start PowerShell commands with**: `powershell -Command "..."` or `powershell -EncodedCommand ...`
- **Do NOT use**: Python, Perl, Ruby, gcc, or 'base64' (use CertUtil instead).
- **Do NOT assume** internet access or specific file paths (use %TEMP%).

**Safety Guidelines:**
- Use test/benign strings where possible
- Avoid actual malicious payloads
- Mark destructive commands as high safety risk
- All commands are for TESTING ONLY in isolated environments

**PowerShell Specifics:**
- If the technique involves EncodedCommand (T1059.001), you MUST ensure the Base64 string is generated from **UTF-16LE** bytes.
- Example: "Write-Host 'Test'" -> UTF-16LE bytes -> Base64
- If you cannot guarantee UTF-16LE, provide the plain text command instead.

Return a list of attack commands with metadata."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
        print("[OK] Attack Command Generation Chain created")
    
    async def generate(self, ttp_data: Dict[str, Any], examples: Optional[str] = None) -> AttackCommandListOutput:
        """Generate attack commands for a TTP"""
        platform = ttp_data.get('platform', 'windows')
        examples_text = examples if examples else "No examples available"
        
        result = await self.chain.ainvoke({
            "technique_name": ttp_data.get('technique_name', ttp_data.get('name', 'Unknown')),
            "technique_id": ttp_data.get('technique_id', 'T1059'),
            "tactic": ttp_data.get('tactic', 'execution'),
            "platform": platform,
            "description": ttp_data.get('description', '')[:500],
            "examples": examples_text
        })
        
        return result


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
            input_variables=["rule_content", "ttp_info", "verification_result"],
            template="""You are a detection engineering expert evaluating SIEM rules.

Evaluate this Sigma rule for quality and effectiveness.

**Rule:**
{rule_content}

**Target TTP:**
{ttp_info}

**Real-World Verification Result:**
{verification_result}

Evaluate on these criteria (score each 0-10):
1. Detection Coverage: Does it catch the technique? (If verification passed, score HIGH. If failed, score LOW)
2. False Positive Rate: Low false positives? (higher score = fewer false positives)
3. Performance: Efficient query?
4. Completeness: All necessary fields?

Important: Use the verification result to ground your assessment. If the rule failed to detect the attack in the real SIEM, you MUST downgrade the Detection Coverage score and explain why in "weaknesses".

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
        # Extract verification result if available
        verification = rule.get('siem_verification', {})
        if verification:
             verification_str = json.dumps(verification, indent=2)
        else:
             verification_str = "No verification run performed."

        result = await self.chain.ainvoke({
            "rule_content": json.dumps(rule, indent=2),
            "ttp_info": json.dumps({
                "name": ttp.get('technique_name', ''),
                "id": ttp.get('technique_id', ''),
                "tactic": ttp.get('tactic', '')
            }, indent=2),
            "verification_result": verification_str
        })
        
        # Convert Pydantic model to dict
        if isinstance(result, RuleEvaluationOutput):
            return result.model_dump()
        return result


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
    
    def get_chat_model(self, temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> BaseChatModel:
        """Get underlying chat model"""
        return self.llm_wrapper.get_llm(temperature, max_tokens)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            "llm": self.llm_wrapper.get_metrics(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def rotate_provider(self):
        """Force rotation of LLM provider"""
        print(f"[LangChainManager] Rotating LLM provider...")
        return self.llm_wrapper.rotate_provider()
# ============================================================================
# Global Accessor
# ============================================================================

_llm_manager_instance: Optional[LangChainManager] = None

def get_llm_manager(config: Optional[Dict[str, Any]] = None) -> LangChainManager:
    """Get or create singleton LLM manager"""
    global _llm_manager_instance
    if _llm_manager_instance is None:
        if config is None:
            config = {} # Defaults
        _llm_manager_instance = LangChainManager(config)
    return _llm_manager_instance
