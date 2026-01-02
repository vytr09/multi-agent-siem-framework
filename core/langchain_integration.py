# -*- coding: utf-8 -*-
"""
LangChain Integration Module
Provides LangChain wrappers for the Multi-Agent SIEM Framework
"""

from typing import Dict, Any, List, Optional
import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel, Field, model_validator
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
    reasoning: str = Field(description="Reasoning for why this TTP was selected")


class TTPListOutput(BaseModel):
    """List of extracted TTPs"""
    ttps: List[TTPOutput] = Field(description="List of extracted TTPs")
    model_config = {'extra': 'ignore'}

    @model_validator(mode='before')
    @classmethod
    def validate_single_dict_to_list(cls, data: Any) -> Any:
        # Handle case where LLM returns a single TTP dict instead of a list wrapped in 'ttps'
        if isinstance(data, dict):
            # If the dict is already in correct format (has 'ttps' key which is a list)
            if 'ttps' in data and isinstance(data['ttps'], list):
                return data
            
            # If the dict looks like a single TTP object (has 'technique_name' etc)
            if 'technique_name' in data or 'technique_id' in data:
                return {'ttps': [data]}
                
        return data


class LogSourceOutput(BaseModel):
    """Log source specification"""
    category: str = Field(description="Event category (e.g., process_creation)")
    product: str = Field(description="Product (e.g., windows)")
    service: Optional[str] = Field(default=None, description="Service (e.g., sysmon)")


class SigmaRuleOutput(BaseModel):
    """Structured output for Sigma rule"""
    reasoning: str = Field(description="Chain-of-thought reasoning: Explain the detection logic, why specific fields were selected, and how false positives are handled.")
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
    reasoning: str = Field(description="Chain-of-thought reasoning: Explain how the commands demonstrate the technique and ensure safety.")
    commands: List[AttackCommandOutput] = Field(description="List of generated attack commands")
    # Removed metadata Dict[str, Any] to avoid schema issues


class RuleEvaluationOutput(BaseModel):
    """Structured output for rule evaluation"""
    reasoning: str = Field(description="Chain-of-thought reasoning: Detailed analysis of the rule's strengths, weaknesses, and verification results.")
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
    
    # Pricing per 1M tokens (as of Jan 2025)
    # Source: https://ai.google.dev/pricing, https://openai.com/pricing
    PRICING = {
        # Gemini models
        "gemini-3-flash-preview": {"input": 0.50, "output": 3.00},
        "gemini-2.5-flash": {"input": 0.15, "output": 0.60},
        "gemini-2.5-pro": {"input": 1.25, "output": 10.00},
        "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
        "gemini-2.0-flash-lite": {"input": 0.075, "output": 0.30},
        "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
        "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
        # OpenAI models  
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        # Default fallback
        "default": {"input": 0.15, "output": 0.60},
    }
    
    def __init__(self):
        self.api_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.errors = 0
        self._start_time = None
        self.total_query_time = 0.0
        self.model_name = "unknown"
        
    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """Track LLM start and begin timing"""
        import time
        self.api_calls += 1
        self._start_time = time.time()
        # Try to get model name from serialized data
        if serialized:
            self.model_name = serialized.get("kwargs", {}).get("model", 
                             serialized.get("name", self.model_name))
        
        # Fallback tracking for prompts (estimate if needed later)
        self._temp_prompt_chars = sum(len(p) for p in prompts)
    
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Track token usage and query time from response"""
        import time
        # Track query time
        if self._start_time:
            self.total_query_time += time.time() - self._start_time
            self._start_time = None
        
        # Track token usage from LangChain response
        found_tokens = False
        try:
            # Sum extracted tokens for this response
            extracted_prompt = 0
            extracted_completion = 0
            extracted_total = 0
            
            # Try to get from llm_output (OpenAI style)
            if hasattr(response, 'llm_output') and response.llm_output:
                usage = response.llm_output.get('token_usage', {}) or response.llm_output.get('usage', {})
                if usage:
                    extracted_prompt += usage.get('prompt_tokens', 0) or usage.get('input_tokens', 0)
                    extracted_completion += usage.get('completion_tokens', 0) or usage.get('output_tokens', 0)
                    extracted_total += usage.get('total_tokens', 0)
            
            # Try to get from generations (Gemini style)
            if extracted_total == 0 and hasattr(response, 'generations') and response.generations:
                for gen_list in response.generations:
                    for gen in gen_list:
                        # Method 1: generation_info
                        if hasattr(gen, 'generation_info') and gen.generation_info:
                            usage = gen.generation_info.get('usage_metadata', {})
                            if usage:
                                extracted_prompt += usage.get('prompt_token_count', 0)
                                extracted_completion += usage.get('candidates_token_count', 0)
                                extracted_total += usage.get('total_token_count', 0)
                        
                        # Method 2: response_metadata on message
                        if hasattr(gen, 'message') and hasattr(gen.message, 'response_metadata'):
                            meta = gen.message.response_metadata
                            if 'token_count' in meta:
                                extracted_prompt += meta.get('token_count', {}).get('prompt_tokens', 0)
                                extracted_completion += meta.get('token_count', {}).get('completion_tokens', 0)
                                extracted_total = extracted_prompt + extracted_completion
                            elif 'usage_metadata' in meta:
                                usage = meta['usage_metadata']
                                extracted_prompt += usage.get('prompt_token_count', 0)
                                extracted_completion += usage.get('candidates_token_count', 0)
                                extracted_total += usage.get('total_token_count', 0)

            # Add extracted tokens if valid
            if extracted_total > 0:
                self.prompt_tokens += extracted_prompt
                self.completion_tokens += extracted_completion
                self.total_tokens += extracted_total
                found_tokens = True

            # FALLBACK: Estimation if no tokens found or total is 0
            if not found_tokens or extracted_total == 0:
                # Estimate output chars
                output_chars = 0
                if hasattr(response, 'generations'):
                    for gen_list in response.generations:
                        for gen in gen_list:
                            if hasattr(gen, 'text'):
                                output_chars += len(gen.text)
                            elif hasattr(gen, 'message') and hasattr(gen.message, 'content'):
                                output_chars += len(gen.message.content)
                
                # Estimate prompt chars (from temporary storage)
                prompt_chars = getattr(self, '_temp_prompt_chars', 0)
                
                est_prompt = prompt_chars // 4
                est_completion = output_chars // 4
                
                self.prompt_tokens += est_prompt
                self.completion_tokens += est_completion
                self.total_tokens += (est_prompt + est_completion)
                
        except Exception as e:
            # Fallback to simple increment to avoid 0
            self.prompt_tokens += 100
            self.completion_tokens += 100
            print(f"Error tracking tokens: {e}")


    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Track errors and stop timing"""
        import time
        self.errors += 1
        if self._start_time:
            self.total_query_time += time.time() - self._start_time
            self._start_time = None
    
    def calculate_cost(self) -> float:
        """Calculate cost based on token usage and model pricing"""
        # Find matching pricing (handle model name variations)
        pricing = self.PRICING.get("default")
        model_lower = self.model_name.lower() if self.model_name else ""
        
        for model_key, price in self.PRICING.items():
            if model_key in model_lower or model_lower in model_key:
                pricing = price
                break
        
        input_cost = (self.prompt_tokens / 1_000_000) * pricing["input"]
        output_cost = (self.completion_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics summary (IntelEx Table V style)"""
        return {
            "api_calls": self.api_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens if self.total_tokens > 0 else self.prompt_tokens + self.completion_tokens,
            "query_time_seconds": round(self.total_query_time, 2),
            "cost_usd": round(self.calculate_cost(), 6),
            "model": self.model_name,
            "errors": self.errors
        }
    
    def reset(self):
        """Reset all metrics for a new run"""
        self.api_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.errors = 0
        self._start_time = None
        self.total_query_time = 0.0


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
            'temperature': self.config.get('temperature', 0.3),
            'max_tokens': self.config.get('max_tokens', 8000)
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
                'max_retries': 1, # Allow 1 internal retry before failing
                'timeout': 30.0, # Reduced timeout to fail faster
            }
            
            # Handle max_tokens vs max_completion_tokens for Mistral/Others
            base_url = config.get('base_url', '')
            max_tokens = config.get('max_tokens', 8000)
            
            if base_url:
                llm_kwargs['base_url'] = base_url
                
            # Mistral (via codestral endpoint) rejects max_completion_tokens, requires max_tokens
            if 'mistral' in base_url or 'codestral' in base_url:
                # Pass via model_kwargs to bypass ChatOpenAI's auto-conversion to max_completion_tokens
                llm_kwargs['model_kwargs'] = {'max_tokens': max_tokens}
            else:
                # Standard behavior (OpenAI, Cerebras seems fine with it)
                llm_kwargs['max_tokens'] = max_tokens
                
            self.llm = ChatOpenAI(**llm_kwargs, callbacks=[self.callback])
            
        else: # Gemini
            if ChatGoogleGenerativeAI is None:
                raise ImportError("langchain-google-genai not installed. Run: pip install langchain-google-genai")
            self.llm = ChatGoogleGenerativeAI(
                model=config.get('model', 'gemini-2.5-flash-lite'),
                temperature=config.get('temperature', 0.3),
                max_tokens=config.get('max_output_tokens', 8000),
                google_api_key=api_key,
                callbacks=[self.callback]
            )
            
        # print(f"[LLM] Initialized {config.get('model')} via {provider}")

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
            'max_tokens': max_tokens if max_tokens is not None else self.config.get('max_tokens', 8000)
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
                'api_key': api_key,
                'max_retries': 2, # Increased retries for stability
                'timeout': 90.0, # Increased timeout for slow providers (Cerebras/Nvidia)
            }
            base_url = config.get('base_url', '')
            max_tokens = config.get('max_tokens', 8000)
            if base_url:
                llm_kwargs['base_url'] = base_url
            if 'mistral' in base_url or 'codestral' in base_url:
                # Mistral/Codestral does NOT support max_completion_tokens (O1 param)
                # We must force max_tokens in model_kwargs and NULLIFY standard params to prevent auto-injection
                llm_kwargs['model_kwargs'] = {'max_tokens': max_tokens}
                llm_kwargs['max_tokens'] = None
                # Explicitly unset max_completion_tokens if the library supports it to prevent body injection
                llm_kwargs['max_completion_tokens'] = None 
            else:
                llm_kwargs['max_tokens'] = max_tokens
                
            return ChatOpenAI(**llm_kwargs, callbacks=[self.callback])
            
        else: # Gemini
            return ChatGoogleGenerativeAI(
                model=config.get('model', 'gemini-2.0-flash-lite'),
                temperature=config.get('temperature', 0.3),
                max_tokens=config.get('max_output_tokens', 8000),
                google_api_key=api_key,
                max_retries=0,
                callbacks=[self.callback]
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics"""
        return self.callback.get_metrics()


# ============================================================================
# TTP Extraction Chain
# ============================================================================

class TTPExtractionChain:
    """Chain for extracting TTPs from text"""
    
    @staticmethod
    def _clean_json_output(text: Any) -> str:
        """Clean LLM output to ensure valid JSON for parser"""
        if hasattr(text, "content"):
            text = text.content
        
        if not isinstance(text, str):
            return str(text)
            
        # Strip markdown code blocks
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1]
            if "```" in text:
                text = text.split("```")[0]
        elif "```" in text:
            text = text.split("```")[1]
            if "```" in text:
                text = text.split("```")[0]
                
        # Strip any leading text before the first {
        if "{" in text:
            text = "{" + text.split("{", 1)[1]
        if "}" in text:
            text = text.rsplit("}", 1)[0] + "}"
            
        return text.strip()
    
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        # Use Higher Temperature for Aggressive Extraction (Recall Focus)
        self.llm = llm_wrapper.get_llm(temperature=0.7)
        self.parser = JsonOutputParser(pydantic_object=TTPListOutput)
        
        # Create prompt template (no format_instructions needed)
        # Create prompt template (no format_instructions needed)
        # Create prompt template (no format_instructions needed)
        self.prompt = PromptTemplate(
            template="""You are a cybersecurity expert analyzing threat intelligence reports to extract TTPs (Tactics, Techniques, and Procedures).

SECTION 1: REFERENCE KNOWLEDGE (MITRE ATT&CK Context)
Use this section ONLY to look up correct Technique IDs and Names. Do NOT extract findings from here.
{context}

SECTION 2: FEW-SHOT EXAMPLES (Follow this extraction style)

Example 1:
Text: "The attacker executed a base64 encoded command using PowerShell."
Output:
{{
    "ttps": [
        {{
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "description": "Attacker used PowerShell to execute a base64 encoded command.",
            "reasoning": "The text explicitly mentions 'PowerShell' and 'base64 encoded command', which maps directly to T1059.001.",
            "indicators": ["PowerShell", "base64"],
            "confidence": 1.0,
            "tools": ["PowerShell"]
        }}
    ]
}}

Example 2:
Text: "The system downloaded 'malware.exe' from 'http://evil.com'."
Output:
{{
    "ttps": [
        {{
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": "File 'malware.exe' was downloaded from a remote URL.",
            "reasoning": "Downloading a file from a remote source corresponds to Ingress Tool Transfer (T1105).",
            "indicators": ["http://evil.com", "malware.exe"],
            "confidence": 0.9,
            "tools": []
        }}
    ]
}}

SECTION 3: REPORT TEXT (Source of Truth)
Extract TTPs found strictly within this text.
{text}

SECTION 4: TASK
Extract every single potential TTP supported by evidence in the REPORT TEXT.
**CRITICAL: Prioritize RECALL. Extract at least 5-10 distinct TTPs if the text allows.**
**List ALL potential techniques. Don't worry about False Positives (they will be filtered).**

INSTRUCTIONS:
1. Identify ALL malicious behaviors in the 'REPORT TEXT'.
2. Map behaviors to MITRE ATT&CK IDs (use REFERENCE KNOWLEDGE for lookup).
3. First, GENERATE REASONING for each potential TTP.
4. JSON Output must include the reasoning field.
5. Even if confidence is low, EXTRACT IT. Let the verifier filter it later.
6. Extract specific indicators (IPs, Domains, File paths).

OUTPUT FORMAT: JSON ONLY (No markdown formatting)
**CRITICAL:**
- Extract specific file paths (e.g. %ALLUSERSPROFILE%\\Start Menu) instead of generic ones.
- Identify Parent-Child process relationships (e.g. "Word initiated command prompt") and list them in the description or indicators.
- Do not ignore IP addresses or Domains if they appear in the text.

EXAMPLES:
Input: "The attacker used PowerShell to execute a base64 encoded command."
Output: {{
    "ttps": [{{
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Attacker used PowerShell with base64 encoding",
        "confidence": 0.9,
        "indicators": ["powershell.exe", "-enc"],
        "tools": ["PowerShell"],
        "reasoning": "The text explicitly mentions 'PowerShell' and typical command line arguments like 'encoded command'. This maps directly to T1059.001."
    }}]
}}

Return ONLY the JSON object. Do not add markdown backticks.
{format_instructions}""",
            input_variables=["text", "context"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )
        
        # Create chain (LCEL style) with cleaning
        self.chain = self.prompt | self.llm | self._clean_json_output | self.parser
        
        # print("[OK] TTP Extraction Chain created")
    
    async def extract(self, text: str, context: Optional[str] = None) -> TTPListOutput:
        """Extract TTPs from text"""
        try:
            # Provide default empty context if None
            ctx = context if context else "No additional context."
            result = await self.chain.ainvoke({"text": text, "context": ctx})
            
            # Convert Dict to Pydantic Model
            if isinstance(result, dict):
                return TTPListOutput(**result)
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
        self.parser = JsonOutputParser(pydantic_object=SigmaRuleOutput)
        self.prompt = PromptTemplate(
            input_variables=["ttp_name", "ttp_id", "tactic", "description", "indicators", "feedback", "examples"],
            template="""You are a SIEM detection engineer creating Sigma rules.

**MITRE ATT&CK Technique:**
- ID: {ttp_id}
- Name: {ttp_name}
- Tactic: {tactic}
- Description: {description}

**Indicators:**
{indicators}

**CRITICAL - Feedback from Previous Iteration:**
You MUST address the following feedback to improve the rule. If the rule failed verification, FIX the detection logic. if it had weak score, improve specificity.
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
   - **IMPORTANT:** The `detection` field must be a VALID JSON STRING representing the dictionary. Escape quotes properly.

**3. CRITICAL RULES (Strict Enforcement):**
   - **NO PIPES in condition:** Do NOT use pipes in 'condition' (e.g. `selection | count()`). This is deprecated. Use simple boolean logic (and/or/not).
   - **NO DEPRECATED MODIFIERS:** Do NOT use `|greater`, `|less`. Use standard operators or aggregations separately (though aggregations are not supported in basic matches).
   - **NO HALLUCINATIONS:** DO NOT invent IPs (e.g. 192.168.1.1), domains, or filenames. Use ONLY what is provided in the **Indicators** section.
   - **Source-Only:** If no specific IP/Domain is provided, use GENERIC behavioral patterns (e.g. command line flags like `-enc`), do not make up values.
   - **Phishing Logic:** For T1566/Phishing, detect Office processes (WINWORD.EXE) spawning command shells (cmd.exe, powershell.exe), rather than looking for specific document names unless provided.
   - **Specificity:** Weigh specific file paths (%ALLUSERSPROFILE%) higher than generic wildcards.

**4. False Positives:**
   - List legitimate scenarios that might trigger

**5. Severity:** low, medium, high, or critical

**6. Tags:** Include attack.{ttp_id} tag

INSTRUCTIONS:
1. Plan the rule logic step-by-step (analyze TTP, choose log source, construct logic, consider FPs).
2. Write this plan in the `reasoning` field.
3. Then generate the complete Sigma rule.

Generate a complete, valid Sigma rule that will actually detect this technique.

Return ONLY the JSON object. Do not add markdown backticks.
{format_instructions}""",
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )
        
        # Create chain (LCEL style) with cleaning
        self.chain = self.prompt | self.llm | TTPExtractionChain._clean_json_output | self.parser
        
        # print("[OK] Sigma Rule Chain created")
    
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
        
        if isinstance(result, dict):
            # Already a dict from JsonOutputParser
            # Convert to SigmaRuleOutput just to validation
            sigma_output = SigmaRuleOutput(**result)
            # Then dump back to dict for processing
            result_dict = sigma_output.model_dump()
            
            # Since detection is already a string in Pydantic model, it might come as string or dict from LLM depending on how it followed instructions.
            # JsonOutputParser usually parses nested JSON if the prompt asked for it, BUT our schema defines it as str.
            # If the LLM returned an object for "detection", we need to json.dumps it.
            if isinstance(result.get('detection'), dict):
                result_dict['detection'] = json.dumps(result['detection'])
            
            # Return dict directly as the agent expects it or re-wrap in SigmaRuleOutput
            # The agent expects a SigmaRuleOutput OBJECT (pydantic model) based on previous code: `sigma_output.title`
            return sigma_output

        # Legacy handling (should not be reached with new chain instructions, but keeping for safety)
        if isinstance(result, SigmaRuleOutput):
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
                    
                    # print(f"[DEBUG] Raw detection string: {detection_str}")
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
                # print(f"[ERROR] JSON/AST Decode Error: {e}")
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
        self.llm = llm_wrapper.llm
        self.parser = JsonOutputParser(pydantic_object=AttackCommandListOutput)
        self.prompt = PromptTemplate(
            input_variables=["technique_name", "technique_id", "tactic", "platform", "description", "examples"],
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
6. **Execution Robustness (CRITICAL):**
   - Use `-Force` ONLY for file operations that support it (e.g. `Compress-Archive`, `Set-Content`, `Remove-Item`). **Do NOT** use `-Force` with `Invoke-WebRequest`.
   - Use `-ErrorAction SilentlyContinue` if a cleanup step might fail.
   - **Escaping:** Ensure all quotes in PowerShell (`'`) are properly escaped or use distinct quoting (e.g. `" 'string' "`). Do NOT leave unclosed strings.


**Platform Constraints (CRITICAL):**
- **Windows**: Use ONLY built-in tools.
- **Preference**: PREFER legacy binaries (net.exe, sc.exe, whoami.exe, ipconfig.exe, certutil.exe) over PowerShell Cmdlets whenever possible, as they are cleaner for detection matching.
- **PowerShell**: Use it if no binary exists (e.g. for encoded commands). Start with `powershell -Command "..."`.
- **Do NOT use**: Python, Perl, Ruby, gcc.
- **Do NOT assume** internet access (use %TEMP% for files).

**Safety Guidelines:**
- Use test/benign strings where possible
- Avoid actual malicious payloads
- **FORBIDDEN COMMANDS:** 
    - Do NOT generate commands that recursively list the entire file system (e.g. `Get-ChildItem -Path C:\ -Recurse` or `dir C:\ /s`). These cause system freezes.
    - Do NOT use `bash`, `sh`, `awk`, `sed`, `grep` on **Windows** unless executed inside WSL (which is rarely the case for standard tests). Assume standard CMD/PowerShell.
- Mark destructive commands as high safety risk

- All commands are for TESTING ONLY in isolated environments

**PowerShell Specifics (CRITICAL Constraints):**
- **NO .NET Reflection:** Do NOT use `[System.Diagnostics.Process]::Start` or other .NET classes directly. Use standard Cmdlets like `Start-Process` or `Invoke-Item`.
- **Path Safety:** Do NOT assume directories exist (like `C:\ProgramData\_Startup`). Use `$env:TEMP`, `$env:APPDATA`, or create the directory first: `mkdir "C:\Path" -ErrorAction SilentlyContinue; ...`.
- **Encoding:** If using `EncodedCommand`, ensure Base64 is from UTF-16LE.
- If you cannot guarantee UTF-16LE, provide the plain text command instead.

    **Common Fixes:**
    - Instead of `[System.Diagnostics.Process]::Start('cmd', '/c ...')`, use `cmd.exe /c ...` or `Start-Process cmd -ArgumentList '/c ...'`.
    
    INSTRUCTIONS:
    1. Think step-by-step (analyze platform, safety, and validity).
    2. Write this thinking in the `reasoning` field.
    3. Generate the list of attack commands.
    
    Return a list of attack commands with metadata.
    
    Return ONLY the JSON object. Do not add markdown backticks.
    {format_instructions}""",
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )
        
        # Create chain (LCEL style) with cleaning
        self.chain = self.prompt | self.llm | TTPExtractionChain._clean_json_output | self.parser
        
        # print("[OK] Attack Command Generation Chain created")
    
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
        
        if isinstance(result, dict):
             return AttackCommandListOutput(**result)
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

Important: Use the verification result to ground your assessment.
- **CRITICAL:** If the rule failed to detect the attack (0 verified events) in the real SIEM, you **MUST** score Detection Coverage below 5/10.
- Check for hallucinations: If the rule contains IPs/Domains not present in the TTP info, mention this as a weakness.

Provide:
- Scores for each criterion (0-10)
- Overall score (average of all criteria)
- List of strengths
    - List of weaknesses  
    - List of improvement suggestions
    
    INSTRUCTIONS:
    1. Analyze the rule step-by-step against the criteria.
    2. Write this analysis in the `reasoning` field.
    3. Assign scores based on your analysis."""
        )
        
        # Create chain (LCEL style)
        self.chain = self.prompt | self.llm
        
        # print("[OK] Rule Evaluation Chain created")
    
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

# ============================================================================
# Verification Chain (IntelEx-Style)
# ============================================================================

class VerifierOutput(BaseModel):
    """Structured output for TTP verification"""
    is_valid: bool = Field(description="Is this TTP supported by the text?")
    confidence: float = Field(description="Confidence score (0.0 - 1.0)")
    reasoning: str = Field(description="Reasoning for validity check. Quote evidence if valid.")


class TTPVerifierChain:
    """Chain for verifying extracted TTPs (LLM-as-a-Judge)"""
    def __init__(self, llm_wrapper: LangChainLLMWrapper):
        self.llm = llm_wrapper.llm
        self.parser = JsonOutputParser(pydantic_object=VerifierOutput)
        self.prompt = PromptTemplate(
            template="""You are a strict QA auditor verifying Threat Intelligence extraction results.

Your goal is to determine if a Candidate TTP is truly supported by the provided Report Text.

REPORT TEXT:
{text}

CANDIDATE TTP:
- ID: {technique_id}
- Name: {technique_name}
- Description: {description}
- Indicators: {indicators}

TASK:
Verify if the Candidate TTP is explicitly supported by the Report Text.
- It is VALID only if there is clear evidence in the text matching the definition of the technique.
- It is INVALID if the technique is hallucinated, inferred without evidence, or mentioned only in a non-malicious context.

**CRITICAL RULES:**
1. **ALLOW LOGICAL INFERENCE:** If the text mentions specific indicators (e.g. "http://..." URL), accept the corresponding technique (e.g. T1071.001 Web Protocols) even if the exact words are missing.
2. **REJECT INCORRECT MAPPING:** If the behavior describes T1552 (File Theft) but the candidate is T1003 (OS Credential Dumping), mark INVALID. Precision matters.
3. **CONTEXTUAL FLEXIBILITY:** Browsing to a URL can be C2 (T1071) or Initial Access (T1189) depending on intent. If the action initiates the attack loop or exploits a browser, ALLOW IT. Do not be overly strict about "existing backdoor" if the behavior aligns with the technique definition.
4. **STRICT EVIDENCE CHECK:** Reject TTPs based purely on generic terms like "escalated privileges", "recon data", or "system shutdown" UNLESS specific tools (e.g. Mimikatz, exploit names) or technical artifacts are mentioned.
5. **PRESERVE STRONG MATCHES:** If a specific tool (e.g. "Copykatz", "PowerShell") is mentioned, PRESERVE the mapping even if implied.

OUTPUT FORMAT: JSON
{{
    "is_valid": boolean,
    "confidence": float (0.0 to 1.0),
    "reasoning": "Explain why based on the text..."
}}
{format_instructions}""",
            input_variables=["text", "technique_id", "technique_name", "description", "indicators"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )

        self.chain = self.prompt | self.llm | self._clean_json_output | self.parser
        
    @staticmethod
    def _clean_json_output(text: Any) -> str:
        """Clean LLM output to ensure valid JSON for parser"""
        if hasattr(text, "content"):
            text = text.content
        
        if not isinstance(text, str):
            return str(text)
            
        # Strip markdown
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1]
            if "```" in text:
                text = text.split("```")[0]
        elif "```" in text:
            text = text.split("```")[1]
            if "```" in text:
                text = text.split("```")[0]
        
        # Remove trailing commas (common JSON error)
        import re
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)
        
        return text.strip()
        
    async def verify(self, text: str, ttp: Dict[str, Any]) -> Dict[str, Any]:
        """Verify TTP against text"""
        try:
            return await self.chain.ainvoke({
                "text": text,
                "technique_id": ttp.get("technique_id"),
                "technique_name": ttp.get("technique_name"),
                "description": ttp.get("description"),
                "indicators": str(ttp.get("indicators"))
            })
        except Exception as e:
            return {"is_valid": False, "confidence": 0.0, "reasoning": f"Verification failed: {e}"}

def create_verifier_chain(llm_wrapper: LangChainLLMWrapper) -> TTPVerifierChain:
    """Create TTP verification chain"""
    return TTPVerifierChain(llm_wrapper)


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
        self.verifier_chain = create_verifier_chain(self.llm_wrapper)
        
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
