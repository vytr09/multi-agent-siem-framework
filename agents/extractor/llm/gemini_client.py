"""
Gemini LLM Client for TTP extraction
Replaces OpenAI with Google Gemini API using the new google-genai SDK
"""

import asyncio
import json
from typing import Dict, Any, Optional, TYPE_CHECKING
from datetime import datetime
import random
import os
from dotenv import load_dotenv

from agents.base.exceptions import LLMException

load_dotenv()

if TYPE_CHECKING:
    from google.genai.types import GenerateContentConfig

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    genai = None
    types = None  # type: ignore
    HAS_GENAI = False


class MockGeminiClient:
    """Mock Gemini client for testing (no API calls)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.model = config.get("model", "gemini-2.0-flash-lite")
        self.api_key = config.get("api_key", "mock-key")
        
        # Template TTPs for testing
        self.template_ttps = [
            {
                "technique_name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": "Malicious emails with Office documents containing VBA macros",
                "indicators": ["malicious.doc", "macro", "email attachment"],
                "tools": ["Office", "Emotet"]
            },
            {
                "technique_name": "PowerShell",
                "tactic": "Execution",
                "description": "PowerShell commands executed for payload download and execution",
                "indicators": ["powershell.exe", "DownloadString", "IEX"],
                "tools": ["PowerShell", "Empire"]
            },
            {
                "technique_name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "LSASS memory dumping using credential extraction tools",
                "indicators": ["mimikatz", "lsass.exe", "sekurlsa"],
                "tools": ["Mimikatz"]
            },
            {
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "description": "Registry run keys modified for persistence across reboots",
                "indicators": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                "tools": []
            }
        ]
    
    async def generate(self, prompt: str, max_tokens: int = 2000,
                      temperature: float = 0.3) -> str:
        """Generate mock response with simulated delay"""
        await asyncio.sleep(0.3)  # Simulate API delay
        
        # Select random TTPs from template
        num_ttps = random.randint(2, min(4, len(self.template_ttps)))
        selected_ttps = random.sample(self.template_ttps, num_ttps)
        
        return json.dumps(selected_ttps, indent=2)
    
    async def test_connection(self) -> bool:
        """Test mock connection"""
        await asyncio.sleep(0.1)
        return True


class GeminiClient:
    """Real Gemini API client for TTP extraction using google-genai"""
    
    def __init__(self, config: Dict[str, Any]):
        if not HAS_GENAI:
            raise ImportError("google-genai package not installed. Install with: pip install google-genai")
        
        self.api_key = config.get("api_key")
        if not self.api_key:
            # Try to get from environment
            self.api_key = os.getenv("GEMINI_API_KEY")
            if not self.api_key:
                raise ValueError("Gemini API key not provided in config or GEMINI_API_KEY environment variable")
        
        self.model_name = config.get("model", "gemini-2.0-flash-lite")
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 1000)
        self.top_p = config.get("top_p", 0.95)
        self.top_k = config.get("top_k", 40)
        
        # Initialize google-genai client
        try:
            print(f"Debug: Initializing Gemini client with model: {self.model_name}")
            self.client = genai.Client(api_key=self.api_key)
            print(f"Debug: Gemini client initialized successfully")
        except Exception as e:
            print(f"Debug: Failed to initialize: {type(e).__name__}: {str(e)}")
            raise ValueError(f"Failed to initialize Gemini client: {str(e)}")
    
    def _get_generation_config(self, max_tokens: Optional[int] = None, 
                               temperature: Optional[float] = None) -> "GenerateContentConfig":
        """Create generation configuration object"""
        return types.GenerateContentConfig(
            temperature=temperature if temperature is not None else self.temperature,
            max_output_tokens=max_tokens if max_tokens is not None else self.max_tokens,
            top_p=self.top_p,
            top_k=self.top_k,
            # Safety settings for security research content
            safety_settings=[
                types.SafetySetting(
                    category='HARM_CATEGORY_HARASSMENT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_HATE_SPEECH',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_SEXUALLY_EXPLICIT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_DANGEROUS_CONTENT',
                    threshold='BLOCK_NONE'
                ),
            ]
        )
    
    async def generate(self, prompt: str, max_tokens: int = 1000,
                      temperature: float = 0.3) -> str:
        """
        Generate response using google-genai API
        
        Args:
            prompt: Input prompt for TTP extraction
            max_tokens: Maximum output tokens (overrides config if provided)
            temperature: Temperature for generation (overrides config if provided)
            
        Returns:
            Generated text response containing extracted TTPs
        """
        try:
            # Only override if different from defaults
            use_max_tokens = max_tokens if max_tokens != 1000 else None
            use_temperature = temperature if temperature != 0.3 else None
            
            # Run in thread pool to maintain async interface
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                self._generate_sync,
                prompt,
                use_max_tokens,
                use_temperature
            )
            return response
            
        except Exception as e:
            print(f"Debug: Generate error: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            raise LLMException(f"Gemini API error: {str(e)}")
    
    def _generate_sync(self, prompt: str, max_tokens: Optional[int] = None, 
                       temperature: Optional[float] = None) -> str:
        """Synchronous wrapper for google-genai generation"""
        try:
            config = self._get_generation_config(max_tokens, temperature)
            
            # CORRECT API CALL for google-genai
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            
            # Extract text from response
            if hasattr(response, 'text') and response.text:
                return response.text
            
            # Fallback: extract from candidates/parts structure
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, "parts") and content.parts:
                        texts = []
                        for part in content.parts:
                            if hasattr(part, "text") and part.text:
                                texts.append(part.text)
                        if texts:
                            return ''.join(texts)
                
                # Direct text in candidate
                if hasattr(candidate, "text") and candidate.text:
                    return candidate.text
            
            # If no text found, return empty string
            print("Debug: No text found in response")
            return ""
            
        except Exception as e:
            print(f"Debug: _generate_sync error: {type(e).__name__}: {str(e)}")
            raise Exception(f"Generation failed: {str(e)}")
    
    async def test_connection(self) -> bool:
        """Test google-genai API connection"""
        try:
            print("Debug: Testing connection...")
            test_prompt = "Respond with 'OK' only"
            response = await self.generate(test_prompt, max_tokens=10)
            success = "OK" in response or len(response) > 0
            print(f"Debug: Connection test {'passed' if success else 'failed'}")
            return success
        except Exception as e:
            print(f"Debug: Connection test error: {type(e).__name__}: {str(e)}")
            return False


def create_llm_client(config: Dict[str, Any], use_mock: bool = True):
    """
    Factory function to create LLM client for TTP extraction
    
    Args:
        config: LLM configuration dictionary with:
            - api_key: Gemini API key (optional if GEMINI_API_KEY env var is set)
            - model: Model name (default: gemini-2.0-flash-lite)
            - temperature: Generation temperature (default: 0.3)
            - max_tokens: Maximum output tokens (default: 1000)
            - top_p: Top-p sampling (default: 0.95)
            - top_k: Top-k sampling (default: 40)
        use_mock: If True, use mock client for testing
        
    Returns:
        LLM client instance (MockGeminiClient or GeminiClient)
    """
    if use_mock:
        return MockGeminiClient(config)
    else:
        return GeminiClient(config)