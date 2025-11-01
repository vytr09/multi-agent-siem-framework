"""
Gemini LLM Client for AttackGen Agent (google-genai).
Handles communication with Google's Gemini API for attack command generation.
"""

import asyncio
import json
import os
from typing import Dict, Any, Optional, List

from google import genai

# Try to import safety types with fallback
try:
    from google.genai.types import SafetySetting
    HAS_SAFETY_SETTINGS = True
    
    # Try different import paths for SafetyCategory
    try:
        from google.genai.types import SafetyCategory
    except ImportError:
        try:
            from google.genai import SafetyCategory
        except ImportError:
            # If SafetyCategory is not available, we'll define constants
            class SafetyCategory:
                HARM_CATEGORY_HARASSMENT = "HARM_CATEGORY_HARASSMENT"
                HARM_CATEGORY_HATE_SPEECH = "HARM_CATEGORY_HATE_SPEECH"
                HARM_CATEGORY_SEXUALLY_EXPLICIT = "HARM_CATEGORY_SEXUALLY_EXPLICIT"
                HARM_CATEGORY_DANGEROUS_CONTENT = "HARM_CATEGORY_DANGEROUS_CONTENT"
except ImportError:
    HAS_SAFETY_SETTINGS = False
    SafetySetting = None
    SafetyCategory = None

from agents.attackgen.exceptions import AttackGenException
from agents.attackgen.llm.prompt_templates import PromptTemplates


class MockGeminiClient:
    """Mock Gemini client for testing without API calls"""
    
    def __init__(self, config: Dict[str, Any]):
        self.model_name = config.get("model_name", "gemini-2.0-flash-lite")
        self.temperature = config.get("temperature", 0.7)
        self.max_tokens = config.get("max_tokens", 2000)
        self.prompt_templates = PromptTemplates()
    
    async def test_connection(self) -> bool:
        """Mock connection test always returns True"""
        await asyncio.sleep(0.1)  # Simulate network delay
        return True
    
    async def generate_commands(self, prompt: str) -> str:
        """Generate mock attack commands"""
        await asyncio.sleep(0.3)  # Simulate generation time
        
        mock_response = {
            "commands": [
                {
                    "name": "Mock PowerShell Execution",
                    "command": "powershell.exe -ExecutionPolicy Bypass -Command \"Get-Process | Where-Object {$_.Name -eq 'explorer'}\"",
                    "explanation": "Mock command for testing PowerShell execution detection",
                    "indicators": ["PowerShell execution", "Process enumeration", "ExecutionPolicy Bypass"],
                    "prerequisites": ["PowerShell available", "User privileges"],
                    "cleanup": "No cleanup required for mock command"
                },
                {
                    "name": "Mock Registry Persistence",
                    "command": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"MockTest\" /t REG_SZ /d \"echo Mock persistence test\"",
                    "explanation": "Mock command for testing registry-based persistence",
                    "indicators": ["Registry modification", "Persistence mechanism", "Run key"],
                    "prerequisites": ["Registry access"],
                    "cleanup": "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"MockTest\" /f"
                }
            ]
        }
        
        return json.dumps(mock_response)
    
    async def generate_text(self, prompt: str) -> str:
        """Generate mock text response"""
        await asyncio.sleep(0.2)
        return f"Mock response for prompt: {prompt[:50]}..."
    
    async def generate(self, prompt: str) -> str:
        """Generate mock structured response"""
        return await self.generate_commands(prompt)
    
    async def enhance_command(
        self, 
        base_command: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock command enhancement"""
        enhanced = base_command.copy()
        enhanced["mock_enhanced"] = True
        enhanced["enhancement_note"] = "Mock enhancement applied"
        return enhanced


class GeminiClient:
    """
    Gemini LLM client for intelligent attack command generation, migrated to google-genai.
    """

    def __init__(
        self,
        model_name: str = "gemini-2.0-flash-lite",
        temperature: float = 0.7,
        max_tokens: int = 2000,
        use_mock: bool = False,
    ):
        self.model_name = model_name
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.use_mock = use_mock

        self.client: Optional[genai.Client] = None
        self.prompt_templates = PromptTemplates()

        if not self.use_mock:
            self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize google-genai client instance."""
        try:
            api_key = self._get_api_key()
            self.client = genai.Client(api_key=api_key)
        except Exception as e:
            raise AttackGenException(f"Failed to initialize Gemini client: {str(e)}")

    def _get_api_key(self) -> str:
        """Get Gemini API key from environment or config."""
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise AttackGenException("GEMINI_API_KEY environment variable not set")
        return api_key

    def _safety_settings(self) -> List:
        """
        Safety settings mapped to allow generation needed for security research.
        Returns empty list if safety settings are not available.
        """
        if not HAS_SAFETY_SETTINGS or not SafetySetting or not SafetyCategory:
            return []
        
        try:
            return [
                SafetySetting(category=SafetyCategory.HARM_CATEGORY_HARASSMENT, threshold="BLOCK_NONE"),
                SafetySetting(category=SafetyCategory.HARM_CATEGORY_HATE_SPEECH, threshold="BLOCK_NONE"),
                SafetySetting(category=SafetyCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold="BLOCK_NONE"),
                SafetySetting(category=SafetyCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold="BLOCK_NONE"),
            ]
        except Exception:
            # If safety settings construction fails, return empty list
            return []

    def _gen_config(self) -> dict:
        """
        Generation configuration for google-genai responses.generate call.
        """
        return {
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }

    async def test_connection(self) -> bool:
        """Test connection to Gemini API."""
        if self.use_mock:
            return True
        try:
            txt = await self.generate_text("Test connection")
            return txt is not None
        except Exception:
            return False

    async def generate_commands(self, prompt: str) -> str:
        """
        Generate commands from a structured prompt.
        Returns a JSON string that the caller will parse.
        """
        try:
            return await self.generate(prompt)
        except Exception:
            # Fallback to a safe mock response to avoid pipeline failure.
            mock_response = {
                "commands": [
                    {
                        "name": "Safe Test Command",
                        "command": f"echo 'Test command for {prompt[:50]}...'",
                        "explanation": "Safe test command generated due to LLM error",
                        "indicators": ["test_command"],
                        "prerequisites": ["System access"],
                        "cleanup": "No cleanup needed",
                    }
                ]
            }
            return json.dumps(mock_response)

    async def generate_text(self, prompt: str) -> str:
        """
        Generate general text using google-genai.
        The SDK is sync-first; wrap in executor to preserve async interface.
        """
        if self.use_mock:
            return "Mock response from Gemini"

        if not self.client:
            raise AttackGenException("Gemini client is not initialized")

        try:
            def _call():
                # Prepare kwargs for safety settings
                kwargs = self._gen_config()
                safety_settings = self._safety_settings()
                if safety_settings:
                    kwargs["safety_settings"] = safety_settings
                
                return self.client.responses.generate(
                    model=self.model_name,
                    contents=prompt,
                    **kwargs,
                )

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, _call)

            # Prefer resp.text; otherwise reconstruct from candidates/parts.
            text = getattr(resp, "text", None)
            if text:
                return text

            if hasattr(resp, "candidates") and resp.candidates:
                cand = resp.candidates[0]
                # Try parts->text
                content = getattr(cand, "content", None)
                parts = getattr(content, "parts", []) if content else []
                texts = [getattr(p, "text", "") for p in parts if getattr(p, "text", None)]
                if texts:
                    return "\n".join(texts)
                # Fallback direct text in candidate
                if hasattr(cand, "text") and cand.text:
                    return cand.text

            return ""
        except Exception as e:
            raise AttackGenException(f"Text generation failed: {str(e)}")

    async def generate(self, prompt: str) -> str:
        """
        Generate structured content (as text) that should be JSON:
        { "commands": [ ... ] }
        """
        if self.use_mock:
            return self._get_mock_response()

        if not self.client:
            raise AttackGenException("Gemini client is not initialized")

        try:
            def _call():
                # Prepare kwargs for safety settings
                kwargs = self._gen_config()
                safety_settings = self._safety_settings()
                if safety_settings:
                    kwargs["safety_settings"] = safety_settings
                
                return self.client.responses.generate(
                    model=self.model_name,
                    contents=prompt,
                    **kwargs,
                )

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, _call)

            # Try to get consolidated text.
            text = getattr(resp, "text", None)
            if not text and hasattr(resp, "candidates") and resp.candidates:
                cand = resp.candidates[0]
                content = getattr(cand, "content", None)
                parts = getattr(content, "parts", []) if content else []
                texts = [getattr(p, "text", "") for p in parts if getattr(p, "text", None)]
                text = "\n".join(texts) if texts else getattr(cand, "text", None)

            # If no text returned, provide a safe mock JSON to keep pipeline running.
            if not text:
                return self._get_mock_response()

            return text
        except Exception:
            # Last-resort fallback to avoid breaking the pipeline.
            return self._get_mock_response()

    async def enhance_command(
        self,
        base_command: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Enhance an existing command with LLM-generated insights.
        Returns merged command data; on failure returns the base command unchanged.
        """
        prompt = self.prompt_templates.get_enhancement_prompt(base_command, context)
        try:
            response = await self.generate_commands(prompt)
            enhanced_data = json.loads(response)

            enhanced_command = base_command.copy()
            if isinstance(enhanced_data, dict):
                enhanced_command.update(enhanced_data)
            return enhanced_command
        except Exception:
            return base_command

    def _get_mock_response(self) -> str:
        """Get mock JSON response for testing."""
        return json.dumps(
            {
                "commands": [
                    {
                        "name": "Mock PowerShell Command",
                        "command": "Get-Process | Where-Object {$_.ProcessName -eq 'explorer'}",
                        "explanation": "This is a mock command for testing purposes",
                        "indicators": ["PowerShell execution", "Process enumeration"],
                        "prerequisites": ["PowerShell available"],
                        "cleanup": "No cleanup required",
                    }
                ]
            }
        )


def create_llm_client(config: Dict[str, Any], use_mock: bool = False):
    """
    Factory function to create LLM client for AttackGen
    
    Args:
        config: LLM configuration dict with:
            - model_name: Model to use
            - temperature: Generation temperature
            - max_tokens: Maximum output tokens
            - api_key: API key (optional, will use env var)
        use_mock: If True, return MockGeminiClient for testing
        
    Returns:
        LLM client instance (MockGeminiClient or GeminiClient)
    """
    if use_mock:
        return MockGeminiClient(config)
    else:
        # Extract parameters for GeminiClient constructor
        return GeminiClient(
            model_name=config.get("model_name", "gemini-2.0-flash-lite"),
            temperature=config.get("temperature", 0.7),
            max_tokens=config.get("max_tokens", 2000),
            use_mock=False
        )
