"""
Gemini LLM Client for AttackGen Agent
Handles communication with Google's Gemini API for attack command generation.
"""

import asyncio
import json
import os
from typing import Dict, Any, Optional, List

from google import genai
from google.genai import types

from agents.attackgen.exceptions import AttackGenException
from agents.attackgen.llm.prompt_templates import PromptTemplates


class GeminiClient:
    """
    Gemini LLM client for intelligent attack command generation.
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
            print(f"[DEBUG] Initializing Gemini client...")
            self.client = genai.Client(api_key=api_key)
            print(f"[DEBUG] Client initialized successfully")
        except Exception as e:
            print(f"[DEBUG] Initialization failed: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            raise AttackGenException(f"Failed to initialize Gemini client: {str(e)}")

    def _get_api_key(self) -> str:
        """Get Gemini API key from environment or config."""
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise AttackGenException("GEMINI_API_KEY environment variable not set")
        return api_key

    def _get_generation_config(self) -> types.GenerateContentConfig:
        """Create generation configuration object."""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
            # Safety settings to allow security testing content
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

    async def test_connection(self) -> bool:
        """Test connection to Gemini API."""
        if self.use_mock:
            return True
        
        if not self.client:
            print("[DEBUG] Client is None")
            return False
            
        try:
            print("[DEBUG] Testing connection with simple prompt...")
            txt = await self.generate_text("Test")
            success = txt is not None and len(txt) > 0
            print(f"[DEBUG] Connection test {'passed' if success else 'failed'}")
            return success
        except Exception as e:
            print(f"[DEBUG] Connection test failed: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    async def generate_commands(self, prompt: str) -> str:
        """
        Generate commands from a structured prompt.
        Returns a JSON string that the caller will parse.
        """
        try:
            return await self.generate(prompt)
        except Exception as e:
            print(f"[DEBUG] generate_commands failed: {e}")
            # Fallback to a safe mock response to avoid pipeline failure
            mock_response = {
                "commands": [
                    {
                        "name": "Safe Test Command",
                        "command": f"echo 'Test command'",
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
        """
        if self.use_mock:
            return "Mock response from Gemini"

        if not self.client:
            raise AttackGenException("Gemini client is not initialized")

        try:
            def _call():
                config = self._get_generation_config()
                # CORRECT API CALL for google-genai SDK
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config
                )
                return response

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, _call)

            # Extract text from response
            if hasattr(resp, 'text') and resp.text:
                return resp.text
            
            # Fallback: try to get from candidates
            if hasattr(resp, 'candidates') and resp.candidates:
                candidate = resp.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, 'parts') and content.parts:
                        texts = []
                        for part in content.parts:
                            if hasattr(part, 'text') and part.text:
                                texts.append(part.text)
                        if texts:
                            return ''.join(texts)

            return ""
            
        except Exception as e:
            print(f"[DEBUG] generate_text error: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
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
                config = self._get_generation_config()
                # CORRECT API CALL for google-genai SDK
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config
                )
                return response

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, _call)

            # Extract text from response
            text = None
            if hasattr(resp, 'text') and resp.text:
                text = resp.text
            elif hasattr(resp, 'candidates') and resp.candidates:
                candidate = resp.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, 'parts') and content.parts:
                        texts = []
                        for part in content.parts:
                            if hasattr(part, 'text') and part.text:
                                texts.append(part.text)
                        if texts:
                            text = ''.join(texts)

            # If no text returned, provide a safe mock JSON to keep pipeline running
            if not text:
                print("[DEBUG] No text in response, using mock")
                return self._get_mock_response()

            return text
            
        except Exception as e:
            print(f"[DEBUG] generate error: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            # Last-resort fallback to avoid breaking the pipeline
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
        except Exception as e:
            print(f"[DEBUG] enhance_command failed: {e}")
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


class MockGeminiClient(GeminiClient):
    """Mock Gemini client used for testing when the real API is unavailable."""
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        super().__init__(
            model_name=config.get("model_name", "gemini-mock"),
            temperature=config.get("temperature", 0.7),
            max_tokens=config.get("max_tokens", 2000),
            use_mock=True,
        )


def create_llm_client(config: Dict[str, Any], use_mock: bool = False):
    """
    Factory function to create LLM client for AttackGen
    if use_mock:
        return MockGeminiClient(config)
    else:
        return GeminiClient(
            - max_tokens: Maximum output tokens
            - api_key: API key (optional, will use env var)
        use_mock: If True, return MockGeminiClient for testing
        
    Returns:
        LLM client instance
    """
    if use_mock:
        return MockGeminiClient(config)
    else:
        return GeminiClient(
            model_name=config.get("model_name", "gemini-2.0-flash-lite"),
            temperature=config.get("temperature", 0.7),
            max_tokens=config.get("max_tokens", 2000),
            use_mock=False
        )