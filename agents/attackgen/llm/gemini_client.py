# agents/attackgen/llm/gemini_client.py
"""
Gemini LLM Client for AttackGen Agent.
Handles communication with Google's Gemini API for attack command generation.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

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
        use_mock: bool = False
    ):
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.use_mock = use_mock
        
        self.model = None
        self.prompt_templates = PromptTemplates()
        
        if not use_mock:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize Gemini API client"""
        try:
            # Configure Gemini API
            genai.configure(api_key=self._get_api_key())
            
            # Initialize model with safety settings
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=genai.types.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens,
                ),
                safety_settings={
                    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                }
            )
            
        except Exception as e:
            raise AttackGenException(f"Failed to initialize Gemini client: {str(e)}")
    
    def _get_api_key(self) -> str:
        """Get Gemini API key from environment or config"""
        import os
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise AttackGenException("GEMINI_API_KEY environment variable not set")
        return api_key
    
    async def test_connection(self) -> bool:
        """Test connection to Gemini API"""
        if self.use_mock:
            return True
        
        try:
            response = await self.generate_text("Test connection")
            return response is not None
        except Exception:
            return False
    
    async def generate_commands(self, prompt: str) -> str:
        """Generate attack commands using Gemini"""
        if self.use_mock:
            return self._get_mock_response()
        
        try:
            # Generate response using Gemini
            response = self.model.generate_content(prompt)
            
            if response.text:
                return response.text
            else:
                raise AttackGenException("Empty response from Gemini")
                
        except Exception as e:
            raise AttackGenException(f"Gemini API call failed: {str(e)}")
    
    async def generate_text(self, prompt: str) -> str:
        """Generate general text using Gemini"""
        if self.use_mock:
            return "Mock response from Gemini"
        
        try:
            response = self.model.generate_content(prompt)
            return response.text or ""
        except Exception as e:
            raise AttackGenException(f"Text generation failed: {str(e)}")
    
    async def enhance_command(
        self, 
        base_command: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enhance existing command with LLM insights"""
        
        prompt = self.prompt_templates.get_enhancement_prompt(base_command, context)
        
        try:
            response = await self.generate_commands(prompt)
            enhanced_data = json.loads(response)
            
            # Merge enhanced data with base command
            enhanced_command = base_command.copy()
            enhanced_command.update(enhanced_data)
            
            return enhanced_command
            
        except Exception as e:
            # Return original command if enhancement fails
            return base_command
    
    def _get_mock_response(self) -> str:
        """Get mock response for testing"""
        return json.dumps({
            "commands": [
                {
                    "name": "Mock PowerShell Command",
                    "command": "Get-Process | Where-Object {$_.ProcessName -eq 'explorer'}",
                    "explanation": "This is a mock command for testing purposes",
                    "indicators": ["PowerShell execution", "Process enumeration"],
                    "prerequisites": ["PowerShell available"],
                    "cleanup": "No cleanup required"
                }
            ]
        })