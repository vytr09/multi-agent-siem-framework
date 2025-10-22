"""
Gemini LLM Client for TTP extraction
Replaces OpenAI with Google Gemini API
"""

import asyncio
import json
from typing import Dict, Any, Optional
from datetime import datetime
import random
import os
from dotenv import load_dotenv

from agents.base.exceptions import LLMException

load_dotenv()

try:
    import google.generativeai as genai
except ImportError:
    genai = None


class MockGeminiClient:
    """Mock Gemini client for testing (no API calls)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.model = config.get("model", "gemini-2.5-pro")
        self.api_key = config.get("api_key", "mock-key")
        
        # Template TTPs
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
        """Generate mock response"""
        await asyncio.sleep(0.3)  # Simulate API delay
        
        # Select random TTPs
        num_ttps = random.randint(2, min(4, len(self.template_ttps)))
        selected_ttps = random.sample(self.template_ttps, num_ttps)
        
        return json.dumps(selected_ttps, indent=2)
    
    async def test_connection(self) -> bool:
        """Test connection"""
        await asyncio.sleep(0.1)
        return True


class GeminiClient:
    """Real Gemini API client for TTP extraction"""
    
    def __init__(self, config: Dict[str, Any]):
        if not genai:
            raise ImportError("google-generativeai package not installed")
        
        self.api_key = config.get("api_key")
        if not self.api_key:
            raise ValueError("Gemini API key not provided")
        
        self.model_name = config.get("model", "gemini-2.5-pro")
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 1000)
        
        # Initialize Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(
            model_name=self.model_name,
            generation_config=genai.types.GenerationConfig(
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
                top_p=0.95,
                top_k=40
            )
        )
    
    async def generate(self, prompt: str, max_tokens: int = 1000,
                      temperature: float = 0.3) -> str:
        """
        Generate response using Gemini API
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum output tokens
            temperature: Temperature for generation
            
        Returns:
            Generated text response
        """
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                self._generate_sync,
                prompt
            )
            return response
            
        except Exception as e:
            raise LLMException(f"Gemini API error: {str(e)}")
    
    def _generate_sync(self, prompt: str) -> str:
        """Synchronous wrapper for Gemini generation"""
        response = self.model.generate_content(prompt)
        return response.text
    
    async def test_connection(self) -> bool:
        """Test Gemini API connection"""
        try:
            test_prompt = "Respond with 'OK' only"
            response = await self.generate(test_prompt, max_tokens=10)
            return "OK" in response or len(response) > 0
        except Exception:
            return False


def create_llm_client(config: Dict[str, Any], use_mock: bool = True):
    """
    Factory function to create LLM client
    
    Args:
        config: LLM configuration
        use_mock: If True, use mock client
        
    Returns:
        LLM client instance
    """
    if use_mock:
        return MockGeminiClient(config)
    else:
        return GeminiClient(config)