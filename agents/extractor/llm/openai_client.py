"""
LLM clients for TTP extraction.
"""

import asyncio
import json
from typing import Dict, Any, Optional
from datetime import datetime
import random

from agents.base.exceptions import LLMException

class MockLLMClient:
    """
    Mock LLM client for development and testing.
    
    Generates realistic TTP extraction responses without calling real LLM APIs.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.model = config.get("model", "mock-gpt-4")
        self.api_key = config.get("api_key", "mock-key")
        
        # Template TTPs for mock responses
        self.template_ttps = [
            {
                "technique_name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": "Attackers sent emails with malicious Office documents containing VBA macros",
                "indicators": ["malicious.doc", "macro execution", "suspicious email"],
                "tools": ["Emotet", "Microsoft Office"]
            },
            {
                "technique_name": "PowerShell",
                "tactic": "Execution",
                "description": "Execution of PowerShell scripts to download and execute additional payloads",
                "indicators": ["powershell.exe", "-encodedCommand", "DownloadString"],
                "tools": ["PowerShell", "Empire", "Cobalt Strike"]
            },
            {
                "technique_name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Dumping credentials from LSASS process memory using Mimikatz",
                "indicators": ["mimikatz", "sekurlsa::logonpasswords", "lsass.exe"],
                "tools": ["Mimikatz"]
            },
            {
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "description": "Creating registry run keys for persistence across system reboots",
                "indicators": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                "tools": []
            },
            {
                "technique_name": "Remote Desktop Protocol",
                "tactic": "Lateral Movement",
                "description": "Using RDP to move laterally to other systems in the network",
                "indicators": ["mstsc.exe", "RDP connection", "port 3389"],
                "tools": []
            }
        ]
    
    async def generate(self, prompt: str, max_tokens: int = 2000, 
                      temperature: float = 0.3) -> str:
        """
        Generate mock LLM response.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens (ignored in mock)
            temperature: Temperature (ignored in mock)
            
        Returns:
            JSON string with extracted TTPs
        """
        # Simulate API delay
        await asyncio.sleep(0.2)
        
        # Select random subset of template TTPs
        num_ttps = random.randint(3, len(self.template_ttps))
        selected_ttps = random.sample(self.template_ttps, num_ttps)
        
        # Return as JSON
        return json.dumps(selected_ttps, indent=2)
    
    async def test_connection(self) -> bool:
        """Test connection (always succeeds for mock)"""
        await asyncio.sleep(0.1)
        return True


class OpenAIClient:
    """
    Real OpenAI API client.
    
    To be implemented when integrating with actual OpenAI API.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # TODO: Initialize OpenAI client
        pass
    
    async def generate(self, prompt: str, max_tokens: int = 2000,
                      temperature: float = 0.3) -> str:
        """Implementation for real OpenAI API"""
        # TODO: Implement real OpenAI integration
        raise NotImplementedError("Real OpenAI client not implemented yet")


def create_llm_client(config: Dict[str, Any], use_mock: bool = True):
    """
    Factory function to create LLM client.
    
    Args:
        config: LLM configuration
        use_mock: If True, use mock client; if False, use real client
        
    Returns:
        LLM client instance
    """
    if use_mock:
        return MockLLMClient(config)
    else:
        return OpenAIClient(config)