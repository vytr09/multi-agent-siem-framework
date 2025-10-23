# agents/attackgen/generators/base_generator.py
"""
Base generator for platform-specific attack command generation.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging


class BaseGenerator(ABC):
    """
    Abstract base class for platform-specific attack command generators.
    """
    
    def __init__(self, platform: str):
        self.platform = platform
        self.logger = logging.getLogger(f"attackgen.generator.{platform}")
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the generator"""
        self._initialized = True
        self.logger.info(f"{self.platform} generator initialized")
    
    @abstractmethod
    async def generate_from_templates(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate commands from templates"""
        pass
