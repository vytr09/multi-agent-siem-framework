"""
Structured logging system for the Multi-Agent SIEM Framework.
"""

import logging
import logging.config
import sys
from typing import Optional

class AgentLogger:
    """Agent-specific logger that provides additional context and functionality."""
    
    def __init__(self, agent_name: str, agent_id: Optional[str] = None):
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logging.getLogger(f"agent.{agent_name}")
        
        # Set up basic logging if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def info(self, message: str, **kwargs):
        """Log an info message with optional extra context"""
        self.logger.info(message)
    
    def warning(self, message: str, **kwargs):
        """Log a warning message with optional extra context"""
        self.logger.warning(message)
    
    def error(self, message: str, **kwargs):
        """Log an error message with optional extra context"""
        self.logger.error(message)
    
    def debug(self, message: str, **kwargs):
        """Log a debug message with optional extra context"""
        self.logger.debug(message)

def get_agent_logger(agent_name: str, agent_id: Optional[str] = None) -> AgentLogger:
    """Get an agent-specific logger instance."""
    return AgentLogger(agent_name, agent_id)
