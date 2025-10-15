# agents/base/agent.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import uuid
import logging
import asyncio
from datetime import datetime
from enum import Enum

class AgentStatus(Enum):
    """Agent status enumeration"""
    INITIALIZED = "initialized"
    RUNNING = "running"
    IDLE = "idle"
    ERROR = "error"
    STOPPING = "stopping"
    STOPPED = "stopped"

class BaseAgent(ABC):
    """
    Abstract base class for all agents in the Multi-Agent SIEM Framework.
    
    This class provides the common interface and functionality that all agents
    must implement, including status management, health checks, and execution flow.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize the base agent.
        
        Args:
            name: Unique name for the agent
            config: Configuration dictionary for the agent
        """
        self.id = str(uuid.uuid4())
        self.name = name
        self.config = config
        self.logger = self._setup_logger()
        self.status = AgentStatus.INITIALIZED
        self.start_time: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self._is_running = False
        
    def _setup_logger(self) -> logging.Logger:
        """Set up structured logging for the agent"""
        logger = logging.getLogger(f"agent.{self.name}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    @abstractmethod
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main execution method for the agent.
        
        Args:
            input_data: Input data for the agent to process
            
        Returns:
            Dictionary containing the execution results
        """
        pass
    
    @abstractmethod
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """
        Validate input data format.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if data is valid, False otherwise
        """
        pass
    
    async def start(self) -> None:
        """Start the agent"""
        try:
            self.status = AgentStatus.RUNNING
            self.start_time = datetime.utcnow()
            self._is_running = True
            self.logger.info(f"Agent {self.name} started successfully")
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            self.logger.error(f"Failed to start agent {self.name}: {str(e)}")
            raise
    
    async def stop(self) -> None:
        """Stop the agent gracefully"""
        try:
            self.status = AgentStatus.STOPPING
            self._is_running = False
            self.logger.info(f"Agent {self.name} stopping...")
            
            # Give some time for ongoing operations to complete
            await asyncio.sleep(1)
            
            self.status = AgentStatus.STOPPED
            self.logger.info(f"Agent {self.name} stopped successfully")
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            self.logger.error(f"Error stopping agent {self.name}: {str(e)}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check for monitoring.
        
        Returns:
            Dictionary containing health status information
        """
        return {
            "agent_id": self.id,
            "name": self.name,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "uptime_seconds": (
                (datetime.utcnow() - self.start_time).total_seconds()
                if self.start_time else 0
            ),
            "is_running": self._is_running,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def update_last_activity(self) -> None:
        """Update the last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with default fallback.
        
        Args:
            key: Configuration key to retrieve
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def set_status(self, status: AgentStatus, message: Optional[str] = None) -> None:
        """
        Set agent status with optional message.
        
        Args:
            status: New status to set
            message: Optional status message
        """
        old_status = self.status
        self.status = status
        
        log_message = f"Status changed from {old_status.value} to {status.value}"
        if message:
            log_message += f": {message}"
            
        self.logger.info(log_message)
    
    def get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.utcnow().isoformat()
    
    def __str__(self) -> str:
        return f"Agent(id={self.id}, name={self.name}, status={self.status.value})"
    
    def __repr__(self) -> str:
        return self.__str__()
