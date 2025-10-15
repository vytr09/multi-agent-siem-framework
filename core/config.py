# core/config.py
"""
Configuration management for the Multi-Agent SIEM Framework.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Application Settings
    app_name: str = Field(default="Multi-Agent SIEM Framework")
    app_version: str = Field(default="1.0.0")
    debug: bool = Field(default=False)
    environment: str = Field(default="development")
    
    # Database Settings
    database_url: str = Field(
        default="postgresql+asyncpg://siem_user:siem_password@localhost:5432/multi_agent_siem"
    )
    
    # Redis Settings
    redis_url: str = Field(default="redis://localhost:6379")
    
    # Logging
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")

class ConfigManager:
    """Centralized configuration management for all agents."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.settings = Settings()
        self._agent_configs: Dict[str, Dict[str, Any]] = {}
    
    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """Get configuration for a specific agent."""
        # For now, return basic config
        return {
            'name': agent_name,
            'database_url': self.settings.database_url,
            'redis_url': self.settings.redis_url,
            'debug': self.settings.debug,
            'environment': self.settings.environment
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return {
            'level': self.settings.log_level,
            'format': self.settings.log_format
        }

# Global configuration instance
config_manager = ConfigManager()

def get_config() -> ConfigManager:
    """Get the global configuration manager instance"""
    return config_manager
