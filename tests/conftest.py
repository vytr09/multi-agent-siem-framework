# tests/conftest.py
"""
Shared pytest fixtures for Multi-Agent SIEM Framework tests.
Loads LLM configuration from config/agents.yaml.
"""

import os
import yaml
import pytest
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# Config Loading Utilities
# ============================================================================

def get_project_root() -> Path:
    """Get the project root directory."""
    # This file is at tests/conftest.py, so parent.parent is project root
    return Path(__file__).parent.parent


def load_agents_config() -> dict:
    """
    Load the agents configuration from config/agents.yaml.
    Environment variable placeholders (${VAR_NAME}) are resolved.
    """
    config_path = get_project_root() / "config" / "agents.yaml"
    
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    return config


def resolve_env_vars(config: dict) -> dict:
    """
    Recursively resolve ${VAR_NAME} placeholders in config values.
    """
    if isinstance(config, dict):
        return {k: resolve_env_vars(v) for k, v in config.items()}
    elif isinstance(config, list):
        return [resolve_env_vars(item) for item in config]
    elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
        env_var = config[2:-1]
        return os.getenv(env_var, "")
    else:
        return config


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def agents_config() -> dict:
    """Load full agents configuration with resolved env vars."""
    config = load_agents_config()
    return resolve_env_vars(config)


@pytest.fixture(scope="session")
def extractor_config(agents_config) -> dict:
    """Get extractor agent configuration."""
    return agents_config.get("agents", {}).get("extractor", {})


@pytest.fixture(scope="session")
def rulegen_config(agents_config) -> dict:
    """Get rulegen agent configuration."""
    return agents_config.get("agents", {}).get("rulegen", {})


@pytest.fixture(scope="session")
def evaluator_config(agents_config) -> dict:
    """Get evaluator agent configuration."""
    return agents_config.get("agents", {}).get("evaluator", {})


@pytest.fixture(scope="session")
def attackgen_config(agents_config) -> dict:
    """Get attackgen agent configuration."""
    return agents_config.get("agents", {}).get("attackgen", {})


@pytest.fixture(scope="session")
def collector_config(agents_config) -> dict:
    """Get collector agent configuration."""
    return agents_config.get("agents", {}).get("collector", {})


@pytest.fixture(scope="session")
def llm_config(rulegen_config) -> dict:
    """Get LLM configuration (defaults to rulegen's LLM config)."""
    return rulegen_config.get("llm", {})


@pytest.fixture(scope="session")
def feedback_config(agents_config) -> dict:
    """Get feedback loop configuration."""
    return agents_config.get("feedback", {})


@pytest.fixture(scope="session")
def siem_config(agents_config) -> dict:
    """Get SIEM configuration."""
    return agents_config.get("siem", {})


# ============================================================================
# Helper Functions (can be imported directly in test files)
# ============================================================================

def get_llm_config_for_agent(agent_name: str) -> dict:
    """
    Get LLM configuration for a specific agent.
    Can be called directly without pytest context.
    
    Args:
        agent_name: One of 'extractor', 'rulegen', 'evaluator', 'attackgen'
    
    Returns:
        LLM configuration dict with resolved env vars
    """
    config = load_agents_config()
    config = resolve_env_vars(config)
    
    agent_config = config.get("agents", {}).get(agent_name, {})
    
    # Handle evaluator's llm_judge nested config
    if agent_name == "evaluator":
        return agent_config.get("benchmark", {}).get("llm_judge", {})
    
    return agent_config.get("llm", {})


def get_full_agent_config(agent_name: str) -> dict:
    """
    Get full configuration for a specific agent.
    
    Args:
        agent_name: One of 'extractor', 'rulegen', 'evaluator', 'attackgen', 'collector'
    
    Returns:
        Full agent configuration dict with resolved env vars
    """
    config = load_agents_config()
    config = resolve_env_vars(config)
    return config.get("agents", {}).get(agent_name, {})
