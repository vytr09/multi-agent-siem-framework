import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_project_root() -> Path:
    """Get the project root directory."""
    # This file is at tests/utils.py, so parent.parent is project root
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
    
    agent_config = config.get("config", {}).get("agents", {}).get(agent_name, {})
    
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
    return config.get("config", {}).get("agents", {}).get(agent_name, {})
