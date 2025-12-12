# tests/conftest.py
"""
Shared pytest fixtures for Multi-Agent SIEM Framework tests.
Loads LLM configuration from config/agents.yaml.
"""

import pytest
from tests.utils import load_agents_config, resolve_env_vars, get_llm_config_for_agent, get_full_agent_config

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
