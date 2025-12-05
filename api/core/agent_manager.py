import asyncio
import logging
import os
import yaml
from typing import Dict, Any, Optional
from core.langchain_orchestrator import LangChainOrchestrator

logger = logging.getLogger("agent_manager")

class AgentManager:
    """
    Singleton manager for the LangChain Orchestrator.
    Handles agent lifecycle and state management for the API.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AgentManager, cls).__new__(cls)
            cls._instance.orchestrator = None
            cls._instance.is_initialized = False
            cls._instance.config = {}
        return cls._instance

    def _load_config(self) -> Dict[str, Any]:
        """Load config from file with env var substitution"""
        from dotenv import load_dotenv
        load_dotenv()
        
        path = "config/agents.yaml"
        if not os.path.exists(path):
            return {}

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Substitute env vars
        content = os.path.expandvars(content)
        
        data = yaml.safe_load(content)
        
        # Handle root 'config' key if present
        if data and 'config' in data and 'agents' in data['config']:
            return data['config']
            
        return data

    async def ensure_config_loaded(self):
        """Ensure configuration is loaded even if agents are not initialized"""
        if not self.config:
            try:
                self.config = self._load_config()
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

    async def initialize(self):
        """Initialize the orchestrator if not already done"""
        if not self.is_initialized:
            logger.info("Initializing AgentManager...")
            # Initialize with default config path
            self.orchestrator = LangChainOrchestrator(mode="langchain")
            await self.orchestrator.initialize()
            self.config = self.orchestrator.config # Sync config
            self.is_initialized = True
            logger.info("AgentManager initialized successfully")

    def get_agent_status(self) -> Dict[str, str]:
        """Get status of all agents"""
        # If not initialized, all are stopped
        if not self.is_initialized or not self.orchestrator:
            return {
                "extractor": "stopped",
                "rulegen": "stopped",
                "evaluator": "stopped",
                "attackgen": "stopped",
            }
            
        status = {
            "extractor": "running" if self.orchestrator.extractor else "stopped",
            "rulegen": "running" if self.orchestrator.rulegen else "stopped",
            "evaluator": "running" if self.orchestrator.evaluator else "stopped",
            "attackgen": "running" if self.orchestrator.attackgen else "stopped",
        }
        return status

    def get_agent_details(self) -> Dict[str, Any]:
        """Get detailed configuration of all agents"""
        # Use cached config if available, otherwise try to load it
        if not self.config:
            # We can't use async here easily without changing signature, 
            # but this is usually called after ensure_config_loaded
            try:
                self.config = self._load_config()
            except:
                pass

        config = self.config.get("agents", {})
        details = {}
        
        # Helper to extract model info safely
        def get_model_info(agent_conf):
            llm = agent_conf.get("llm", {})
            if "model" in llm:
                return llm["model"]
            # Fallback for benchmark/judge configs
            if "benchmark" in agent_conf and "llm_judge" in agent_conf["benchmark"]:
                return agent_conf["benchmark"]["llm_judge"].get("model", "Unknown")
            return "Unknown"

        for key in ["extractor", "rulegen", "evaluator", "attackgen"]:
            if key in config:
                agent_conf = config[key]
                details[key] = {
                    "name": agent_conf.get("name", key.capitalize()),
                    "description": agent_conf.get("description", ""),
                    "model": get_model_info(agent_conf),
                    "type": "LangChain" if agent_conf.get("use_langchain", True) else "Traditional",
                    # Infer capabilities from config keys
                    "capabilities": [k for k in ["nlp", "sigma", "benchmark", "platforms"] if k in agent_conf]
                }
        
        return details

    async def start_agent(self, agent_name: str):
        """Start a specific agent"""
        if not self.is_initialized:
            await self.initialize()
        if self.orchestrator:
            await self.orchestrator.start_agent(agent_name)

    async def start_all(self):
        """Start all agents"""
        if not self.is_initialized:
            await self.initialize()
        if self.orchestrator:
            await self.orchestrator.start_all()

    async def run_pipeline(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run the full pipeline"""
        if not self.is_initialized:
            await self.initialize()
            
        # Ensure all agents are started
        await self.start_all()
            
        # Determine input type and run appropriate pipeline
        if "cti_reports" in input_data:
            return await self.orchestrator.run_pipeline(input_data["cti_reports"])
        elif "extracted_ttps" in input_data:
            return await self.orchestrator.run_test_pipeline(input_data)
        else:
            raise ValueError("Invalid input data format")

    async def run_agent(self, agent_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific agent"""
        if not self.is_initialized:
            await self.initialize()
            
        # Ensure specific agent is started
        await self.start_agent(agent_name)
            
        return await self.orchestrator.run_agent(agent_name, input_data)

    async def stop_agent(self, agent_name: str):
        """Stop a specific agent"""
        if self.orchestrator:
            await self.orchestrator.stop_agent(agent_name)

    async def stop_all(self):
        """Stop all agents and reset manager state"""
        if self.orchestrator:
            await self.orchestrator.cleanup()
            self.orchestrator = None
            
        self.is_initialized = False
        logger.info("AgentManager stopped and state reset")

# Global instance
agent_manager = AgentManager()
