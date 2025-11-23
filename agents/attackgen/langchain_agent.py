"""
LangChain-Enhanced AttackGen Agent
Integrates LangChain for Attack Command Generation
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import json

from agents.base.agent import BaseAgent, AgentStatus
from agents.attackgen.exceptions import AttackGenException
from agents.attackgen.mitre.attack_mapper import AttackMapper
from agents.attackgen.validators.safety_checker import SafetyChecker
from core.logging import get_agent_logger
from core.langchain_integration import (
    create_langchain_llm,
    create_attack_gen_chain,
    AttackCommandGenerationChain
)


class LangChainAttackGenAgent(BaseAgent):
    """
    LangChain-powered AttackGen Agent
    
    Uses LangChain for structured attack command generation with:
    - Pydantic output parsing
    - Automatic retries
    - Structured outputs
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # LangChain components
        self.langchain_enabled = config.get("use_langchain", True)
        self.attack_chain: Optional[AttackCommandGenerationChain] = None
        
        # Traditional components
        self.attack_mapper = AttackMapper()
        self.safety_checker = SafetyChecker()
        
        # Configuration
        self.llm_config = config.get("llm", {})
        self.supported_platforms = config.get('platforms', ['windows', 'linux'])
        self.safety_level = config.get('safety_level', 'medium')
        
        # Statistics
        self.stats = {
            "total_ttps_processed": 0,
            "total_commands_generated": 0,
            "langchain_generations": 0,
            "generation_errors": 0,
            "safety_violations": 0,
            "processing_time_ms": 0
        }
        
        self.logger = get_agent_logger(f"langchain_attackgen_{name}", self.id)
    
    async def start(self) -> None:
        """Start the agent"""
        await super().start()
        
        try:
            # Load MITRE ATT&CK data
            await self.attack_mapper.load_attack_data()
            
            if self.langchain_enabled:
                # Initialize LangChain components
                llm_wrapper = create_langchain_llm(self.llm_config)
                self.attack_chain = create_attack_gen_chain(llm_wrapper)
                
                self.logger.info("LangChain AttackGen Agent started with LangChain integration")
            else:
                self.logger.warning("LangChain AttackGen Agent started but LangChain is disabled")
                
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise AttackGenException(f"Failed to start: {str(e)}")
    
    async def _execute_with_context(self, input_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute attack generation"""
        start_time = datetime.utcnow()
        
        try:
            self.set_status(AgentStatus.RUNNING)
            
            # Parse input
            extracted_ttps = input_data.get("extracted_ttps", [])
            if not extracted_ttps and "ttps" in input_data:
                 extracted_ttps = input_data["ttps"]
            
            if not extracted_ttps:
                return {
                    "status": "no_data",
                    "message": "No TTPs to process"
                }
            
            self.logger.info(f"Processing {len(extracted_ttps)} TTPs with LangChain")
            
            all_commands = []
            generation_errors = []
            
            for ttp in extracted_ttps:
                try:
                    commands = await self._generate_commands_for_ttp(ttp)
                    all_commands.extend(commands)
                    self.stats["total_ttps_processed"] += 1
                    
                except Exception as e:
                    self.logger.error(f"Generation failed for TTP {ttp.get('ttp_id')}: {str(e)}")
                    generation_errors.append(str(e))
                    self.stats["generation_errors"] += 1
            
            # Calculate statistics
            self.stats["total_commands_generated"] += len(all_commands)
            processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats["processing_time_ms"] = processing_time_ms
            
            return {
                "status": "success",
                "agent_id": self.id,
                "timestamp": self.get_timestamp(),
                "generation_summary": {
                    "ttps_processed": len(extracted_ttps),
                    "commands_generated": len(all_commands),
                    "langchain_generations": self.stats["langchain_generations"],
                    "processing_time_ms": processing_time_ms
                },
                "attack_commands": all_commands,
                "errors": generation_errors
            }
            
        except Exception as e:
            self.logger.error(f"Execution error: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
            
    async def _generate_commands_for_ttp(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate commands for a single TTP"""
        generated_commands = []
        
        for platform in self.supported_platforms:
            if self.langchain_enabled and self.attack_chain:
                try:
                    # Prepare TTP data with platform
                    ttp_data = {
                        'technique_name': ttp.get('technique_name', ttp.get('name', 'Unknown')),
                        'technique_id': ttp.get('technique_id', ttp.get('ttp_id', 'T1059')),
                        'tactic': ttp.get('tactic', 'execution'),
                        'description': ttp.get('description', ''),
                        'platform': platform
                    }
                    
                    # Generate using LangChain
                    self.logger.debug(f"Generating commands for {ttp_data['technique_id']} on {platform}")
                    output = await self.attack_chain.generate(ttp_data)
                    
                    self.stats["langchain_generations"] += 1
                    
                    # Process and validate commands
                    for cmd in output.commands:
                        processed_cmd = await self._process_command(cmd, ttp, platform)
                        if processed_cmd:
                            generated_commands.append(processed_cmd)
                            
                except Exception as e:
                    self.logger.error(f"LangChain generation failed for {platform}: {e}")
                    self.stats["generation_errors"] += 1
            
        return generated_commands

    async def _process_command(self, cmd_obj, ttp: Dict[str, Any], platform: str) -> Optional[Dict[str, Any]]:
        """Process and validate individual command"""
        try:
            # Convert Pydantic model to dict if needed
            cmd_dict = cmd_obj.dict() if hasattr(cmd_obj, 'dict') else cmd_obj
            
            # Extract command data
            command = cmd_dict.get('command', '')
            description = cmd_dict.get('description', '')
            technique_id = cmd_dict.get('technique_id', ttp.get('technique_id', 'T1059'))
            
            # Safety validation - check command safety
            if not command or len(command.strip()) == 0:
                self.logger.warning("Empty command generated, skipping")
                return None
            
            # Basic safety check
            dangerous_keywords = ['rm -rf /', 'format', 'del /f /s /q C:\\']
            if any(keyword in command.lower() for keyword in dangerous_keywords):
                self.stats['safety_violations'] += 1
                self.logger.warning(f"Command failed safety check: {command[:50]}")
                return None
            
            # Build final command structure
            return {
                'id': str(uuid.uuid4()),
                'ttp_id': ttp.get('ttp_id', ttp.get('technique_id')),
                'technique_id': technique_id,
                'technique_name': ttp.get('technique_name', ttp.get('name', 'Unknown')),
                'tactic': ttp.get('tactic', 'execution'),
                'platform': platform,
                'command': command,
                'description': description,
                'requires_admin': cmd_dict.get('requires_admin', False),
                'safety_level': cmd_dict.get('safety_level', 'medium'),
                'expected_behavior': cmd_dict.get('expected_behavior', ''),
                'source': 'langchain',
                'generated_at': datetime.utcnow().isoformat(),
                'agent_id': self.id,
                'confidence_score': ttp.get('confidence', ttp.get('confidence_score', 0.8)),
                'validated': True
            }
            
        except Exception as e:
            self.logger.error(f"Command processing failed: {e}")
            return None

    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data"""
        return "extracted_ttps" in data or "ttps" in data
