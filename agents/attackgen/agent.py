# agents/attackgen/agent.py
"""
AttackGen Agent - Generates executable attack commands from TTPs using LLM + MITRE ATT&CK
"""

import asyncio
import json
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

from agents.base.agent import BaseAgent, AgentStatus
from agents.attackgen.config import get_attackgen_config
from agents.attackgen.exceptions import AttackGenException
from agents.attackgen.llm.gemini_client import GeminiClient
from agents.attackgen.mitre.attack_mapper import AttackMapper
from agents.attackgen.generators.windows_generator import WindowsGenerator
from agents.attackgen.generators.linux_generator import LinuxGenerator
from agents.attackgen.validators.safety_checker import SafetyChecker
from core.logging import get_agent_logger


class AttackGenAgent(BaseAgent):
    """
    AttackGen Agent for generating executable attack commands from TTPs.
    
    Features:
    - LLM-driven attack command generation using Gemini
    - Full MITRE ATT&CK framework integration  
    - Multi-platform support (Windows/Linux/macOS/Cloud)
    - Safety validation and compliance checks
    - Script building and payload generation
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Core components
        self.llm_client: Optional[GeminiClient] = None
        self.attack_mapper = AttackMapper()
        self.safety_checker = SafetyChecker()
        
        # Platform generators
        self.generators = {
            'windows': WindowsGenerator(),
            'linux': LinuxGenerator()
        }
        
        # LLM configuration
        self.llm_config = config.get('llm', {})
        self.use_mock_llm = self.llm_config.get('use_mock', False)
        self.model_name = self.llm_config.get('model', 'gemini-2.0-flash-lite')
        self.max_tokens = self.llm_config.get('max_tokens', 2000)
        self.temperature = self.llm_config.get('temperature', 0.7)
        
        # Attack generation settings
        self.supported_platforms = config.get('platforms', ['windows', 'linux'])
        self.max_commands_per_ttp = config.get('max_commands_per_ttp', 2)
        
        # Safety settings
        self.safety_level = config.get('safety_level', 'medium')  # low, medium, high
        
        # Statistics
        self.stats = {
            'total_ttps_processed': 0,
            'total_commands_generated': 0,
            'commands_by_platform': defaultdict(int),
            'commands_by_tactic': defaultdict(int),
            'generation_errors': 0,
            'safety_violations': 0,
            'successful_generations': 0,
            'avg_generation_time_ms': 0,
            'llm_api_calls': 0,
            'last_generation_time': None
        }
        
        self.logger = get_agent_logger(f'attackgen-{name}', self.id)
    
    async def start(self) -> None:
        """Start the AttackGen agent"""
        await super().start()
        
        try:
            # Initialize Gemini LLM client
            await self.initialize_llm()
            
            # Load MITRE ATT&CK data
            await self.attack_mapper.load_attack_data()
            
            # Initialize generators
            for generator in self.generators.values():
                await generator.initialize()
            
            self.logger.info(
                "AttackGen Agent started successfully",
                model=self.model_name,
                use_mock=self.use_mock_llm,
                platforms=self.supported_platforms,
                safety_level=self.safety_level
            )
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise AttackGenException(f"Failed to start AttackGen Agent: {str(e)}")
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute attack command generation from TTPs.
        
        Args:
            input_data: Contains 'extracted_ttps' from ExtractorAgent
            
        Returns:
            Dictionary with generated attack commands and metadata
        """
        start_time = datetime.utcnow()
        
        try:
            self.set_status(AgentStatus.RUNNING)
            self.update_last_activity()
            
            # Parse input TTPs
            extracted_ttps = input_data.get('extracted_ttps', [])
            if not extracted_ttps:
                return {
                    'agent_id': self.id,
                    'status': 'no_data',
                    'message': 'No TTPs to process for attack generation',
                    'timestamp': self.get_timestamp()
                }
            
            self.logger.info(f"Processing {len(extracted_ttps)} TTPs for attack generation")
            
            # Generate attack commands
            all_attack_commands = []
            generation_errors = []
            
            for ttp in extracted_ttps:
                try:
                    commands = await self._generate_commands_for_ttp(ttp)
                    all_attack_commands.extend(commands)
                    self.stats['total_ttps_processed'] += 1
                    
                except Exception as e:
                    error_msg = f"Failed to generate commands for TTP {ttp.get('ttp_id')}: {str(e)}"
                    self.logger.error(error_msg)
                    generation_errors.append(error_msg)
                    self.stats['generation_errors'] += 1
            
            # Update statistics
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.stats['avg_generation_time_ms'] = processing_time / max(len(extracted_ttps), 1)
            self.stats['last_generation_time'] = datetime.utcnow().isoformat()
            self.stats['successful_generations'] = len(all_attack_commands)
            
            # Prepare result
            result = {
                'agent_id': self.id,
                'status': 'success',
                'timestamp': self.get_timestamp(),
                'generation_summary': {
                    'ttps_processed': len(extracted_ttps),
                    'commands_generated': len(all_attack_commands),
                    'generation_errors': len(generation_errors),
                    'processing_time_ms': processing_time
                },
                'attack_commands': all_attack_commands,
                'errors': generation_errors,
                'statistics': self.stats.copy()
            }
            
            self.set_status(AgentStatus.IDLE)
            self.logger.info(
                "Attack generation completed",
                ttps=len(extracted_ttps),
                commands=len(all_attack_commands),
                errors=len(generation_errors)
            )
            
            return result
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, str(e))
            self.logger.error("Attack generation execution failed", error=str(e))
            raise AttackGenException(f"Attack generation failed: {e}")
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data format"""
        try:
            if not isinstance(data, dict):
                return False
            
            extracted_ttps = data.get('extracted_ttps')
            if not isinstance(extracted_ttps, list):
                return False
            
            # Validate each TTP has required fields
            for ttp in extracted_ttps:
                if not isinstance(ttp, dict):
                    return False
                
                required_fields = ['ttp_id', 'technique_name', 'attack_id', 'tactic']
                if not all(field in ttp for field in required_fields):
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def initialize_llm(self) -> None:
        """Initialize Gemini LLM client with proper error handling"""
        try:
            from agents.attackgen.llm.gemini_client import create_llm_client
            
            self.llm_client = create_llm_client(self.llm_config, use_mock=self.use_mock_llm)
            
            # Test connection if available
            if hasattr(self.llm_client, 'test_connection'):
                try:
                    connection_ok = await self.llm_client.test_connection()
                    if not connection_ok:
                        self.logger.warning("LLM connection test failed, falling back to mock")
                        self.use_mock_llm = True
                        self.llm_client = create_llm_client(self.llm_config, use_mock=True)
                except Exception as e:
                    self.logger.warning(f"Connection test error: {e}, using mock mode")
                    self.use_mock_llm = True
                    self.llm_client = create_llm_client(self.llm_config, use_mock=True)
            
            # Verify generate_commands method exists
            if not hasattr(self.llm_client, 'generate_commands'):
                self.logger.error("LLM client missing generate_commands method")
                raise AttackGenException("LLM client missing required methods")
                
            self.logger.info("LLM client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"LLM initialization failed: {e}")
            # Force fallback to mock
            self.use_mock_llm = True
            try:
                from agents.attackgen.llm.gemini_client import MockGeminiClient
                self.llm_client = MockGeminiClient(self.llm_config)
                self.logger.info("Fallback to MockGeminiClient successful")
            except Exception as fallback_error:
                raise AttackGenException(f"Complete LLM initialization failure: {fallback_error}")
    
    async def _generate_commands_for_ttp(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate attack commands for a specific TTP"""
        ttp_id = ttp.get('ttp_id')
        technique_name = ttp.get('technique_name')
        attack_id = ttp.get('attack_id', '')
        tactic = ttp.get('tactic')
        
        self.logger.debug(f"Generating commands for TTP {attack_id} - {technique_name}")
        
        # Get MITRE ATT&CK technique details
        attack_details = await self.attack_mapper.get_technique_details(attack_id)
        
        generated_commands = []
        
        # Generate commands for each supported platform
        for platform in self.supported_platforms:
            try:
                platform_commands = await self._generate_platform_commands(
                    ttp, attack_details, platform
                )
                generated_commands.extend(platform_commands)
                
            except Exception as e:
                self.logger.error(f"Failed to generate {platform} commands for {attack_id}: {e}")
                self.stats['generation_errors'] += 1
        
        return generated_commands
    
    async def _generate_platform_commands(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any], 
        platform: str
    ) -> List[Dict[str, Any]]:
        """Generate platform-specific commands"""
        
        commands = []
        
        # Try LLM generation first
        try:
            llm_commands = await self._generate_llm_commands(ttp, attack_details, platform)
            commands.extend(llm_commands)
            
        except Exception as e:
            self.logger.warning(f"LLM generation failed for {platform}: {e}")
        
        # Fallback to template generation
        if not commands and platform in self.generators:
            try:
                template_commands = await self.generators[platform].generate_from_templates(
                    ttp, attack_details
                )
                commands.extend(template_commands)
                
            except Exception as e:
                self.logger.error(f"Template generation failed for {platform}: {e}")
        
        # Process and validate commands
        processed_commands = []
        for cmd in commands:
            try:
                processed_cmd = await self._process_command(cmd, ttp, platform)
                if processed_cmd:
                    processed_commands.append(processed_cmd)
                    
            except Exception as e:
                self.logger.error(f"Command processing failed: {e}")
        
        return processed_commands
    
    async def _generate_llm_commands(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any], 
        platform: str
    ) -> List[Dict[str, Any]]:
        """Generate commands using LLM"""
        
        prompt = self._create_llm_prompt(ttp, attack_details, platform)
        
        try:
            self.stats['llm_api_calls'] += 1
            response = await self.llm_client.generate_commands(prompt)
            commands = await self._parse_llm_response(response, platform)
            
            self.logger.debug(f"LLM generated {len(commands)} commands for {platform}")
            return commands
            
        except Exception as e:
            self.logger.error(f"LLM command generation failed: {e}")
            return []
    
    def _create_llm_prompt(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any], 
        platform: str
    ) -> str:
        """Create optimized prompt for LLM"""
        
        technique_name = ttp.get('technique_name', '')
        attack_id = ttp.get("technique_id") or ttp.get("attack_id")
        tactic = ttp.get('tactic', '')
        description = ttp.get('description', '')
        confidence_score = ttp.get('confidence_score', 0.5)
        
        prompt = f"""You are a cybersecurity expert specializing in MITRE ATT&CK techniques.

Generate {self.max_commands_per_ttp} realistic and safe attack commands for testing purposes.

=== TECHNIQUE DETAILS ===
Technique: {technique_name} ({attack_id})
Tactic: {tactic}
Platform: {platform}
Description: {description}
Confidence: {confidence_score:.2f}

=== MITRE ATT&CK CONTEXT ===
Official Name: {attack_details.get('name', 'N/A')}
Platforms: {', '.join(attack_details.get('platforms', []))}
Description: {attack_details.get('description', 'N/A')[:200]}...

=== REQUIREMENTS ===
1. Commands must be SAFE for testing environments
2. Include realistic execution methods for {platform}
3. Provide clear explanations and expected artifacts
4. Include prerequisites and cleanup instructions

=== OUTPUT FORMAT ===
Respond with valid JSON only:
{{
  "commands": [
    {{
      "name": "descriptive command name",
      "command": "actual executable command or script",
      "explanation": "detailed explanation of what this does",
      "indicators": ["list", "of", "expected", "detection", "artifacts"],
      "prerequisites": ["required", "conditions", "for", "execution"],
      "cleanup": "commands to clean up after testing"
    }}
  ]
}}

Generate commands for {technique_name} on {platform}:"""
        
        return prompt
    
    async def _parse_llm_response(self, response: str, platform: str) -> List[Dict[str, Any]]:
        """Parse and validate LLM response"""
        
        try:
            # Clean response (handle markdown code blocks)
            cleaned_response = self._clean_llm_response(response)
            
            # Parse JSON
            parsed = json.loads(cleaned_response)
            
            if 'commands' not in parsed or not isinstance(parsed['commands'], list):
                self.logger.warning("Invalid LLM response structure")
                return []
            
            # Process each command
            commands = []
            for cmd in parsed['commands']:
                if not isinstance(cmd, dict):
                    continue
                
                # Validate required fields and fix structure
                processed_cmd = self._fix_command_structure(cmd)
                processed_cmd['platform'] = platform
                processed_cmd['source'] = 'gemini_llm'
                processed_cmd['generated_at'] = datetime.utcnow().isoformat()
                
                commands.append(processed_cmd)
            
            return commands
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse LLM JSON response: {e}")
            return []
        except Exception as e:
            self.logger.error(f"LLM response processing failed: {e}")
            return []
    
    def _clean_llm_response(self, response: str) -> str:
        """Clean LLM response from markdown code blocks"""
        import re
        
        # Remove markdown code block markers
        patterns = [
            r'```json\s*\n(.*?)\n```',
            r'```\s*\n(.*?)\n```',
            r'```json(.*?)```',
            r'```(.*?)```',
            r'\{.*\}'  # JSON object
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                return match.group(1).strip() if match.lastindex else match.group(0)
        
        return response.strip()
    
    def _fix_command_structure(self, cmd: Dict[str, Any]) -> Dict[str, Any]:
        """Fix and validate command structure"""
        required_fields = {
            'name': 'Generated Command',
            'command': 'echo "test command"',
            'explanation': 'Generated test command',
            'indicators': ['Command execution'],
            'prerequisites': ['System access'],
            'cleanup': 'No cleanup required'
        }
        
        # Fix missing or malformed fields
        for field, default in required_fields.items():
            if field not in cmd or cmd[field] is None:
                cmd[field] = default
            elif field in ['indicators', 'prerequisites'] and isinstance(cmd[field], str):
                cmd[field] = [cmd[field]]
        
        return cmd
    
    async def _process_command(
        self, 
        cmd: Dict[str, Any], 
        ttp: Dict[str, Any], 
        platform: str
    ) -> Optional[Dict[str, Any]]:
        """Process and validate individual command"""
        
        try:
            # Safety validation
            is_safe = await self.safety_checker.is_safe(cmd, self.safety_level)
            if not is_safe:
                self.stats['safety_violations'] += 1
                self.logger.warning(f"Command failed safety check: {cmd.get('name', 'Unknown')}")
                return None
            
            # Build final command structure
            processed_cmd = {
                'command_id': str(uuid.uuid4()),
                'ttp_id': ttp.get('ttp_id'),
                'mitre_attack_id': ttp.get('attack_id'),
                'technique_name': ttp.get('technique_name'),
                'tactic': ttp.get('tactic'),
                'platform': platform,
                'name': cmd['name'],
                'command': cmd['command'],
                'explanation': cmd['explanation'],
                'indicators': cmd['indicators'],
                'prerequisites': cmd['prerequisites'],
                'cleanup': cmd.get('cleanup', 'No cleanup required'),
                'source': cmd.get('source', 'template'),
                'generated_at': cmd.get('generated_at', datetime.utcnow().isoformat()),
                'agent_id': self.id,
                'confidence_score': ttp.get('confidence_score', 0.5),
                'safety_level': self.safety_level,
                'validated': True,
                'metadata': {
                    'threat_actor': ttp.get('context', {}).get('threat_actor'),
                    'campaign': ttp.get('context', {}).get('campaign'),
                    'malware_used': ttp.get('context', {}).get('malware_used', [])
                }
            }
            
            # Update statistics
            self.stats['commands_by_platform'][platform] += 1
            self.stats['commands_by_tactic'][ttp.get('tactic', 'unknown')] += 1
            self.stats['total_commands_generated'] += 1
            
            return processed_cmd
            
        except Exception as e:
            self.logger.error(f"Command processing failed: {e}")
            return None
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics"""
        success_rate = (
            (self.stats['successful_generations'] / max(self.stats['total_ttps_processed'], 1)) * 100
        )
        
        return {
            'agent_info': {
                'id': self.id,
                'name': self.name,
                'status': self.status.value,
                'uptime_seconds': (
                    (datetime.utcnow() - self.start_time).total_seconds() 
                    if self.start_time else 0
                )
            },
            'configuration': {
                'supported_platforms': self.supported_platforms,
                'safety_level': self.safety_level,
                'max_commands_per_ttp': self.max_commands_per_ttp,
                'use_mock_llm': self.use_mock_llm,
                'model_name': self.model_name
            },
            'statistics': self.stats,
            'performance': {
                'success_rate': round(success_rate, 2),
                'avg_generation_time_ms': self.stats['avg_generation_time_ms']
            }
        }