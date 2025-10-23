# agents/attackgen/tests/test_agent.py
"""
Tests for AttackGen Agent.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch

from agents.attackgen.agent import AttackGenAgent
from agents.attackgen.config import get_attackgen_config


class TestAttackGenAgent:
    
    @pytest.fixture
    def agent_config(self):
        config = get_attackgen_config()
        config['llm']['use_mock'] = True
        return config
    
    @pytest.fixture
    def agent(self, agent_config):
        return AttackGenAgent('test_attackgen', agent_config)
    
    @pytest.fixture
    def sample_ttps(self):
        return [
            {
                'ttp_id': 'ttp-001',
                'technique_name': 'PowerShell',
                'attack_id': 'T1059.001',
                'tactic': 'Execution',
                'description': 'PowerShell execution technique'
            }
        ]
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, agent):
        """Test agent initialization"""
        await agent.start()
        assert agent.status.value == 'running'
        assert agent.llm_client is not None
        assert agent.attack_mapper is not None
    
    @pytest.mark.asyncio
    async def test_attack_command_generation(self, agent, sample_ttps):
        """Test attack command generation"""
        await agent.start()
        
        result = await agent.execute({
            'extracted_ttps': sample_ttps
        })
        
        assert result['status'] == 'success'
        assert 'attack_commands' in result
        assert len(result['attack_commands']) > 0
        
        # Verify command structure
        command = result['attack_commands'][0]
        assert 'command_id' in command
        assert 'ttp_id' in command
        assert 'mitre_attack_id' in command
        assert 'command' in command
        assert 'platform' in command
    
    @pytest.mark.asyncio
    async def test_input_validation(self, agent):
        """Test input validation"""
        await agent.start()
        
        # Valid input
        assert agent.validate_input({'extracted_ttps': []}) == True
        
        # Invalid input
        assert agent.validate_input({'invalid': 'data'}) == False
        assert agent.validate_input('not_dict') == False
    
    @pytest.mark.asyncio
    async def test_statistics(self, agent):
        """Test statistics collection"""
        await agent.start()
        
        stats = await agent.get_statistics()
        
        assert 'agent_info' in stats
        assert 'configuration' in stats
        assert 'statistics' in stats
        assert 'performance' in stats