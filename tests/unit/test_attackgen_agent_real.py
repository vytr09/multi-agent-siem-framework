# test_attackgen_agent_real.py
"""
AttackGen Agent Tests - NO MOCK/FALLBACK
Tests ONLY with real AttackGen Agent and real extracted TTP data
"""

import pytest
import os
import json
from pathlib import Path
from dotenv import load_dotenv
import sys

# Load .env file
load_dotenv()
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import AttackGen Agent components - NO FALLBACK
from agents.attackgen.agent import AttackGenAgent
from agents.attackgen.config import get_attackgen_config
from agents.base.agent import AgentStatus

# ================================
# TEST CLASS - NO MOCK
# ================================

class TestRealAttackGenAgent:
    """Tests for AttackGen Agent ONLY"""
    
    @pytest.fixture
    def real_agent_config(self):
        """Configuration for agent"""
        config = get_attackgen_config()
        
        # Use Gemini API - NO MOCK
        config['llm']['use_mock'] = False
        config['platforms'] = ['windows', 'linux']
        config['safety_level'] = 'medium'
        config['max_commands_per_ttp'] = 2
        
        return config
    
    @pytest.fixture
    def real_agent(self, real_agent_config):
        """Create AttackGen Agent - NO MOCK"""
        return AttackGenAgent('test_real_agent', real_agent_config)
    
    @pytest.fixture
    def real_extracted_ttps(self):
        """Load TTPs from ExtractorAgent output - NO FALLBACK"""
        
        # Load TTP data - MUST EXIST
        ttp_file = Path('data/extracted/ttps_extracted.json')
        
        if not ttp_file.exists():
            raise FileNotFoundError(f"Real TTP file not found: {ttp_file.absolute()}")
        
        print(f"📄 Loading TTPs from {ttp_file}")
        
        with open(ttp_file, 'r', encoding='utf-8') as f:
            extractor_data = json.load(f)
        
        # Parse TTP data structure
        real_ttps = []
        extraction_results = extractor_data.get('extraction_results', [])
        
        if not extraction_results:
            raise ValueError("No extraction results found in TTP file")
        
        for result in extraction_results:
            source_info = result.get('source_report', {})
            extracted_ttps = result.get('extracted_ttps', [])
            
            for ttp in extracted_ttps:
                # Convert to AttackGen Agent expected format
                formatted_ttp = {
                    'ttp_id': f"real-{ttp.get('attack_id', 'unknown')}",
                    'technique_name': ttp.get('technique_name', ''),
                    'tactic': ttp.get('tactic', ''),
                    'description': ttp.get('description', ''),
                    'attack_id': ttp.get('attack_id', ''),
                    'attack_name': ttp.get('attack_name', ''),
                    'confidence_score': ttp.get('confidence_score', 0.5),
                    'confidence_level': ttp.get('confidence_level', 'medium'),
                    'indicators': ttp.get('indicators', []),
                    'tools': ttp.get('tools', []),
                    'source_report': source_info.get('title', 'Unknown Report')
                }
                
                # Only add if we have essential fields
                if formatted_ttp['attack_id'] and formatted_ttp['technique_name']:
                    real_ttps.append(formatted_ttp)
        
        if not real_ttps:
            raise ValueError("No valid TTPs found in extraction results")
        
        print(f"✅ Successfully loaded {len(real_ttps)} TTPs")
        
        # Show sample of loaded TTPs
        for i, ttp in enumerate(real_ttps[:3]):
            print(f"   TTP {i+1}: {ttp['attack_id']} - {ttp['technique_name']} (confidence: {ttp['confidence_score']:.2f})")
        
        # Return subset for testing (limit to avoid overwhelming)
        return real_ttps[:6]  # Use first 6 real TTPs
    
    def test_environment_requirements(self):
        """Test 1: Verify environment requirements"""
        print("🔍 Testing environment requirements...")
        
        # MUST have .env file
        env_file = Path('.env')
        assert env_file.exists(), f".env file required: {env_file.absolute()}"
        
        # MUST have GEMINI_API_KEY
        api_key = os.getenv('GEMINI_API_KEY')
        assert api_key is not None, "GEMINI_API_KEY environment variable required"
        assert len(api_key) > 10, f"GEMINI_API_KEY seems invalid (length: {len(api_key)})"
        
        print(f"✅ GEMINI_API_KEY loaded (length: {len(api_key)})")
        
        # MUST have TTP data file
        ttp_file = Path('data/extracted/ttps_extracted.json')
        assert ttp_file.exists(), f"Real TTP data file required: {ttp_file.absolute()}"
        
        print(f"✅ Real TTP data file found: {ttp_file}")
        
        # Create required directories
        for dir_name in ['logs', 'test_results']:
            Path(dir_name).mkdir(exist_ok=True)
        
        print("✅ Environment requirements verified")
    
    def test_real_agent_import(self):
        """Test 2: Verify AttackGen Agent can be imported"""
        print("🔍 Testing AttackGen Agent imports...")
        
        # Must be able to import ALL components
        from agents.attackgen.agent import AttackGenAgent
        from agents.attackgen.config import get_attackgen_config
        from agents.base.agent import AgentStatus
        
        print("✅ AttackGenAgent imported successfully")
        
        # Configuration must be valid
        config = get_attackgen_config()
        assert isinstance(config, dict), "Config must be dictionary"
        assert 'llm' in config, "Config must have 'llm' section"
        assert 'platforms' in config, "Config must have 'platforms' section"
        
        print("✅ Configuration structure validated")
    
    @pytest.mark.asyncio
    async def test_real_agent_workflow(self, real_agent, real_extracted_ttps):
        """Test 3: Complete AttackGen Agent workflow"""
        print("🚀 Testing AttackGen Agent workflow...")
        
        # Start agent
        print("🔄 Starting AttackGen agent...")
        await real_agent.start()
        
        # MUST be running
        assert real_agent.status == AgentStatus.RUNNING, f"Agent status: {real_agent.status}"
        print("✅ Agent started successfully")
        
        # Prepare input data
        input_data = {'extracted_ttps': real_extracted_ttps}
        print(f"📝 Processing {len(real_extracted_ttps)} TTPs...")
        
        # Validate input
        is_valid = real_agent.validate_input(input_data)
        assert is_valid == True, "Input validation failed"
        print("✅ Input validation passed")
        
        # Execute attack generation
        print("⚡ Executing attack generation with Gemini API...")
        result = await real_agent.execute(input_data)
        
        # Verify results
        assert result['status'] == 'success', f"Execution failed: {result.get('status')}"
        assert len(result['attack_commands']) > 0, "No attack commands generated"
        
        print(f"✅ Generated {len(result['attack_commands'])} attack commands")
        
        # Verify command structure
        commands = result['attack_commands']
        for i, cmd in enumerate(commands):
            assert 'command_id' in cmd, f"Command {i}: missing command_id"
            assert 'mitre_attack_id' in cmd, f"Command {i}: missing mitre_attack_id"
            assert 'platform' in cmd, f"Command {i}: missing platform"
            assert 'command' in cmd, f"Command {i}: missing command"
            assert 'technique_name' in cmd, f"Command {i}: missing technique_name"
            assert len(cmd['command'].strip()) > 0, f"Command {i}: empty command"
        
        print("✅ All command structures validated")
        
        # Get statistics
        stats = await real_agent.get_statistics()
        assert stats['statistics']['total_ttps_processed'] > 0, "No TTPs processed"
        
        ttps_processed = stats['statistics']['total_ttps_processed']
        commands_generated = len(commands)
        processing_time = result['generation_summary']['processing_time_ms']
        
        print(f"✅ Statistics: {ttps_processed} TTPs processed")
        
        # Show detailed results
        print("📊 WORKFLOW RESULTS:")
        print(f"   📈 TTPs processed: {result['generation_summary']['ttps_processed']}")
        print(f"   ⚡ Commands generated: {result['generation_summary']['commands_generated']}")
        print(f"   🕒 Processing time: {processing_time:.2f}ms")
        print(f"   🎯 Success rate: {(commands_generated/ttps_processed)*100:.1f}%")
        
        # Show sample commands
        print("📋 Sample generated commands:")
        for i, cmd in enumerate(commands[:3]):
            print(f"   Command {i+1}: {cmd['mitre_attack_id']} - {cmd['name'][:50]}...")
            print(f"      Platform: {cmd['platform']}")
            print(f"      Command: {cmd['command'][:60]}...")
        
        # Save results
        results_file = Path('test_results/real_attackgen_results.json')
        results_file.parent.mkdir(exist_ok=True)
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': result.get('timestamp'),
                'agent_id': real_agent.id,
                'test_mode': 'real_no_mock',
                'statistics': stats,
                'execution_result': result
            }, f, indent=2, ensure_ascii=False)
        
        print(f"📄 test results saved to {results_file}")
        print("🎉 AttackGen Agent workflow test PASSED!")
    
    @pytest.mark.asyncio
    async def test_real_api_integration(self, real_agent):
        """Test 4: Verify Gemini API integration"""
        print("🔍 Testing Gemini API integration...")
        
        # Start agent to initialize LLM
        await real_agent.start()
        
        # Verify LLM client is initialized
        assert real_agent.llm_client is not None, "LLM client not initialized"
        
        # Test API connection
        if hasattr(real_agent.llm_client, 'test_connection'):
            connected = await real_agent.llm_client.test_connection()
            assert connected == True, "Failed to connect to Gemini API"
            print("✅ Gemini API connection verified")
        
        print("✅ API integration validated")


# ================================
# PYTEST CONFIG
# ================================

def pytest_configure(config):
    """Configure pytest for tests"""
    config.addinivalue_line("markers", "real: integration tests with real data and APIs")


# ================================
# MAIN RUNNER
# ================================

if __name__ == "__main__":
    """
    Run AttackGen Agent tests
    
    Usage:
    python test_attackgen_agent_real.py           # Run all tests
    python test_attackgen_agent_real.py --check   # Check requirements only
    """
    
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--check':
        # Just check requirements
        print("🔍 Checking test requirements...")
        test_class = TestRealAttackGenAgent()
        test_class.test_environment_requirements()
        test_class.test_real_agent_import()
        print("🏁 test requirements check complete!")
    else:
        # Run all tests
        import pytest
        
        print("🚀 Running AttackGen Agent tests...")
        print("⚠️  This will use Gemini API and may take time...")
        
        pytest.main([
            __file__,
            '-v', '-s',
            '--tb=short'
        ])
