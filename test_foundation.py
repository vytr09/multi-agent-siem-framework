#!/usr/bin/env python3
"""
Simple test script to verify the foundation files work correctly.
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import ConfigurationException, MessageQueueException, DatabaseException
from core.config import get_config
from core.logging import get_agent_logger

class TestAgent(BaseAgent):
    """Simple test agent implementation"""
    
    async def execute(self, input_data):
        self.logger.info("Test agent executing...")
        self.update_last_activity()
        return {"status": "success", "message": "Test execution completed"}
    
    def validate_input(self, data):
        return True

async def test_foundation():
    """Test the foundation components"""
    print("🧪 Testing Multi-Agent SIEM Framework Foundation...")
    
    try:
        # Test configuration
        print("✓ Testing configuration management...")
        config = get_config()
        print(f"  - App name: {config.settings.app_name}")
        print(f"  - Environment: {config.settings.environment}")
        
        # Test logging
        print("✓ Testing logging system...")
        logger = get_agent_logger("test_agent", "test-001")
        logger.info("Foundation test log message", test=True)
        
        # Test base agent
        print("✓ Testing base agent...")
        agent_config = {"test": True, "timeout": 30}
        test_agent = TestAgent("test_agent", agent_config)
        
        # Test agent lifecycle
        await test_agent.start()
        print(f"  - Agent Status: {test_agent.status.value}")
        
        # Test health check
        health = await test_agent.health_check()
        print(f"  - Agent ID: {health['agent_id'][:8]}...")
        print(f"  - Is Running: {health['is_running']}")
        
        # Test execution
        result = await test_agent.execute({"test_data": "hello"})
        print(f"  - Execution Result: {result['status']}")
        
        await test_agent.stop()
        print(f"  - Final Status: {test_agent.status.value}")
        
        # Test exception imports (without actually using external services)
        print("✓ Testing exception imports...")
        try:
            raise MessageQueueException("Test message queue exception")
        except MessageQueueException:
            print("  - MessageQueueException imported successfully")
        
        try:
            raise DatabaseException("Test database exception")
        except DatabaseException:
            print("  - DatabaseException imported successfully")
        
        print("\n🎉 All foundation tests passed!")
        print("📝 Note: Redis and Database tests skipped (services not required for foundation)")
        return True
        
    except Exception as e:
        print(f"\n❌ Foundation test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_foundation())
    sys.exit(0 if success else 1)
