# agents/attackgen/config.py
"""
AttackGen Agent Configuration
"""

import os
from typing import Dict, Any
from pathlib import Path


def get_attackgen_config() -> Dict[str, Any]:
    """Get default AttackGen agent configuration"""
    
    return {
        # LLM Configuration
        'llm': {
            'model': os.getenv('GEMINI_MODEL', 'gemini-2.0-flash-lite'),
            'temperature': float(os.getenv('GEMINI_TEMPERATURE', '0.7')),
            'max_tokens': int(os.getenv('GEMINI_MAX_TOKENS', '2000')),
            'use_mock': os.getenv('USE_MOCK_LLM', 'false').lower() == 'true'
        },
        
        # Platform Support
        'platforms': ['windows', 'linux'],  # ['windows', 'linux', 'macos', 'cloud']
        
        # Generation Settings
        'max_commands_per_ttp': 2,
        'enable_script_generation': True,
        
        # Safety Settings
        'safety_level': 'medium',  # low, medium, high
        'enable_compliance_check': True,
        
        # Performance Settings
        'enable_caching': True,
        
        # Paths
        'mitre_data_path': 'data/mitre_attack',
        
        # Logging
        'log_level': 'INFO',
    }

