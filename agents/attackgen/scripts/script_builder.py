# agents/attackgen/scripts/script_builder.py
"""
Script builder for generating executable scripts from commands.
"""

from typing import Dict, Any
from datetime import datetime


class ScriptBuilder:
    """
    Builds executable scripts from command data.
    """
    
    async def build_script(self, command_data: Dict[str, Any], platform: str) -> str:
        """
        Build executable script for command.
        
        Args:
            command_data: Command information
            platform: Target platform
            
        Returns:
            Script content as string
        """
        
        if platform == 'windows':
            return await self._build_powershell_script(command_data)
        elif platform in ['linux', 'macos']:
            return await self._build_bash_script(command_data)
        else:
            return await self._build_generic_script(command_data)
    
    async def _build_powershell_script(self, command_data: Dict[str, Any]) -> str:
        """Build PowerShell script"""
        
        script_header = f"""# AttackGen Generated PowerShell Script
# Generated: {datetime.utcnow().isoformat()}
# Technique: {command_data.get('name', 'Unknown')}
# Command: {command_data.get('command', '')}

# Prerequisites check
if (-not (Get-Command powershell -ErrorAction SilentlyContinue)) {{
    Write-Error "PowerShell not available"
    exit 1
}}

# Main execution
try {{
"""
        
        script_footer = """
} catch {
    Write-Error "Execution failed: $_"
    exit 1
}

# Cleanup section
Write-Host "Execution completed. Run cleanup if needed."
"""
        
        main_command = f"    {command_data.get('command', '')}"
        
        return script_header + main_command + script_footer
    
    async def _build_bash_script(self, command_data: Dict[str, Any]) -> str:
        """Build Bash script"""
        
        script_header = f"""#!/bin/bash
# AttackGen Generated Bash Script
# Generated: {datetime.utcnow().isoformat()}
# Technique: {command_data.get('name', 'Unknown')}
# Command: {command_data.get('command', '')}

set -e  # Exit on any error

# Prerequisites check
if ! command -v bash &> /dev/null; then
    echo "Bash not available" >&2
    exit 1
fi

# Main execution
"""
        
        script_footer = """
# Cleanup section
echo "Execution completed. Run cleanup if needed."
"""
        
        main_command = command_data.get('command', '')
        
        return script_header + main_command + script_footer
    
    async def _build_generic_script(self, command_data: Dict[str, Any]) -> str:
        """Build generic script"""
        
        return f"""# AttackGen Generated Script
# Generated: {datetime.utcnow().isoformat()}
# Technique: {command_data.get('name', 'Unknown')}

{command_data.get('command', '')}
"""