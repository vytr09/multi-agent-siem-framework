# agents/attackgen/generators/linux_generator.py
"""
Linux-specific attack command generator.
"""

from typing import Dict, Any, List
from agents.attackgen.generators.base_generator import BaseGenerator


class LinuxGenerator(BaseGenerator):
    """Generator for Linux-specific attack commands."""
    
    def __init__(self):
        super().__init__('linux')
    
    async def generate_from_templates(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate Linux commands from templates"""
        
        technique_id = ttp['attack_id']
        tactic = ttp['tactic'].lower()
        
        commands = []
        
        # Generate based on common Linux attack techniques
        if 'execution' in tactic:
            commands.extend(await self._generate_execution_commands(ttp))
        elif 'persistence' in tactic:
            commands.extend(await self._generate_persistence_commands(ttp))
        elif 'privilege escalation' in tactic:
            commands.extend(await self._generate_privesc_commands(ttp))
        elif 'discovery' in tactic:
            commands.extend(await self._generate_discovery_commands(ttp))
        
        return commands
    
    async def _generate_execution_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate Linux execution commands"""
        return [
            {
                'type': 'execution',
                'name': 'Bash Command Execution',
                'command': 'bash -c "echo Linux execution test"',
                'explanation': 'Executes bash command',
                'indicators': ['Bash process creation', 'Command execution'],
                'prerequisites': ['Bash shell available'],
                'cleanup': 'No cleanup required',
                'source': 'linux_execution'
            }
        ]
    
    async def _generate_persistence_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate Linux persistence commands"""
        return [
            {
                'type': 'persistence',
                'name': 'Crontab Persistence',
                'command': 'echo "* * * * * /bin/echo persistence test" | crontab -',
                'explanation': 'Creates crontab entry for persistence',
                'indicators': ['Crontab modification', 'Scheduled task creation'],
                'prerequisites': ['Crontab access'],
                'cleanup': 'crontab -r',
                'source': 'linux_persistence'
            }
        ]
    
    async def _generate_privesc_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate Linux privilege escalation commands"""
        return [
            {
                'type': 'privilege_escalation',
                'name': 'SUID Binary Discovery',
                'command': 'find / -perm -4000 -type f 2>/dev/null',
                'explanation': 'Finds SUID binaries for potential privilege escalation',
                'indicators': ['File system enumeration', 'SUID discovery'],
                'prerequisites': ['File system access'],
                'cleanup': 'No cleanup required',
                'source': 'linux_privesc'
            }
        ]
    
    async def _generate_discovery_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate Linux discovery commands"""
        return [
            {
                'type': 'discovery',
                'name': 'System Information Gathering',
                'command': 'uname -a && whoami && ps aux',
                'explanation': 'Gathers basic system and process information',
                'indicators': ['System info gathering', 'Process enumeration'],
                'prerequisites': ['Command line access'],
                'cleanup': 'No cleanup required',
                'source': 'linux_discovery'
            }
        ]
    
    async def get_atomic_red_team_commands(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get Atomic Red Team commands for Linux"""
        # Implementation similar to Windows but for Linux platforms
        return []