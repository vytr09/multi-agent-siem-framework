# agents/attackgen/generators/windows_generator.py
"""
Windows-specific attack command generator.
"""

import asyncio
from typing import Dict, Any, List
import yaml
from pathlib import Path

from agents.attackgen.generators.base_generator import BaseGenerator
from agents.attackgen.exceptions import AttackGenException


class WindowsGenerator(BaseGenerator):
    """
    Generator for Windows-specific attack commands.
    """
    
    def __init__(self):
        super().__init__('windows')
    
    async def initialize(self) -> None:
        """Initialize Windows generator"""
        await super().initialize()
    
    async def generate_from_templates(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate Windows commands from templates"""
        
        technique_id = ttp['attack_id']
        tactic = ttp['tactic'].lower().replace(' ', '_')
        
        commands = []
        
        # If no specific templates, generate generic commands
        if not commands:
            commands = await self._generate_generic_windows_commands(ttp, attack_details)
        
        return commands
    
    async def _generate_generic_windows_commands(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate generic Windows commands when no templates available"""
        
        technique_id = ttp['attack_id']
        technique_name = ttp['technique_name']
        tactic = ttp['tactic']
        
        commands = []
        
        # Generate based on tactic
        if 'execution' in tactic.lower():
            commands.extend(await self._generate_execution_commands(ttp))
        elif 'persistence' in tactic.lower():
            commands.extend(await self._generate_persistence_commands(ttp))
        elif 'privilege escalation' in tactic.lower():
            commands.extend(await self._generate_privesc_commands(ttp))
        elif 'defense evasion' in tactic.lower():
            commands.extend(await self._generate_evasion_commands(ttp))
        elif 'credential access' in tactic.lower():
            commands.extend(await self._generate_credential_commands(ttp))
        elif 'discovery' in tactic.lower():
            commands.extend(await self._generate_discovery_commands(ttp))
        else:
            # Generic command
            commands.append({
                'type': 'generic',
                'name': f'Generic {technique_name} Command',
                'command': f'# {technique_name} ({technique_id}) demonstration\necho "Executing {technique_name}"',
                'explanation': f'Generic demonstration of {technique_name}',
                'indicators': ['Command line execution', f'{technique_name} technique'],
                'prerequisites': ['Windows OS', 'Command prompt access'],
                'cleanup': 'echo "Cleanup completed"',
                'source': 'windows_generic'
            })
        
        return commands
    
    async def _generate_execution_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate execution-specific commands"""
        return [
            {
                'type': 'execution',
                'name': 'PowerShell Execution',
                'command': 'powershell.exe -ExecutionPolicy Bypass -Command "Write-Host \'PowerShell Execution Test\'"',
                'explanation': 'Executes PowerShell command bypassing execution policy',
                'indicators': ['PowerShell process creation', 'ExecutionPolicy bypass'],
                'prerequisites': ['PowerShell available'],
                'cleanup': 'No cleanup required',
                'source': 'windows_execution'
            },
            {
                'type': 'execution',
                'name': 'WMI Command Execution',
                'command': 'wmic process call create "cmd.exe /c echo WMI execution test"',
                'explanation': 'Executes command using WMI',
                'indicators': ['WMI process creation', 'wmic.exe execution'],
                'prerequisites': ['WMI service running'],
                'cleanup': 'No cleanup required',
                'source': 'windows_execution'
            }
        ]
    
    async def _generate_persistence_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate persistence-specific commands"""
        return [
            {
                'type': 'persistence',
                'name': 'Registry Run Key Persistence',
                'command': r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestPersistence" /t REG_SZ /d "cmd.exe /c echo Persistence test"',
                'explanation': 'Creates registry run key for persistence',
                'indicators': ['Registry modification', 'Run key creation'],
                'prerequisites': ['Registry write access'],
                'cleanup': r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestPersistence" /f',
                'source': 'windows_persistence'
            }
        ]
    
    async def _generate_privesc_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate privilege escalation commands"""
        return [
            {
                'type': 'privilege_escalation',
                'name': 'UAC Bypass Test',
                'command': 'powershell.exe -Command "Start-Process cmd.exe -Verb runAs -WindowStyle Hidden"',
                'explanation': 'Attempts to bypass UAC using PowerShell',
                'indicators': ['PowerShell elevation attempt', 'UAC bypass'],
                'prerequisites': ['PowerShell available', 'Local admin rights'],
                'cleanup': 'No cleanup required',
                'source': 'windows_privesc'
            }
        ]
    
    async def _generate_evasion_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate defense evasion commands"""
        return [
            {
                'type': 'defense_evasion',
                'name': 'Process Hollowing Simulation',
                'command': 'powershell.exe -Command "$proc = Start-Process notepad.exe -PassThru; $proc.Kill()"',
                'explanation': 'Simulates process manipulation for evasion',
                'indicators': ['Process creation and termination', 'PowerShell execution'],
                'prerequisites': ['PowerShell available'],
                'cleanup': 'No cleanup required',
                'source': 'windows_evasion'
            }
        ]
    
    async def _generate_credential_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate credential access commands"""
        return [
            {
                'type': 'credential_access',
                'name': 'Credential Dumping Simulation',
                'command': 'powershell.exe -Command "Get-WmiObject -Class Win32_UserAccount | Select-Object Name"',
                'explanation': 'Simulates credential discovery using WMI',
                'indicators': ['WMI queries', 'User account enumeration'],
                'prerequisites': ['PowerShell available', 'WMI access'],
                'cleanup': 'No cleanup required',
                'source': 'windows_credential'
            }
        ]
    
    async def _generate_discovery_commands(self, ttp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate discovery commands"""
        return [
            {
                'type': 'discovery',
                'name': 'System Discovery',
                'command': 'systeminfo && whoami /all && net user',
                'explanation': 'Performs basic system and user discovery',
                'indicators': ['System information gathering', 'User enumeration'],
                'prerequisites': ['Command prompt access'],
                'cleanup': 'No cleanup required',
                'source': 'windows_discovery'
            }
        ]