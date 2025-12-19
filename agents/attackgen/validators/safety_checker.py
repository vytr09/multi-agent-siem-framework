# agents/attackgen/validators/safety_checker.py
"""
Safety validation for generated attack commands.
"""

from typing import Dict, Any
import re


class SafetyChecker:
    """
    Validates attack commands for safety and compliance.
    """
    
    def __init__(self):
        # Dangerous patterns that should be blocked
        self.high_risk_patterns = [
            r'rm\s+-rf\s+/',  # Dangerous file deletion
            r'dd\s+if=.*of=/dev/sd',  # Disk wiping
            r':(){ :|:& };:',  # Fork bomb
            r'mkfs\.',  # Format filesystem
            r'fdisk.*--delete',  # Delete partitions
            r'Get-ChildItem.*-Recurse',  # Dangerous recursive listing (Freeze Risk)
            r'dir\s.*\/s',  # Recursive dir (Freeze Risk)
        ]
        
        # Medium risk patterns that need careful review
        self.medium_risk_patterns = [
            r'wget.*\|\s*bash',  # Download and execute
            r'curl.*\|\s*sh',  # Download and execute
            r'nc.*-e\s*/bin/',  # Netcat reverse shell
            r'python.*-c.*socket',  # Python reverse shell
        ]
        
        # Network connection patterns
        self.network_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            r'nc\s+.*\d+',  # Netcat connections
            r'telnet\s+',  # Telnet connections
        ]
    
    async def is_safe(self, command_data: Dict[str, Any], safety_level: str = 'medium') -> bool:
        """
        Check if command is safe for execution.
        
        Args:
            command_data: Command data to validate
            safety_level: 'low', 'medium', or 'high'
            
        Returns:
            True if command is safe, False otherwise
        """
        
        command = command_data.get('command', '')
        
        # Always block high-risk patterns
        for pattern in self.high_risk_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        
        # Check medium risk patterns based on safety level
        if safety_level in ['medium', 'high']:
            for pattern in self.medium_risk_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    if safety_level == 'high':
                        return False
                    # Medium level allows with warning
                    command_data['warnings'] = command_data.get('warnings', [])
                    command_data['warnings'].append(f"Medium risk pattern detected: {pattern}")
        
        # Additional checks for high safety level
        if safety_level == 'high':
            # Block any network connections
            for pattern in self.network_patterns:
                if re.search(pattern, command):
                    return False
            
            # Block privileged operations
            if any(keyword in command.lower() for keyword in ['sudo', 'su -', 'runas']):
                return False
        
        return True