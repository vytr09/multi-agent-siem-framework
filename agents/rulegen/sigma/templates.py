# agents/rulegen/sigma/templates.py

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class SigmaTemplates:
    """
    Pre-defined Sigma rule templates for common detection scenarios
    """
    
    @staticmethod
    def get_process_creation_template() -> Dict[str, Any]:
        """Template for process creation detection"""
        return {
            'title': 'Suspicious Process Creation',
            'id': '',  # To be filled
            'status': 'experimental',
            'description': 'Detects suspicious process creation activity',
            'references': [],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.t1059.001',
                'attack.execution'
            ],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection_img': {
                    'Image|endswith': [
                        '\\powershell.exe',
                        '\\pwsh.exe'
                    ]
                },
                'selection_cmd': {
                    'CommandLine|contains': [
                        '-enc',
                        '-encodedcommand',
                        'bypass',
                        '-nop',
                        '-w hidden'
                    ]
                },
                'condition': 'selection_img and selection_cmd'
            },
            'falsepositives': [
                'Administrative scripts',
                'Legitimate automation'
            ],
            'level': 'high'
        }
    
    @staticmethod
    def get_credential_dumping_template() -> Dict[str, Any]:
        """Template for credential dumping detection"""
        return {
            'title': 'Credential Dumping Activity',
            'id': '',
            'status': 'experimental',
            'description': 'Detects potential credential dumping attempts',
            'references': [
                'https://attack.mitre.org/techniques/T1003/'
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.t1003',
                'attack.credential_access'
            ],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': [
                        'lsass',
                        'sekurlsa',
                        'procdump',
                        'mimikatz'
                    ]
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'Security tools',
                'Legitimate debugging'
            ],
            'level': 'critical'
        }
    
    @staticmethod
    def get_lateral_movement_template() -> Dict[str, Any]:
        """Template for lateral movement detection"""
        return {
            'title': 'Lateral Movement Activity',
            'id': '',
            'status': 'experimental',
            'description': 'Detects potential lateral movement attempts',
            'references': [
                'https://attack.mitre.org/tactics/TA0008/'
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.lateral_movement'
            ],
            'logsource': {
                'category': 'network_connection',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'DestinationPort': [
                        135, 139, 445, 3389, 5985, 5986
                    ],
                    'Initiated': 'true'
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'Administrative access',
                'System administration'
            ],
            'level': 'high'
        }
    
    @staticmethod
    def get_persistence_template() -> Dict[str, Any]:
        """Template for persistence mechanism detection"""
        return {
            'title': 'Persistence Mechanism Detected',
            'id': '',
            'status': 'experimental',
            'description': 'Detects establishment of persistence mechanisms',
            'references': [
                'https://attack.mitre.org/tactics/TA0003/'
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.persistence',
                'attack.t1547'
            ],
            'logsource': {
                'category': 'registry_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'TargetObject|contains': [
                        '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                        '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                        '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
                    ],
                    'EventType': 'SetValue'
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'Software installation',
                'System updates'
            ],
            'level': 'high'
        }
    
    @staticmethod
    def get_command_and_control_template() -> Dict[str, Any]:
        """Template for C2 communication detection"""
        return {
            'title': 'Command and Control Communication',
            'id': '',
            'status': 'experimental',
            'description': 'Detects potential C2 communication patterns',
            'references': [
                'https://attack.mitre.org/tactics/TA0011/'
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.command_and_control'
            ],
            'logsource': {
                'category': 'network_connection',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'Initiated': 'true',
                    'DestinationPort': [
                        4444, 8080, 8443, 443
                    ]
                },
                'filter': {
                    'DestinationHostname|endswith': [
                        '.microsoft.com',
                        '.windows.com'
                    ]
                },
                'condition': 'selection and not filter'
            },
            'falsepositives': [
                'Legitimate web traffic',
                'Software updates'
            ],
            'level': 'medium'
        }
    
    @staticmethod
    def get_network_connection_template() -> Dict[str, Any]:
        """Template for network connection detection"""
        return {
            'title': 'Suspicious Network Connection',
            'id': '',
            'status': 'experimental',
            'description': 'Detects suspicious network connection activity',
            'references': [],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [],
            'logsource': {
                'category': 'network_connection',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'Initiated': 'true',
                    'DestinationHostname|endswith': [],
                    'DestinationIp': []
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'Legitimate software updates',
                'Administrative activity'
            ],
            'level': 'medium'
        }
    
    @staticmethod
    def get_file_event_template() -> Dict[str, Any]:
        """Template for file event detection"""
        return {
            'title': 'Suspicious File Activity',
            'id': '',
            'status': 'experimental',
            'description': 'Detects suspicious file creation or modification',
            'references': [],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [],
            'logsource': {
                'category': 'file_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'TargetFilename|contains': [],
                    'TargetFilename|endswith': []
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'System updates',
                'Software installation'
            ],
            'level': 'medium'
        }
    
    @staticmethod
    def get_registry_event_template() -> Dict[str, Any]:
        """Template for registry event detection"""
        return {
            'title': 'Suspicious Registry Modification',
            'id': '',
            'status': 'experimental',
            'description': 'Detects suspicious registry modifications',
            'references': [],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [],
            'logsource': {
                'category': 'registry_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'EventType': 'SetValue',
                    'TargetObject|contains': []
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'System updates',
                'Administrative changes'
            ],
            'level': 'medium'
        }
    
    @staticmethod
    def get_powershell_execution_template() -> Dict[str, Any]:
        """Template for PowerShell execution detection"""
        return {
            'title': 'Suspicious PowerShell Execution',
            'id': '',
            'status': 'experimental',
            'description': 'Detects suspicious PowerShell command execution',
            'references': [
                'https://attack.mitre.org/techniques/T1059/001/'
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [
                'attack.t1059.001',
                'attack.execution'
            ],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': [],
                    'Image|endswith': []
                },
                'condition': 'selection'
            },
            'falsepositives': [
                'Unknown'
            ],
            'level': 'medium'
        }
    
    @staticmethod
    def get_template_by_category(category: str) -> Dict[str, Any]:
        """
        Get template by log source category
        
        Args:
            category: Log source category
            
        Returns:
            Appropriate template dictionary
        """
        templates = {
            'process_creation': SigmaTemplates.get_process_creation_template,
            'network_connection': SigmaTemplates.get_network_connection_template,
            'file_event': SigmaTemplates.get_file_event_template,
            'registry_event': SigmaTemplates.get_registry_event_template
        }
        
        template_func = templates.get(category, SigmaTemplates.get_process_creation_template)
        return template_func()
    
    @staticmethod
    def get_template_by_technique(technique_id: str) -> Dict[str, Any]:
        """
        Get template by MITRE ATT&CK technique
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003)
            
        Returns:
            Appropriate template dictionary
        """
        technique_templates = {
            'T1003': SigmaTemplates.get_credential_dumping_template,
            'T1059': SigmaTemplates.get_powershell_execution_template,
            'T1547': SigmaTemplates.get_persistence_template,
            'T1021': SigmaTemplates.get_lateral_movement_template,
            'T1071': SigmaTemplates.get_command_and_control_template
        }
        
        # Try exact match first
        if technique_id in technique_templates:
            return technique_templates[technique_id]()
        
        # Try parent technique (e.g., T1059.001 -> T1059)
        parent_technique = technique_id.split('.')[0]
        if parent_technique in technique_templates:
            return technique_templates[parent_technique]()
        
        # Default to process creation
        return SigmaTemplates.get_process_creation_template()
    
    @staticmethod
    def list_available_templates() -> List[str]:
        """List all available template types"""
        return [
            'process_creation',
            'network_connection',
            'file_event',
            'registry_event',
            'powershell_execution',
            'credential_dumping',
            'lateral_movement',
            'persistence',
            'command_and_control'
        ]