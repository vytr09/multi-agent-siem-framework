from typing import Dict, Any, Optional

class ATTACKMapper:
    """Map techniques to MITRE ATT&CK"""
    
    def __init__(self):
        # Simplified ATT&CK database
        self.attack_db = {
            'spearphishing attachment': {
                'technique_id': 'T1566.001',
                'technique_name': 'Phishing: Spearphishing Attachment',
                'tactic': 'Initial Access',
                'subtechnique': True
            },
            'powershell': {
                'technique_id': 'T1059.001',
                'technique_name': 'Command and Scripting Interpreter: PowerShell',
                'tactic': 'Execution',
                'subtechnique': True
            },
            'os credential dumping': {
                'technique_id': 'T1003',
                'technique_name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'subtechnique': False
            },
            'registry run keys': {
                'technique_id': 'T1547.001',
                'technique_name': 'Boot or Logon Autostart Execution: Registry Run Keys',
                'tactic': 'Persistence',
                'subtechnique': True
            },
            'remote desktop protocol': {
                'technique_id': 'T1021.001',
                'technique_name': 'Remote Services: Remote Desktop Protocol',
                'tactic': 'Lateral Movement',
                'subtechnique': True
            }
        }
    
    def map_technique(self, technique_name: str, tactic: str = '', 
                     description: str = '') -> Optional[Dict[str, Any]]:
        """Map technique name to ATT&CK"""
        normalized = technique_name.lower().strip()
        
        # Direct match
        if normalized in self.attack_db:
            return self.attack_db[normalized]
        
        # Fuzzy match
        for key, value in self.attack_db.items():
            if key in normalized or normalized in key:
                return value
        
        return None