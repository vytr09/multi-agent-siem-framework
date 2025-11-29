#!/usr/bin/env python3
"""
Indicators of Compromise (IOC) & Evidence Extractor
Trích xuất indicators va evidence tu bao cao de tang coverage
"""

import re
from typing import Dict, List, Set, Any
from collections import Counter


class IndicatorExtractor:
    """Trích xuất IOCs va evidence tu text"""
    
    # Indicators patterns
    INDICATORS = {
        'file_hashes': {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
        },
        'network': {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'url': r'https?://[^\s\)]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        },
        'registry': {
            'registry_key': r'(?:HKEY_[A-Z_]+\\[^\s\)\\]*)',
        },
        'malware': {
            'malware_family': r'\b(?:Emotet|Ryuk|Trickbot|Dridex|Mirai|WannaCry|Petya|NotPetya|Locky|Cerber)\b',
            'ransomware': r'\b(?:Ransomware|Encryptor|Cryptolocker|Sodinokibi|REvil|DarkSide)\b',
        },
        'techniques': {
            'credential_dump': r'(?:credential|password|hash|lsass|sam|ntds|dump|extract)',
            'lateral_movement': r'(?:lateral|psexec|wmi|rpc|ssh|rdp)',
            'command_execution': r'(?:powershell|cmd\.exe|batch|shell|script|execute)',
            'persistence': r'(?:persistence|registry|startup|boot|service|scheduled)',
            'defense_evasion': r'(?:obfuscate|encode|encrypt|bypass|evade|defense)',
        }
    }
    
    def __init__(self):
        """Initialize extractor"""
        self.compiled_patterns = {}
        for category, patterns in self.INDICATORS.items():
            self.compiled_patterns[category] = {}
            for name, pattern in patterns.items():
                self.compiled_patterns[category][name] = re.compile(pattern, re.IGNORECASE)
    
    def extract_indicators(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all indicators from text
        """
        indicators = {}
        
        for category, patterns in self.compiled_patterns.items():
            indicators[category] = {}
            for name, compiled_pattern in patterns.items():
                matches = compiled_pattern.findall(text)
                if matches:
                    indicators[category][name] = list(set(matches))  # unique
        
        return indicators
    
    def extract_evidence_phrases(self, text: str) -> Dict[str, List[str]]:
        """
        Extract evidence phrases for technique matching
        """
        evidence = {
            'attack_indicators': [],
            'tool_mentions': [],
            'malware_mentions': [],
            'capability_mentions': [],
        }
        
        # Attack indicators
        attack_patterns = [
            r'(?:attack|incident|breach|compromise|intrusion|exploitation)',
            r'(?:malicious|suspicious|adversarial|threat|malware)',
            r'(?:unauthorized|illegal|unauthorized|unauthorized)',
        ]
        
        for pattern in attack_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                evidence['attack_indicators'].append(text[start:end].strip())
        
        # Tool mentions
        tools = [
            'mimikatz', 'psexec', 'powershell', 'wmi', 'cmd', 'batch',
            'vbscript', 'javascript', 'python', 'perl', 'ruby',
            'metasploit', 'cobalt strike', 'empire', 'meterpreter',
            'beacon', 'shellcode', 'payload', 'exploit'
        ]
        
        for tool in tools:
            if tool.lower() in text.lower():
                pattern = f'(?i){re.escape(tool)}'
                matches = re.finditer(pattern, text)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    evidence['tool_mentions'].append(text[start:end].strip())
        
        # Malware mentions
        malware_names = [
            'trojan', 'worm', 'ransomware', 'virus', 'botnet',
            'backdoor', 'rootkit', 'spyware', 'adware', 'keylogger'
        ]
        
        for malware in malware_names:
            if malware.lower() in text.lower():
                pattern = f'(?i){re.escape(malware)}'
                matches = re.finditer(pattern, text)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    evidence['malware_mentions'].append(text[start:end].strip())
        
        return evidence
    
    def calculate_indicator_score(self, indicators: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on indicator count and diversity
        """
        score = 0.5  # base
        
        total_indicators = 0
        categories_found = 0
        
        for category, items in indicators.items():
            if isinstance(items, dict):
                for name, values in items.items():
                    if values:
                        total_indicators += len(values)
                        categories_found += 1
        
        # Add score based on count
        if total_indicators > 0:
            score += min(total_indicators * 0.05, 0.3)  # up to 0.3 bonus
        
        # Add score based on diversity
        if categories_found > 0:
            score += min(categories_found * 0.05, 0.15)  # up to 0.15 bonus
        
        return min(score, 1.0)
