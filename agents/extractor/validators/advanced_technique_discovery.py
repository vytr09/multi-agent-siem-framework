#!/usr/bin/env python3
"""
Advanced Technique Discovery
Phat hien them ATT&CK techniques tu text va indicators
"""

import re
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass


@dataclass
class TechniqueMatch:
    """Result cua technique matching"""
    technique_id: str
    technique_name: str
    confidence: float
    evidence: List[str]
    evidence_type: str


class AdvancedTechniqueDiscovery:
    """Phat hien techniques tu multiple evidence sources"""
    
    # Comprehensive technique mappings based on evidence patterns
    TECHNIQUE_PATTERNS = {
        'T1003': {  # OS Credential Dumping
            'name': 'OS Credential Dumping',
            'tactic': 'Credential Access',
            'patterns': [
                r'(?:credential|password|hash|lsass|sam|ntds|dcync|sekurlsa)',
                r'(?:dump.*password|extract.*credential)',
                r'(?:mimikatz|credential manager|password dump)',
            ]
        },
        'T1087': {  # Account Discovery
            'name': 'Account Discovery',
            'tactic': 'Discovery',
            'patterns': [
                r'(?:enumerate.*account|list.*user|account discovery)',
                r'(?:net user|wmic useraccount|dsquery)',
                r'(?:getaduser|get-localuser)',
            ]
        },
        'T1552': {  # Unsecured Credentials
            'name': 'Unsecured Credentials',
            'tactic': 'Credential Access',
            'patterns': [
                r'(?:credential.*found|password.*plaintext|hardcoded)',
                r'(?:config.*password|api.*key)',
                r'(?:exposed.*credential|leaked.*password)',
            ]
        },
        'T1110': {  # Brute Force
            'name': 'Brute Force',
            'tactic': 'Credential Access',
            'patterns': [
                r'(?:brute force|password spray|credential stuffing)',
                r'(?:dictionary attack|rainbow table)',
                r'(?:repeated.*authentication|failed.*logon)',
            ]
        },
        'T1040': {  # Network Sniffing
            'name': 'Network Sniffing',
            'tactic': 'Credential Access',
            'patterns': [
                r'(?:packet capture|network sniff|wireshark|tcpdump)',
                r'(?:traffic.*capture|network.*intercept)',
                r'(?:sniffer|promiscuous)',
            ]
        },
        'T1598': {  # Phishing for Information
            'name': 'Phishing for Information',
            'tactic': 'Reconnaissance',
            'patterns': [
                r'(?:phishing.*information|information gathering)',
                r'(?:spear.*phish|targeted.*phish)',
                r'(?:social engineer)',
            ]
        },
        'T1566': {  # Phishing
            'name': 'Phishing',
            'tactic': 'Initial Access',
            'patterns': [
                r'(?:phishing|spear phishing|malicious email)',
                r'(?:attachment.*malware|email.*exploit)',
                r'(?:phishing campaign)',
            ]
        },
        'T1199': {  # Trusted Relationship
            'name': 'Trusted Relationship',
            'tactic': 'Initial Access',
            'patterns': [
                r'(?:trusted.*relationship|supply chain|third party)',
                r'(?:vendor compromise|partner compromise)',
                r'(?:software.*update.*malware)',
            ]
        },
        'T1190': {  # Exploit Public-Facing Application
            'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access',
            'patterns': [
                r'(?:exploit.*vulnerability|public.*facing)',
                r'(?:rce|remote code execution)',
                r'(?:web.*exploit|application.*exploit)',
            ]
        },
        'T1021': {  # Remote Services
            'name': 'Remote Services',
            'tactic': 'Lateral Movement',
            'patterns': [
                r'(?:rdp|ssh|psexec|rpc|wmi|dcom)',
                r'(?:remote.*access|lateral movement)',
                r'(?:admin.*share|ipc\$)',
            ]
        },
        'T1210': {  # Exploitation of Remote Services
            'name': 'Exploitation of Remote Services',
            'tactic': 'Lateral Movement',
            'patterns': [
                r'(?:exploit.*service|rce|remote)',
                r'(?:vulnerability.*exploit)',
                r'(?:zerologon|eternblue|cve)',
            ]
        },
        'T1570': {  # Lateral Tool Transfer
            'name': 'Lateral Tool Transfer',
            'tactic': 'Lateral Movement',
            'patterns': [
                r'(?:tool.*transfer|malware.*propagat)',
                r'(?:copy.*share|move.*file)',
                r'(?:lateral.*deployment)',
            ]
        },
        'T1047': {  # Windows Management Instrumentation
            'name': 'Windows Management Instrumentation',
            'tactic': 'Execution',
            'patterns': [
                r'(?:wmi|wmic|windows.*management)',
                r'(?:wmiexec|wmicexec)',
                r'(?:ciminstance)',
            ]
        },
        'T1059': {  # Command and Scripting Interpreter
            'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution',
            'patterns': [
                r'(?:powershell|cmd\.exe|bash|shell script)',
                r'(?:command line|shell execution)',
                r'(?:script.*execution)',
            ]
        },
        'T1053': {  # Scheduled Task/Job
            'name': 'Scheduled Task/Job',
            'tactic': 'Execution',
            'patterns': [
                r'(?:scheduled.*task|cron|at command)',
                r'(?:task scheduler|launchd)',
                r'(?:scheduled job)',
            ]
        },
        'T1176': {  # Browser Extensions
            'name': 'Browser Extensions',
            'tactic': 'Persistence',
            'patterns': [
                r'(?:browser.*extension|plugin|addon)',
                r'(?:malicious.*extension|rogue extension)',
                r'(?:browser hijack)',
            ]
        },
        'T1547': {  # Boot or Logon Autostart Execution
            'name': 'Boot or Logon Autostart Execution',
            'tactic': 'Persistence',
            'patterns': [
                r'(?:registry.*run|startup.*folder)',
                r'(?:boot.*persistence|autostart)',
                r'(?:hklm.*run)',
            ]
        },
        'T1197': {  # BITS Jobs
            'name': 'BITS Jobs',
            'tactic': 'Defense Evasion',
            'patterns': [
                r'(?:bits job|bitsadmin)',
                r'(?:background.*intelligent)',
                r'(?:bits.*transfer)',
            ]
        },
        'T1140': {  # Deobfuscate/Decode Files or Information
            'name': 'Deobfuscate/Decode Files or Information',
            'tactic': 'Defense Evasion',
            'patterns': [
                r'(?:deobfuscat|decode|decrypt)',
                r'(?:base64|obfuscat)',
                r'(?:decompil|disassembl)',
            ]
        },
        'T1036': {  # Masquerading
            'name': 'Masquerading',
            'tactic': 'Defense Evasion',
            'patterns': [
                r'(?:disguise|masquerad|fake|imperson)',
                r'(?:name spoof|fake extension)',
                r'(?:double extension)',
            ]
        },
        'T1070': {  # Indicator Removal
            'name': 'Indicator Removal',
            'tactic': 'Defense Evasion',
            'patterns': [
                r'(?:log.*clear|delete.*evidence)',
                r'(?:wipe.*trace|remove.*log)',
                r'(?:clear event)',
            ]
        },
        'T1041': {  # Exfiltration Over C2 Channel
            'name': 'Exfiltration Over C2 Channel',
            'tactic': 'Exfiltration',
            'patterns': [
                r'(?:data.*exfiltrat|steal|extract)',
                r'(?:c2.*channel|command.*control)',
                r'(?:exfil.*c2)',
            ]
        },
        'T1020': {  # Automated Exfiltration
            'name': 'Automated Exfiltration',
            'tactic': 'Exfiltration',
            'patterns': [
                r'(?:automated.*exfil|continuous)',
                r'(?:background.*transfer)',
                r'(?:automated.*data)',
            ]
        },
    }
    
    def __init__(self):
        """Initialize discovery"""
        self.compiled_patterns = {}
        for tech_id, tech_data in self.TECHNIQUE_PATTERNS.items():
            patterns = []
            for pattern_str in tech_data['patterns']:
                patterns.append(re.compile(pattern_str, re.IGNORECASE))
            self.compiled_patterns[tech_id] = patterns
    
    def discover_techniques(
        self,
        text: str,
        indicators: Dict[str, any] = None,
        tools: List[str] = None,
        existing_techniques: Set[str] = None
    ) -> List[TechniqueMatch]:
        """
        Discover techniques from text, indicators, and tools
        """
        if existing_techniques is None:
            existing_techniques = set()
        
        matches = []
        
        # Pattern-based discovery
        for tech_id, patterns in self.compiled_patterns.items():
            if tech_id in existing_techniques:
                continue
            
            evidence = []
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    evidence.extend(found)
            
            if evidence:
                tech_data = self.TECHNIQUE_PATTERNS[tech_id]
                confidence = min(len(set(evidence)) * 0.2, 0.9)
                
                matches.append(TechniqueMatch(
                    technique_id=tech_id,
                    technique_name=tech_data['name'],
                    confidence=confidence,
                    evidence=list(set(evidence))[:3],
                    evidence_type='text_pattern'
                ))
        
        # Indicator-based discovery
        if indicators:
            indicator_matches = self._discover_from_indicators(indicators, existing_techniques)
            matches.extend(indicator_matches)
        
        # Tool-based discovery
        if tools:
            tool_matches = self._discover_from_tools(tools, existing_techniques)
            matches.extend(tool_matches)
        
        # Sort by confidence
        matches.sort(key=lambda x: x.confidence, reverse=True)
        
        return matches
    
    def _discover_from_indicators(
        self,
        indicators: Dict[str, any],
        existing_techniques: Set[str]
    ) -> List[TechniqueMatch]:
        """Discover techniques based on indicators"""
        matches = []
        
        # Hash indicators suggest credential dumping
        if indicators.get('file_hashes'):
            if 'T1003' not in existing_techniques:
                matches.append(TechniqueMatch(
                    technique_id='T1003',
                    technique_name='OS Credential Dumping',
                    confidence=0.7,
                    evidence=['Credential-related hashes found'],
                    evidence_type='indicator'
                ))
        
        # Network indicators suggest command and control
        if indicators.get('network'):
            matches.append(TechniqueMatch(
                technique_id='T1071',
                technique_name='Application Layer Protocol',
                confidence=0.65,
                evidence=['Network communication detected'],
                evidence_type='indicator'
            ))
        
        # Registry indicators suggest persistence
        if indicators.get('registry'):
            if 'T1547' not in existing_techniques:
                matches.append(TechniqueMatch(
                    technique_id='T1547',
                    technique_name='Boot or Logon Autostart Execution',
                    confidence=0.6,
                    evidence=['Registry persistence indicators'],
                    evidence_type='indicator'
                ))
        
        return matches
    
    def _discover_from_tools(
        self,
        tools: List[str],
        existing_techniques: Set[str]
    ) -> List[TechniqueMatch]:
        """Discover techniques based on tools"""
        matches = []
        
        tool_technique_map = {
            'mimikatz': ('T1003', 'OS Credential Dumping'),
            'psexec': ('T1021', 'Remote Services'),
            'powershell': ('T1059', 'Command and Scripting Interpreter'),
            'wmi': ('T1047', 'Windows Management Instrumentation'),
            'cmd': ('T1059', 'Command and Scripting Interpreter'),
        }
        
        for tool in tools:
            tool_lower = tool.lower()
            for tool_key, (tech_id, tech_name) in tool_technique_map.items():
                if tool_key in tool_lower and tech_id not in existing_techniques:
                    matches.append(TechniqueMatch(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        confidence=0.75,
                        evidence=[f'Tool detected: {tool}'],
                        evidence_type='tool'
                    ))
                    break
        
        return matches
    
    def get_top_techniques(self, matches: List[TechniqueMatch], top_n: int = 10) -> List[TechniqueMatch]:
        """Get top N techniques by confidence"""
        return sorted(matches, key=lambda x: x.confidence, reverse=True)[:top_n]
