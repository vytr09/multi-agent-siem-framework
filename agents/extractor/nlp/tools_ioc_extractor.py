#!/usr/bin/env python3
"""
Enhanced Tools & Indicators Extractor
Cải thiện extraction của tools, IOCs, và correlation
"""

import re
from typing import Dict, List, Set, Tuple
from collections import Counter
import hashlib


class ToolsAndIndicatorsExtractor:
    """Advanced extraction của tools, malware, và IOCs"""
    
    # Danh sách tools phổ biến (expanded)
    COMMON_TOOLS = {
        'admin_tools': {
            'psexec', 'paexec', 'winexe', 'sysinternals', 'autoruns',
            'pspasswd', 'psgetsid', 'psloggedon', 'psservice', 'psshutdown',
            'pass-the-hash', 'mimikatz', 'hashcat', 'john', 'ophcrack'
        },
        'living_off_land': {
            'powershell', 'cmd', 'wmi', 'wmic', 'vbscript', 'cscript',
            'regsvr32', 'rundll32', 'certutil', 'certreq', 'bitsadmin',
            'msiexec', 'rundll32', 'schtasks', 'taskkill', 'tasklist',
            'netstat', 'ipconfig', 'nslookup', 'nbtstat', 'route',
            'sc.exe', 'reg.exe', 'net.exe', 'attrib.exe', 'cipher.exe'
        },
        'credential_tools': {
            'mimikatz', 'laZagne', 'hashcat', 'john', 'konan', 'credential_dumper',
            'pass-the-hash', 'pass-the-ticket', 'secretsdump', 'impacket',
            'pypykatz', 'sam', 'ntds.dit', 'lsass'
        },
        'c2_tools': {
            'cobalt strike', 'metasploit', 'empire', 'powershell empire',
            'apt', 'sliver', 'mythic', 'covenant', 'brute ratel',
            'havoc', 'caldera', 'merlin', 'lolcat'
        },
        'exploitation': {
            'exploit-db', 'eternalblue', 'zerologon', 'printnightmare',
            'proxylogon', 'codeexecution', 'rce', 'cve'
        },
        'network_tools': {
            'nmap', 'wireshark', 'tcpdump', 'netcat', 'nc', 'socat',
            'proxychains', 'burp', 'metasploit', 'nessus', 'openvas'
        },
        'obfuscation': {
            'obfuscator', 'packer', 'crypter', 'xor', 'base64',
            'polymorphic', 'metamorphic', 'shellcode', 'reflective'
        },
        'data_exfiltration': {
            'pscp', 'plink', 'ftp', 'sftp', 'scp', 'curl', 'wget',
            'rabit hole', 'comet', 'ekko', '7z', 'rar', 'zip'
        }
    }
    
    # IOC Patterns
    HASH_PATTERNS = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'imphash': r'[a-fA-F0-9]{32}',
    }
    
    IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    DOMAIN_PATTERN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    URL_PATTERN = r'https?://[^\s]+'
    REGISTRY_PATTERN = r'HKEY_[A-Z_]+\\[^\s\)]+'
    FILE_PATTERN = r'(?:[A-Za-z]:\\[^\s]+|[A-Za-z0-9_/\-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|zip|rar))'
    
    def __init__(self):
        self.compiled_patterns = {
            'ip': re.compile(self.IP_PATTERN),
            'domain': re.compile(self.DOMAIN_PATTERN, re.IGNORECASE),
            'email': re.compile(self.EMAIL_PATTERN),
            'url': re.compile(self.URL_PATTERN),
            'registry': re.compile(self.REGISTRY_PATTERN),
            'file': re.compile(self.FILE_PATTERN, re.IGNORECASE)
        }
        
        self.hash_patterns = {
            k: re.compile(v) for k, v in self.HASH_PATTERNS.items()
        }
    
    def extract_tools(self, text: str, nlp_entities: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Extract tools từ text + NLP entities
        Returns grouped tools by category
        """
        text_lower = text.lower()
        found_tools = {category: [] for category in self.COMMON_TOOLS.keys()}
        found_tools['mentioned'] = []
        
        # From NLP entities (high confidence)
        nlp_tools = nlp_entities.get('tools', [])
        found_tools['mentioned'].extend(nlp_tools)
        
        # Pattern-based detection
        for category, tools in self.COMMON_TOOLS.items():
            for tool in tools:
                # Word boundary search
                pattern = r'\b' + re.escape(tool) + r'\b'
                if re.search(pattern, text_lower):
                    found_tools[category].append(tool)
        
        # Remove duplicates and sort
        for category in found_tools:
            found_tools[category] = sorted(list(set(found_tools[category])))
        
        # Consolidate to top-level
        all_tools = []
        for category, tools in found_tools.items():
            all_tools.extend(tools)
        
        return {
            'all_tools': sorted(list(set(all_tools))),
            'by_category': found_tools,
            'count': len(set(all_tools))
        }
    
    def extract_iocs(self, text: str) -> Dict[str, any]:
        """Extract all IOCs from text"""
        iocs = {
            'hashes': {},
            'ips': [],
            'domains': [],
            'emails': [],
            'urls': [],
            'registry': [],
            'files': []
        }
        
        # Hash extraction
        for hash_type, pattern in self.hash_patterns.items():
            matches = set(pattern.findall(text))
            if matches:
                iocs['hashes'][hash_type] = list(matches)
        
        # IP extraction (remove duplicates)
        ips = set(self.compiled_patterns['ip'].findall(text))
        iocs['ips'] = sorted(list(ips))
        
        # Domain extraction
        domains = set(self.compiled_patterns['domain'].findall(text))
        # Filter out false positives
        domains = {d for d in domains if len(d) > 4 and '.' in d}
        iocs['domains'] = sorted(list(domains))
        
        # Email extraction
        emails = set(self.compiled_patterns['email'].findall(text))
        iocs['emails'] = sorted(list(emails))
        
        # URL extraction
        urls = set(self.compiled_patterns['url'].findall(text))
        iocs['urls'] = sorted(list(urls))
        
        # Registry extraction
        registry = set(self.compiled_patterns['registry'].findall(text))
        iocs['registry'] = sorted(list(registry))
        
        # File extraction
        files = set(self.compiled_patterns['file'].findall(text))
        iocs['files'] = sorted(list(files))
        
        return iocs
    
    def correlate_iocs_with_ttps(self, ttps: List[Dict], iocs: Dict, text: str) -> List[Dict]:
        """
        Correlate IOCs with TTPs based on proximity and context
        """
        for ttp in ttps:
            technique = ttp.get('technique_name', '').lower()
            description = ttp.get('description', '').lower()
            
            related_iocs = {
                'hashes': [],
                'ips': [],
                'domains': [],
                'files': [],
                'registry': []
            }
            
            # Credential Access TTPs → look for hash types
            if 'credential' in technique or 'credential' in description:
                hash_values = []
                for hash_type, values in iocs.get('hashes', {}).items():
                    if isinstance(values, list):
                        hash_values.extend(values[:2])
                related_iocs['hashes'] = hash_values
            
            # Lateral Movement → look for IPs, domains
            if 'lateral' in technique or 'remote' in description:
                related_iocs['ips'] = iocs.get('ips', [])[:5] if isinstance(iocs.get('ips'), list) else []
                related_iocs['domains'] = iocs.get('domains', [])[:5] if isinstance(iocs.get('domains'), list) else []
            
            # Defense Evasion, Persistence → registry
            if 'defense' in technique or 'persistence' in technique:
                related_iocs['registry'] = iocs.get('registry', [])[:3] if isinstance(iocs.get('registry'), list) else []
            
            # Command & Control → URLs, IPs, domains
            if 'command' in technique or 'control' in description:
                related_iocs['urls'] = iocs.get('urls', [])[:3] if isinstance(iocs.get('urls'), list) else []
                related_iocs['ips'] = iocs.get('ips', [])[:5] if isinstance(iocs.get('ips'), list) else []
                related_iocs['domains'] = iocs.get('domains', [])[:5] if isinstance(iocs.get('domains'), list) else []
            
            # Exfiltration → files, domains, IPs
            if 'exfiltration' in technique or 'collection' in description:
                related_iocs['files'] = iocs.get('files', [])[:5] if isinstance(iocs.get('files'), list) else []
                related_iocs['domains'] = iocs.get('domains', [])[:5] if isinstance(iocs.get('domains'), list) else []
            
            ttp['correlated_iocs'] = {
                k: v for k, v in related_iocs.items() if v
            }
        
        return ttps
    
    def extract_context_for_ttp(self, text: str, technique: str, window_size: int = 100) -> str:
        """
        Extract surrounding context for a TTP
        Tìm sentences/passages chứa technique name
        """
        sentences = re.split(r'[.!?]+', text)
        relevant_sentences = []
        
        technique_lower = technique.lower()
        
        for sentence in sentences:
            if technique_lower in sentence.lower():
                relevant_sentences.append(sentence.strip())
        
        # If not found directly, look for related keywords
        if not relevant_sentences:
            keywords = technique_lower.split()
            for sentence in sentences:
                sentence_lower = sentence.lower()
                if sum(1 for kw in keywords if kw in sentence_lower) >= len(keywords) - 1:
                    relevant_sentences.append(sentence.strip())
        
        # Limit context
        context = ' '.join(relevant_sentences[:3])
        
        if len(context) > window_size:
            context = context[:window_size] + "..."
        
        return context if context else f"Detected {technique}"
    
    def get_tool_extraction_confidence(self, tool: str, frequency: int, text_length: int) -> float:
        """
        Calculate confidence for tool extraction
        Based on: occurrence frequency, tool prominence, text length
        """
        # Base confidence
        base = 0.5
        
        # Frequency bonus (max 0.2)
        freq_bonus = min(frequency / 5 * 0.2, 0.2)
        
        # Text length factor (longer text = more confident)
        text_factor = min(text_length / 1000, 1.0) * 0.1
        
        # Tool prominence (some tools more common than others)
        high_prominence = {'mimikatz', 'powershell', 'cmd', 'psexec', 'metasploit'}
        prominence_bonus = 0.1 if tool.lower() in high_prominence else 0.05
        
        confidence = min(base + freq_bonus + text_factor + prominence_bonus, 1.0)
        return round(confidence, 3)


def get_tools_and_indicators_extractor() -> ToolsAndIndicatorsExtractor:
    """Factory function"""
    return ToolsAndIndicatorsExtractor()
