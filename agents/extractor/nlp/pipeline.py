"""
NLP Pipeline for CTI Report Processing

Pre-processes CTI reports before LLM extraction to:
- Extract technical entities (files, IPs, domains, registry keys)
- Identify security-specific patterns
- Structure unstructured text
- Reduce LLM processing load
"""

import re
from typing import Dict, Any, List, Set, Tuple
from dataclasses import dataclass


@dataclass
class ProcessedText:
    """Processed text with extracted entities"""
    original_text: str
    cleaned_text: str
    sentences: List[str]
    technical_terms: List[str]
    file_paths: List[str]
    registry_keys: List[str]
    commands: List[str]
    network_artifacts: List[str]
    security_keywords: List[str]


class NLPPipeline:
    """
    NLP pipeline for CTI report processing.
    
    Uses regex patterns and rule-based extraction for
    cybersecurity-specific entities and patterns.
    """
    
    def __init__(self):
        # Compile regex patterns for performance
        self._compile_patterns()
        
        # Security-specific keywords
        self.security_keywords = {
            # Actions
            'execute', 'download', 'upload', 'exfiltrate', 'dump', 'harvest',
            'inject', 'encrypt', 'decrypt', 'compress', 'extract', 'modify',
            'create', 'delete', 'establish', 'terminate', 'escalate',
            
            # Techniques
            'persistence', 'privilege', 'evasion', 'credential', 'lateral',
            'reconnaissance', 'weaponization', 'exploitation', 'installation',
            'command-and-control', 'c2', 'backdoor', 'rootkit', 'keylogger',
            
            # Tools
            'powershell', 'cmd', 'wmi', 'mimikatz', 'psexec', 'cobalt',
            'metasploit', 'empire', 'beacon', 'payload', 'dropper', 'loader',
            
            # Artifacts
            'registry', 'process', 'service', 'task', 'dll', 'executable',
            'macro', 'script', 'shellcode', 'malware', 'trojan', 'ransomware'
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for entity extraction"""
        
        # File paths (Windows & Linux)
        self.file_path_pattern = re.compile(
            r'(?:'
            r'[A-Z]:\\(?:[^\s\\/:*?"<>|\r\n]+\\)*[^\s\\/:*?"<>|\r\n]*|'  # Windows
            r'/(?:[^\s/]+/)*[^\s/]*'  # Linux
            r')',
            re.IGNORECASE
        )
        
        # Registry keys
        self.registry_pattern = re.compile(
            r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\n]+',
            re.IGNORECASE
        )
        
        # Command patterns
        self.command_pattern = re.compile(
            r'(?:'
            r'powershell(?:\.exe)?\s+(?:-\w+\s+)*[^\n]+|'
            r'cmd(?:\.exe)?\s+/[a-z]\s+[^\n]+|'
            r'wmic\s+[^\n]+|'
            r'net\s+(?:user|group|localgroup|share|use)\s+[^\n]+|'
            r'reg\s+(?:add|delete|query)\s+[^\n]+|'
            r'schtasks\s+[^\n]+|'
            r'sc\s+(?:create|start|stop|delete)\s+[^\n]+'
            r')',
            re.IGNORECASE
        )
        
        # Network artifacts (IPs, domains, URLs)
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.domain_pattern = re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        )
        
        self.url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        # Technical file extensions
        self.executable_extensions = {
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.msi', '.scr', '.com', '.pif', '.cpl'
        }
        
        # ATT&CK technique patterns
        self.attack_pattern = re.compile(r'T\d{4}(?:\.\d{3})?')
    
    def process(self, text: str) -> ProcessedText:
        """
        Process CTI report text through NLP pipeline.
        
        Args:
            text: Raw CTI report text
            
        Returns:
            ProcessedText with extracted entities
        """
        # Clean and normalize text
        cleaned = self._clean_text(text)
        
        # Split into sentences
        sentences = self._split_sentences(cleaned)
        
        # Extract entities
        file_paths = self._extract_file_paths(text)
        registry_keys = self._extract_registry_keys(text)
        commands = self._extract_commands(text)
        network_artifacts = self._extract_network_artifacts(text)
        
        # Extract technical terms
        technical_terms = self._extract_technical_terms(text)
        
        # Extract security keywords
        security_keywords = self._extract_security_keywords(text)
        
        return ProcessedText(
            original_text=text,
            cleaned_text=cleaned,
            sentences=sentences,
            technical_terms=technical_terms,
            file_paths=file_paths,
            registry_keys=registry_keys,
            commands=commands,
            network_artifacts=network_artifacts,
            security_keywords=security_keywords
        )
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep technical ones
        text = re.sub(r'[^\w\s\-_.:\\/@\[\]{}()$]', ' ', text)
        
        # Normalize line breaks
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        
        return text.strip()
    
    def _split_sentences(self, text: str) -> List[str]:
        """Split text into sentences"""
        # Simple sentence splitting (can use nltk.sent_tokenize for better results)
        sentences = re.split(r'[.!?]\s+', text)
        return [s.strip() for s in sentences if s.strip()]
    
    def _extract_file_paths(self, text: str) -> List[str]:
        """Extract file paths"""
        paths = self.file_path_pattern.findall(text)
        
        # Filter valid paths
        valid_paths = []
        for path in paths:
            # Must have extension or be directory
            if ('.' in path and len(path) > 3) or path.endswith('\\') or path.endswith('/'):
                valid_paths.append(path)
        
        return list(set(valid_paths))
    
    def _extract_registry_keys(self, text: str) -> List[str]:
        """Extract Windows registry keys"""
        keys = self.registry_pattern.findall(text)
        return list(set(keys))
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extract command-line commands"""
        commands = self.command_pattern.findall(text)
        return list(set(commands))
    
    def _extract_network_artifacts(self, text: str) -> List[str]:
        """Extract network artifacts (IPs, domains, URLs)"""
        artifacts = []
        
        # Extract IPs
        ips = self.ip_pattern.findall(text)
        artifacts.extend(ips)
        
        # Extract domains
        domains = self.domain_pattern.findall(text)
        # Filter out common words that match domain pattern
        domains = [d for d in domains if '.' in d and not d.startswith('.')]
        artifacts.extend(domains)
        
        # Extract URLs
        urls = self.url_pattern.findall(text)
        artifacts.extend(urls)
        
        return list(set(artifacts))
    
    def _extract_technical_terms(self, text: str) -> List[str]:
        """Extract technical terms and identifiers"""
        technical_terms = []
        
        # Extract ATT&CK technique IDs
        attack_ids = self.attack_pattern.findall(text)
        technical_terms.extend(attack_ids)
        
        # Extract hash-like strings (MD5, SHA1, SHA256)
        hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        hashes = hash_pattern.findall(text)
        technical_terms.extend(hashes)
        
        # Extract CVE IDs
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
        cves = cve_pattern.findall(text)
        technical_terms.extend(cves)
        
        # Extract process names
        process_pattern = re.compile(r'\b\w+\.exe\b', re.IGNORECASE)
        processes = process_pattern.findall(text)
        technical_terms.extend(processes)
        
        return list(set(technical_terms))
    
    def _extract_security_keywords(self, text: str) -> List[str]:
        """Extract security-specific keywords"""
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.security_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def extract_ttp_indicators(self, text: str) -> Dict[str, List[str]]:
        """
        Extract potential TTP indicators from text.
        
        Returns dictionary of TTP categories with their indicators.
        """
        indicators = {
            'initial_access': [],
            'execution': [],
            'persistence': [],
            'privilege_escalation': [],
            'defense_evasion': [],
            'credential_access': [],
            'discovery': [],
            'lateral_movement': [],
            'collection': [],
            'exfiltration': [],
            'command_and_control': []
        }
        
        text_lower = text.lower()
        
        # Initial Access indicators
        if any(word in text_lower for word in ['phishing', 'spearphishing', 'email', 'attachment']):
            indicators['initial_access'].append('Phishing')
        
        if any(word in text_lower for word in ['exploit', 'vulnerability', 'cve']):
            indicators['initial_access'].append('Exploit Public-Facing Application')
        
        # Execution indicators
        if 'powershell' in text_lower:
            indicators['execution'].append('PowerShell')
        
        if any(word in text_lower for word in ['cmd', 'command prompt', 'cmd.exe']):
            indicators['execution'].append('Command and Scripting Interpreter')
        
        if any(word in text_lower for word in ['wmi', 'windows management']):
            indicators['execution'].append('Windows Management Instrumentation')
        
        if any(word in text_lower for word in ['macro', 'vba', 'office']):
            indicators['execution'].append('User Execution: Malicious File')
        
        # Persistence indicators
        if 'registry' in text_lower:
            indicators['persistence'].append('Registry Run Keys')
        
        if any(word in text_lower for word in ['scheduled task', 'schtasks', 'cron']):
            indicators['persistence'].append('Scheduled Task/Job')
        
        if any(word in text_lower for word in ['service', 'sc create']):
            indicators['persistence'].append('Create or Modify System Process')
        
        # Credential Access indicators
        if any(word in text_lower for word in ['mimikatz', 'lsass', 'credential dump']):
            indicators['credential_access'].append('OS Credential Dumping')
        
        if any(word in text_lower for word in ['keylogger', 'keystroke']):
            indicators['credential_access'].append('Input Capture')
        
        # Defense Evasion indicators
        if any(word in text_lower for word in ['obfuscate', 'encode', 'base64']):
            indicators['defense_evasion'].append('Obfuscated Files or Information')
        
        if any(word in text_lower for word in ['inject', 'process injection']):
            indicators['defense_evasion'].append('Process Injection')
        
        # Discovery indicators
        if any(word in text_lower for word in ['network scan', 'port scan', 'reconnaissance']):
            indicators['discovery'].append('Network Service Discovery')
        
        if any(word in text_lower for word in ['enumerate', 'list users', 'net user']):
            indicators['discovery'].append('Account Discovery')
        
        # Lateral Movement indicators
        if any(word in text_lower for word in ['rdp', 'remote desktop']):
            indicators['lateral_movement'].append('Remote Desktop Protocol')
        
        if any(word in text_lower for word in ['psexec', 'admin share', 'smb']):
            indicators['lateral_movement'].append('Remote Services')
        
        # Collection indicators
        if any(word in text_lower for word in ['archive', 'compress', 'zip', 'rar']):
            indicators['collection'].append('Archive Collected Data')
        
        if any(word in text_lower for word in ['screenshot', 'screen capture']):
            indicators['collection'].append('Screen Capture')
        
        # Exfiltration indicators
        if any(word in text_lower for word in ['exfiltrate', 'upload', 'transfer']):
            indicators['exfiltration'].append('Exfiltration Over C2 Channel')
        
        # C2 indicators
        if any(word in text_lower for word in ['c2', 'command and control', 'beacon']):
            indicators['command_and_control'].append('Application Layer Protocol')
        
        # Filter out empty categories
        return {k: v for k, v in indicators.items() if v}
    
    def enhance_llm_prompt(self, processed_text: ProcessedText) -> str:
        """
        Create enhanced context for LLM prompt using NLP extraction.
        
        Args:
            processed_text: Processed text with entities
            
        Returns:
            Enhanced context string
        """
        context_parts = []
        
        # Add extracted commands
        if processed_text.commands:
            context_parts.append("**Observed Commands:**")
            for cmd in processed_text.commands[:5]:
                context_parts.append(f"- {cmd}")
        
        # Add file paths
        if processed_text.file_paths:
            context_parts.append("\n**File System Activity:**")
            for path in processed_text.file_paths[:5]:
                context_parts.append(f"- {path}")
        
        # Add registry keys
        if processed_text.registry_keys:
            context_parts.append("\n**Registry Modifications:**")
            for key in processed_text.registry_keys[:5]:
                context_parts.append(f"- {key}")
        
        # Add network artifacts
        if processed_text.network_artifacts:
            context_parts.append("\n**Network Indicators:**")
            for artifact in processed_text.network_artifacts[:10]:
                context_parts.append(f"- {artifact}")
        
        # Add security keywords
        if processed_text.security_keywords:
            top_keywords = processed_text.security_keywords[:10]
            context_parts.append(f"\n**Key Security Terms:** {', '.join(top_keywords)}")
        
        return "\n".join(context_parts)
    
    def get_statistics(self, processed_text: ProcessedText) -> Dict[str, Any]:
        """Get statistics about processed text"""
        return {
            "text_length": len(processed_text.original_text),
            "sentence_count": len(processed_text.sentences),
            "file_paths_found": len(processed_text.file_paths),
            "registry_keys_found": len(processed_text.registry_keys),
            "commands_found": len(processed_text.commands),
            "network_artifacts_found": len(processed_text.network_artifacts),
            "technical_terms_found": len(processed_text.technical_terms),
            "security_keywords_found": len(processed_text.security_keywords)
        }