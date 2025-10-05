"""
Entity Extractor for CTI Reports

Extracts structured entities from unstructured CTI text:
- Malware families
- Tools and utilities
- Attack techniques
- Threat actors
- Indicators of Compromise (IOCs)
"""

import re
from typing import Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class ExtractedEntities:
    """Container for extracted entities"""
    malware_families: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    file_hashes: Dict[str, List[str]] = field(default_factory=dict)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    file_names: List[str] = field(default_factory=list)
    cvss_scores: List[Tuple[str, float]] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)


class EntityExtractor:
    """
    Extract cybersecurity entities from CTI reports.
    
    Uses pattern matching and known entity lists to identify
    and extract structured information from unstructured text.
    """
    
    def __init__(self):
        self._initialize_entity_databases()
        self._compile_patterns()
    
    def _initialize_entity_databases(self):
        """Initialize databases of known entities"""
        
        # Known malware families (expand as needed)
        self.known_malware = {
            'emotet', 'trickbot', 'ryuk', 'maze', 'revil', 'sodinokibi',
            'conti', 'lockbit', 'wannacry', 'notpetya', 'petya', 'locky',
            'cryptolocker', 'ransomware', 'trojan', 'backdoor', 'rootkit',
            'mimikatz', 'cobalt strike', 'beacon', 'metasploit', 'empire',
            'powershell empire', 'bloodhound', 'sharphound', 'lazagne',
            'procdump', 'credential dumper', 'keylogger', 'banking trojan',
            'rat', 'remote access trojan', 'apt', 'malware', 'payload',
            'dropper', 'loader', 'downloader', 'stager', 'implant'
        }
        
        # Known security tools (legitimate and malicious)
        self.known_tools = {
            'powershell', 'cmd', 'wmi', 'psexec', 'wmic', 'net', 'netsh',
            'reg', 'regedit', 'sc', 'schtasks', 'at', 'certutil', 'bitsadmin',
            'rundll32', 'regsvr32', 'mshta', 'cscript', 'wscript',
            'tasklist', 'taskkill', 'whoami', 'systeminfo', 'ipconfig',
            'nslookup', 'ping', 'tracert', 'arp', 'netstat',
            'mimikatz', 'cobalt strike', 'metasploit', 'burp suite',
            'nmap', 'masscan', 'wireshark', 'tcpdump', 'john the ripper',
            'hashcat', 'hydra', 'sqlmap', 'nikto', 'dirb'
        }
        
        # Known threat actors/groups (expand as needed)
        self.known_threat_actors = {
            'apt1', 'apt28', 'apt29', 'apt32', 'apt33', 'apt34', 'apt38', 'apt40',
            'fancy bear', 'cozy bear', 'lazarus group', 'equation group',
            'shadow brokers', 'carbanak', 'fin6', 'fin7', 'fin8',
            'turla', 'sandworm', 'dragonfly', 'energetic bear',
            'ocean lotus', 'putter panda', 'comment crew', 'deep panda'
        }
        
        # ATT&CK tactic keywords
        self.tactic_keywords = {
            'reconnaissance': ['recon', 'reconnaissance', 'scan', 'enumerate', 'discover'],
            'resource_development': ['acquire', 'compromise', 'develop', 'establish', 'obtain', 'stage'],
            'initial_access': ['phishing', 'exploit', 'spearphishing', 'drive-by', 'supply chain'],
            'execution': ['execute', 'run', 'launch', 'invoke', 'trigger', 'command'],
            'persistence': ['persist', 'registry', 'scheduled task', 'startup', 'service', 'autorun'],
            'privilege_escalation': ['escalate', 'elevate', 'bypass uac', 'token', 'exploit'],
            'defense_evasion': ['evade', 'obfuscate', 'hide', 'masquerade', 'disable', 'impair'],
            'credential_access': ['credential', 'password', 'dump', 'hash', 'lsass', 'keylog'],
            'discovery': ['discover', 'enumerate', 'query', 'list', 'account', 'network', 'system info'],
            'lateral_movement': ['lateral', 'move', 'rdp', 'remote', 'smb', 'wmi', 'psexec'],
            'collection': ['collect', 'gather', 'archive', 'compress', 'screenshot', 'keylog'],
            'command_and_control': ['c2', 'command and control', 'beacon', 'callback', 'exfiltrate'],
            'exfiltration': ['exfiltrate', 'steal', 'upload', 'transfer', 'send', 'transmit'],
            'impact': ['encrypt', 'destroy', 'delete', 'wipe', 'ransom', 'defacement', 'dos']
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for entity extraction"""
        
        # File hashes
        self.hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
        
        # Network indicators
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.domain_pattern = re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        )
        
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        self.url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        # ATT&CK technique IDs
        self.attack_id_pattern = re.compile(r'T\d{4}(?:\.\d{3})?')
        
        # CVE IDs
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
        
        # Port numbers
        self.port_pattern = re.compile(r'\bport\s+(\d{1,5})\b', re.IGNORECASE)
        
        # File names with suspicious extensions
        self.suspicious_file_pattern = re.compile(
            r'\b[\w\-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|msi|scr|com|pif|cpl)\b',
            re.IGNORECASE
        )
    
    def extract(self, text: str) -> ExtractedEntities:
        """
        Extract all entities from text.
        
        Args:
            text: CTI report text
            
        Returns:
            ExtractedEntities with all found entities
        """
        entities = ExtractedEntities()
        
        text_lower = text.lower()
        
        # Extract malware families
        entities.malware_families = self._extract_malware(text, text_lower)
        
        # Extract tools
        entities.tools = self._extract_tools(text, text_lower)
        
        # Extract threat actors
        entities.threat_actors = self._extract_threat_actors(text, text_lower)
        
        # Extract attack techniques
        entities.attack_techniques = self._extract_attack_techniques(text)
        
        # Extract IOCs
        entities.file_hashes = self._extract_hashes(text)
        entities.ip_addresses = self._extract_ips(text)
        entities.domains = self._extract_domains(text)
        entities.email_addresses = self._extract_emails(text)
        entities.urls = self._extract_urls(text)
        entities.file_names = self._extract_file_names(text)
        entities.ports = self._extract_ports(text)
        
        return entities
    
    def _extract_malware(self, text: str, text_lower: str) -> List[str]:
        """Extract malware family names"""
        found_malware = set()
        
        for malware in self.known_malware:
            if malware in text_lower:
                # Extract the actual case from original text
                pattern = re.compile(re.escape(malware), re.IGNORECASE)
                matches = pattern.findall(text)
                if matches:
                    found_malware.add(matches[0])
        
        return sorted(list(found_malware))
    
    def _extract_tools(self, text: str, text_lower: str) -> List[str]:
        """Extract tool names"""
        found_tools = set()
        
        for tool in self.known_tools:
            if tool in text_lower:
                pattern = re.compile(re.escape(tool), re.IGNORECASE)
                matches = pattern.findall(text)
                if matches:
                    found_tools.add(matches[0])
        
        return sorted(list(found_tools))
    
    def _extract_threat_actors(self, text: str, text_lower: str) -> List[str]:
        """Extract threat actor names"""
        found_actors = set()
        
        for actor in self.known_threat_actors:
            if actor in text_lower:
                pattern = re.compile(re.escape(actor), re.IGNORECASE)
                matches = pattern.findall(text)
                if matches:
                    found_actors.add(matches[0])
        
        # Also look for APT\d+ pattern
        apt_pattern = re.compile(r'\bAPT\d+\b', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        found_actors.update(apt_matches)
        
        return sorted(list(found_actors))
    
    def _extract_attack_techniques(self, text: str) -> List[str]:
        """Extract ATT&CK technique IDs"""
        technique_ids = self.attack_id_pattern.findall(text)
        return sorted(list(set(technique_ids)))
    
    def _extract_hashes(self, text: str) -> Dict[str, List[str]]:
        """Extract file hashes by type"""
        hashes = {}
        
        for hash_type, pattern in self.hash_patterns.items():
            found = pattern.findall(text)
            if found:
                hashes[hash_type] = sorted(list(set(found)))
        
        return hashes
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses"""
        ips = self.ip_pattern.findall(text)
        # Filter out invalid IPs (like version numbers)
        valid_ips = []
        for ip in ips:
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                valid_ips.append(ip)
        
        return sorted(list(set(valid_ips)))
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names"""
        domains = self.domain_pattern.findall(text)
        
        # Filter out common false positives
        excluded = {'example.com', 'test.com', 'localhost', 'sample.com'}
        valid_domains = [d for d in domains if d.lower() not in excluded and len(d) > 3]
        
        return sorted(list(set(valid_domains)))
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses"""
        emails = self.email_pattern.findall(text)
        return sorted(list(set(emails)))
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs"""
        urls = self.url_pattern.findall(text)
        return sorted(list(set(urls)))
    
    def _extract_file_names(self, text: str) -> List[str]:
        """Extract suspicious file names"""
        files = self.suspicious_file_pattern.findall(text)
        return sorted(list(set(files)))
    
    def _extract_ports(self, text: str) -> List[int]:
        """Extract port numbers"""
        ports = self.port_pattern.findall(text)
        valid_ports = [int(p) for p in ports if 0 < int(p) < 65536]
        return sorted(list(set(valid_ports)))
    
    def identify_tactics(self, text: str) -> Dict[str, List[str]]:
        """
        Identify MITRE ATT&CK tactics present in text.
        
        Args:
            text: CTI report text
            
        Returns:
            Dictionary mapping tactics to matched keywords
        """
        text_lower = text.lower()
        identified_tactics = {}
        
        for tactic, keywords in self.tactic_keywords.items():
            matches = []
            for keyword in keywords:
                if keyword in text_lower:
                    matches.append(keyword)
            
            if matches:
                identified_tactics[tactic] = matches
        
        return identified_tactics
    
    def extract_ioc_context(self, text: str, entities: ExtractedEntities) -> Dict[str, List[Dict[str, str]]]:
        """
        Extract context around IOCs (surrounding sentences).
        
        Args:
            text: Full text
            entities: Extracted entities
            
        Returns:
            Dictionary mapping IOC to its context
        """
        contexts = {}
        
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)
        
        # For each IOC type, find surrounding context
        all_iocs = []
        
        # Collect all IOCs
        for ip in entities.ip_addresses:
            all_iocs.append(('ip', ip))
        
        for domain in entities.domains:
            all_iocs.append(('domain', domain))
        
        for hash_type, hashes in entities.file_hashes.items():
            for hash_val in hashes:
                all_iocs.append((hash_type, hash_val))
        
        # Find context for each IOC
        for ioc_type, ioc_value in all_iocs:
            ioc_contexts = []
            
            for sentence in sentences:
                if ioc_value in sentence:
                    ioc_contexts.append({
                        'sentence': sentence.strip(),
                        'type': ioc_type
                    })
            
            if ioc_contexts:
                contexts[ioc_value] = ioc_contexts
        
        return contexts
    
    def correlate_entities(self, entities: ExtractedEntities) -> Dict[str, Any]:
        """
        Correlate extracted entities to find relationships.
        
        Args:
            entities: Extracted entities
            
        Returns:
            Correlation analysis
        """
        correlations = {
            'threat_intel_summary': {},
            'relationships': [],
            'attack_surface': {}
        }
        
        # Threat intelligence summary
        correlations['threat_intel_summary'] = {
            'total_iocs': (
                len(entities.ip_addresses) +
                len(entities.domains) +
                sum(len(h) for h in entities.file_hashes.values())
            ),
            'threat_actor_count': len(entities.threat_actors),
            'malware_family_count': len(entities.malware_families),
            'tool_count': len(entities.tools),
            'technique_count': len(entities.attack_techniques)
        }
        
        # Identify relationships
        if entities.threat_actors and entities.malware_families:
            for actor in entities.threat_actors:
                for malware in entities.malware_families:
                    correlations['relationships'].append({
                        'type': 'actor_uses_malware',
                        'actor': actor,
                        'malware': malware
                    })
        
        if entities.malware_families and entities.tools:
            for malware in entities.malware_families:
                for tool in entities.tools:
                    correlations['relationships'].append({
                        'type': 'malware_uses_tool',
                        'malware': malware,
                        'tool': tool
                    })
        
        # Attack surface analysis
        correlations['attack_surface'] = {
            'network_exposure': len(entities.ip_addresses) + len(entities.domains),
            'file_based_indicators': len(entities.file_names) + sum(len(h) for h in entities.file_hashes.values()),
            'communication_channels': len(entities.urls) + len(entities.email_addresses),
            'open_ports': len(entities.ports)
        }
        
        return correlations
    
    def enrich_with_context(
        self, 
        entities: ExtractedEntities, 
        text: str
    ) -> Dict[str, Any]:
        """
        Enrich entities with contextual information.
        
        Args:
            entities: Extracted entities
            text: Original text
            
        Returns:
            Enriched entity information
        """
        enriched = {
            'entities': entities,
            'tactics_identified': self.identify_tactics(text),
            'ioc_contexts': self.extract_ioc_context(text, entities),
            'correlations': self.correlate_entities(entities),
            'statistics': {
                'malware_count': len(entities.malware_families),
                'tool_count': len(entities.tools),
                'threat_actor_count': len(entities.threat_actors),
                'technique_count': len(entities.attack_techniques),
                'ioc_count': (
                    len(entities.ip_addresses) +
                    len(entities.domains) +
                    len(entities.urls) +
                    len(entities.email_addresses) +
                    sum(len(h) for h in entities.file_hashes.values())
                )
            }
        }
        
        return enriched
    
    def create_entity_summary(self, entities: ExtractedEntities) -> str:
        """
        Create human-readable summary of extracted entities.
        
        Args:
            entities: Extracted entities
            
        Returns:
            Summary string
        """
        summary_parts = []
        
        if entities.threat_actors:
            summary_parts.append(f"Threat Actors: {', '.join(entities.threat_actors[:5])}")
        
        if entities.malware_families:
            summary_parts.append(f"Malware: {', '.join(entities.malware_families[:5])}")
        
        if entities.tools:
            summary_parts.append(f"Tools: {', '.join(entities.tools[:5])}")
        
        if entities.attack_techniques:
            summary_parts.append(f"Techniques: {', '.join(entities.attack_techniques[:5])}")
        
        # IOC summary
        ioc_count = (
            len(entities.ip_addresses) +
            len(entities.domains) +
            sum(len(h) for h in entities.file_hashes.values())
        )
        summary_parts.append(f"Total IOCs: {ioc_count}")
        
        return " | ".join(summary_parts)
    
    def filter_high_confidence_iocs(
        self, 
        entities: ExtractedEntities,
        text: str
    ) -> ExtractedEntities:
        """
        Filter IOCs to keep only high-confidence ones.
        
        Uses context analysis to determine confidence.
        
        Args:
            entities: Extracted entities
            text: Original text for context
            
        Returns:
            Filtered entities with high-confidence IOCs
        """
        filtered = ExtractedEntities()
        
        # Copy non-IOC entities (they're already filtered by known lists)
        filtered.malware_families = entities.malware_families
        filtered.tools = entities.tools
        filtered.threat_actors = entities.threat_actors
        filtered.attack_techniques = entities.attack_techniques
        
        # Filter IPs - keep only those mentioned in security context
        text_lower = text.lower()
        security_contexts = [
            'c2', 'command', 'control', 'server', 'malicious', 
            'attacker', 'threat', 'compromise', 'exfiltrate'
        ]
        
        for ip in entities.ip_addresses:
            # Find context around IP
            ip_index = text.find(ip)
            if ip_index > 0:
                context = text[max(0, ip_index - 100):min(len(text), ip_index + 100)].lower()
                if any(keyword in context for keyword in security_contexts):
                    filtered.ip_addresses.append(ip)
        
        # Similar filtering for domains
        for domain in entities.domains:
            domain_index = text.find(domain)
            if domain_index > 0:
                context = text[max(0, domain_index - 100):min(len(text), domain_index + 100)].lower()
                if any(keyword in context for keyword in security_contexts):
                    filtered.domains.append(domain)
        
        # Copy other IOCs (already high confidence due to patterns)
        filtered.file_hashes = entities.file_hashes
        filtered.urls = entities.urls
        filtered.email_addresses = entities.email_addresses
        filtered.file_names = entities.file_names
        filtered.ports = entities.ports
        
        return filtered