#!/usr/bin/env python3
"""
Advanced ATT&CK ID Validator
Ghi chim, validate va tu dong sua Attack ID
"""

import re
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass


@dataclass
class AttackIdFix:
    """Result cua AT&T CK ID validation va fix"""
    original_id: str
    validated_id: str
    is_valid: bool
    error: str = ""
    confidence: float = 1.0


class AttackIdValidator:
    """Validate va auto-fix ATT&CK IDs"""
    
    # Valid ATT&CK ID patterns
    VALID_PATTERNS = {
        'technique': r'^T\d{4}$',  # T1234
        'subtechnique': r'^T\d{4}\.\d{3}$',  # T1234.001
        'tactic': r'^[a-z-]+$',  # lowercase-with-hyphens
    }
    
    # Known common ATT&CK IDs for fuzzy matching
    COMMON_TECHNIQUES = {
        'T1001': 'Data Obfuscation',
        'T1003': 'OS Credential Dumping',
        'T1007': 'System Service Discovery',
        'T1010': 'Application Window Discovery',
        'T1021': 'Remote Services',
        'T1047': 'Windows Management Instrumentation',
        'T1053': 'Scheduled Task/Job',
        'T1055': 'Process Injection',
        'T1056': 'Input Capture',
        'T1057': 'Process Discovery',
        'T1059': 'Command and Scripting Interpreter',
        'T1071': 'Application Layer Protocol',
        'T1074': 'Data Staged',
        'T1087': 'Account Discovery',
        'T1110': 'Brute Force',
        'T1123': 'Audio Capture',
        'T1136': 'Create Account',
        'T1140': 'Deobfuscate/Decode Files or Information',
        'T1176': 'Browser Extensions',
        'T1185': 'Traffic Signaling',
        'T1187': 'Forced Authentication',
        'T1192': 'Spearphishing Link',
        'T1193': 'Spearphishing Attachment',
        'T1195': 'Supply Chain Compromise',
        'T1199': 'Trusted Relationship',
        'T1204': 'User Execution',
        'T1566': 'Phishing',
        'T1589': 'Gather Victim Identity Information',
        'T1598': 'Phishing for Information',
        'T1600': 'Weaken Encryption',
        'T1134': 'Access Token Manipulation',
        'T1197': 'BITS Jobs',
        'T1547': 'Boot or Logon Autostart Execution',
        'T1037': 'Boot or Logon Initialization Scripts',
        'T1547': 'Boot or Logon Autostart Execution',
        'T1554': 'Compromise Client Software Binary',
        'T1137': 'Office Application Startup',
        'T1547': 'Boot or Logon Autostart Execution',
        'T1547': 'Boot or Logon Autostart Execution',
    }
    
    # Subtechnique mappings
    SUBTECHNIQUES = {
        'T1003.001': 'LSASS Memory',
        'T1003.002': 'SAM Database File',
        'T1003.003': 'NTDS Database File',
        'T1003.004': '/etc/passwd and /etc/shadow',
        'T1003.005': 'Cached Domain Credentials',
        'T1003.006': 'DCSync',
        'T1003.007': 'Proc Filesystem',
        'T1003.008': '/etc/passwd and /etc/shadow',
        'T1059.001': 'PowerShell',
        'T1059.002': 'AppleScript',
        'T1059.003': 'Windows Command Shell',
        'T1059.004': 'Unix Shell',
        'T1059.005': 'Visual Basic',
        'T1059.006': 'Python',
        'T1059.007': 'JavaScript',
        'T1059.008': 'PowerShell',
        'T1021.001': 'Remote Desktop Protocol',
        'T1021.002': 'SSH',
        'T1021.003': 'Distributed Component Object Model',
        'T1021.004': 'SSH',
        'T1021.005': 'VNC',
        'T1021.006': 'Windows Admin Shares',
        'T1071.001': 'Web Protocols',
        'T1071.002': 'File Transfer Protocols',
        'T1071.003': 'Mail Protocols',
        'T1071.004': 'DNS',
        'T1566.001': 'Spearphishing Attachment',
        'T1566.002': 'Spearphishing Link',
        'T1566.003': 'Spearphishing via Service',
    }
    
    def __init__(self):
        """Initialize validator"""
        self.compiled_patterns = {
            k: re.compile(v) for k, v in self.VALID_PATTERNS.items()
        }
    
    def validate_attack_id(self, attack_id: str) -> AttackIdFix:
        """
        Validate single Attack ID
        """
        if not attack_id or not isinstance(attack_id, str):
            return AttackIdFix(
                original_id=str(attack_id),
                validated_id="",
                is_valid=False,
                error="Empty or non-string Attack ID"
            )
        
        attack_id = attack_id.strip().upper()
        
        # Check if it's a valid technique ID
        if self.compiled_patterns['technique'].match(attack_id):
            return AttackIdFix(
                original_id=attack_id,
                validated_id=attack_id,
                is_valid=True
            )
        
        # Check if it's a valid subtechnique ID
        if self.compiled_patterns['subtechnique'].match(attack_id):
            return AttackIdFix(
                original_id=attack_id,
                validated_id=attack_id,
                is_valid=True
            )
        
        # Try to fix common patterns
        fix = self._try_fix_invalid_id(attack_id)
        if fix.is_valid:
            return fix
        
        # Return invalid
        return AttackIdFix(
            original_id=attack_id,
            validated_id="",
            is_valid=False,
            error=f"Invalid format: {attack_id}"
        )
    
    def _try_fix_invalid_id(self, attack_id: str) -> AttackIdFix:
        """
        Try to fix invalid Attack ID with fuzzy matching
        """
        attack_id = attack_id.upper().strip()
        
        # Pattern 1: T1234 with leading zeros removed (e.g., T234 -> T0234)
        match = re.match(r'^T(\d{1,4})$', attack_id)
        if match:
            num = match.group(1)
            if len(num) < 4:
                fixed = f"T{num.zfill(4)}"
                if self._is_known_technique(fixed):
                    return AttackIdFix(
                        original_id=attack_id,
                        validated_id=fixed,
                        is_valid=True,
                        confidence=0.8
                    )
        
        # Pattern 2: Extra dots (e.g., T1234.001.002 -> T1234.001)
        match = re.match(r'^(T\d{4}\.\d{3})\..*$', attack_id)
        if match:
            fixed = match.group(1)
            if self.compiled_patterns['subtechnique'].match(fixed):
                return AttackIdFix(
                    original_id=attack_id,
                    validated_id=fixed,
                    is_valid=True,
                    confidence=0.7
                )
        
        # Pattern 3: Missing leading T (e.g., 1234 -> T1234)
        match = re.match(r'^(\d{4})$', attack_id)
        if match:
            fixed = f"T{match.group(1)}"
            if self._is_known_technique(fixed):
                return AttackIdFix(
                    original_id=attack_id,
                    validated_id=fixed,
                    is_valid=True,
                    confidence=0.7
                )
        
        # Pattern 4: Wrong separators (e.g., T1234-001 -> T1234.001)
        match = re.match(r'^(T\d{4})[-_](0\d{2})$', attack_id)
        if match:
            fixed = f"{match.group(1)}.{match.group(2)}"
            if self.compiled_patterns['subtechnique'].match(fixed):
                return AttackIdFix(
                    original_id=attack_id,
                    validated_id=fixed,
                    is_valid=True,
                    confidence=0.8
                )
        
        # Pattern 5: Extra spaces or special chars
        cleaned = re.sub(r'[_\s]', '', attack_id)
        if cleaned != attack_id:
            fix = self.validate_attack_id(cleaned)
            if fix.is_valid:
                return AttackIdFix(
                    original_id=attack_id,
                    validated_id=fix.validated_id,
                    is_valid=True,
                    confidence=0.7
                )
        
        return AttackIdFix(
            original_id=attack_id,
            validated_id="",
            is_valid=False,
            error="Could not fix invalid ID"
        )
    
    def _is_known_technique(self, attack_id: str) -> bool:
        """Check if technique ID is in known list"""
        return attack_id in self.COMMON_TECHNIQUES or attack_id in self.SUBTECHNIQUES
    
    def validate_batch(self, attack_ids: List[str]) -> Dict[str, AttackIdFix]:
        """
        Validate multiple Attack IDs
        """
        results = {}
        for attack_id in attack_ids:
            results[attack_id] = self.validate_attack_id(attack_id)
        return results
    
    def get_fixed_ids(self, fixes: Dict[str, AttackIdFix]) -> List[str]:
        """Extract fixed IDs from validation results"""
        return [
            fix.validated_id
            for fix in fixes.values()
            if fix.is_valid and fix.validated_id
        ]
    
    def get_invalid_ids(self, fixes: Dict[str, AttackIdFix]) -> List[Tuple[str, str]]:
        """Extract invalid IDs with errors"""
        return [
            (fix.original_id, fix.error)
            for fix in fixes.values()
            if not fix.is_valid
        ]
