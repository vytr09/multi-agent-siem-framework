# agents/rulegen/sigma/converter.py

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)


class SigmaConverter:
    """
    Converts TTP data into Sigma rule format (universal detection rule format)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.default_level = config.get('default_level', 'medium')
        self.default_status = config.get('default_status', 'experimental')
        
        # Mapping MITRE ATT&CK tactics to Sigma tags
        self.tactic_mapping = {
            'initial_access': 'attack.initial_access',
            'execution': 'attack.execution',
            'persistence': 'attack.persistence',
            'privilege_escalation': 'attack.privilege_escalation',
            'defense_evasion': 'attack.defense_evasion',
            'credential_access': 'attack.credential_access',
            'discovery': 'attack.discovery',
            'lateral_movement': 'attack.lateral_movement',
            'collection': 'attack.collection',
            'command_and_control': 'attack.command_and_control',
            'exfiltration': 'attack.exfiltration',
            'impact': 'attack.impact'
        }
        
        logger.info("SigmaConverter initialized")
    
    async def initialize(self) -> None:
        """Initialize the converter"""
        logger.info("SigmaConverter initialization complete")
    
    async def convert_ttp_to_sigma(
        self,
        ttp_id: str,
        technique_id: str,
        technique_name: str,
        indicators: List[Dict[str, Any]],
        detection_logic: Dict[str, Any],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert TTP data to Sigma rule format
        
        Args:
            ttp_id: Unique TTP identifier
            technique_id: MITRE ATT&CK technique ID (e.g., T1059.001)
            technique_name: Human-readable technique name
            indicators: List of detection indicators
            detection_logic: Detection logic configuration
            metadata: Additional metadata about the TTP
            
        Returns:
            Sigma rule dictionary
        """
        logger.debug(f"Converting TTP {ttp_id} to Sigma rule")
        
        # Build detection section
        detection = self._build_detection(indicators, detection_logic)
        
        # Build tags
        tags = self._build_tags(technique_id, metadata)
        
        # Determine rule level based on confidence and context
        level = self._determine_level(metadata)
        
        # Build Sigma rule structure
        sigma_rule = {
            'title': f"{technique_name} Detection",
            'id': str(uuid.uuid4()),
            'status': self.default_status,
            'description': detection_logic.get('description', f"Detects {technique_name} activity"),
            'references': self._build_references(technique_id, metadata),
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'modified': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': tags,
            'logsource': self._determine_logsource(indicators),
            'detection': detection,
            'falsepositives': self._generate_false_positives(technique_name, metadata),
            'level': level,
            'metadata': {
                'ttp_id': ttp_id,
                'technique_id': technique_id,
                'confidence': metadata.get('confidence', 0.7),
                'extraction_method': metadata.get('extraction_method'),
                'threat_actor': metadata.get('threat_actor'),
                'malware': metadata.get('malware', []),
                'tools': metadata.get('tools', []),
                'campaign': metadata.get('campaign')
            }
        }
        
        logger.debug(f"Generated Sigma rule: {sigma_rule['title']}")
        
        return sigma_rule
    
    def _build_detection(
        self, 
        indicators: List[Dict[str, Any]], 
        detection_logic: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the detection section of Sigma rule"""
        detection = {}
        
        # Group indicators by type
        indicators_by_type = {}
        for indicator in indicators:
            ind_type = indicator.get('type', 'generic')
            if ind_type not in indicators_by_type:
                indicators_by_type[ind_type] = []
            indicators_by_type[ind_type].append(indicator['value'])
        
        # Build selection conditions
        selection = {}
        
        if 'process_image' in indicators_by_type:
            selection['Image|endswith'] = indicators_by_type['process_image']
        
        if 'process_commandline' in indicators_by_type:
            selection['CommandLine|contains'] = indicators_by_type['process_commandline']
        
        if 'registry_key' in indicators_by_type:
            selection['TargetObject|contains'] = indicators_by_type['registry_key']
        
        if 'file_path' in indicators_by_type:
            selection['TargetFilename|contains'] = indicators_by_type['file_path']
        
        if 'ip_address' in indicators_by_type:
            selection['DestinationIp'] = indicators_by_type['ip_address']
        
        if 'domain' in indicators_by_type:
            selection['DestinationHostname|endswith'] = indicators_by_type['domain']
        
        # Add generic indicators
        if 'generic' in indicators_by_type or 'tool' in indicators_by_type:
            generic_values = indicators_by_type.get('generic', []) + indicators_by_type.get('tool', [])
            if generic_values:
                selection['CommandLine|contains'] = generic_values
        
        detection['selection'] = selection
        
        # Build condition
        logic = detection_logic.get('logic', 'and')
        if logic == 'and':
            detection['condition'] = 'selection'
        else:
            detection['condition'] = 'selection'
        
        return detection
    
    def _build_tags(self, technique_id: str, metadata: Dict[str, Any]) -> List[str]:
        """Build Sigma tags from technique and metadata"""
        tags = []
        
        # Add MITRE ATT&CK tag
        tags.append(f'attack.{technique_id.lower()}')
        
        # Add tactic tag
        tactic = metadata.get('tactic', '').lower().replace(' ', '_')
        if tactic in self.tactic_mapping:
            tags.append(self.tactic_mapping[tactic])
        
        # Add threat actor tag if available
        threat_actor = metadata.get('threat_actor')
        if threat_actor:
            actor_tag = threat_actor.lower().replace(' ', '_')
            tags.append(f'threat_actor.{actor_tag}')
        
        return tags
    
    def _build_references(self, technique_id: str, metadata: Dict[str, Any]) -> List[str]:
        """Build reference URLs"""
        references = [
            f'https://attack.mitre.org/techniques/{technique_id}/'
        ]
        
        # Add campaign reference if available
        campaign = metadata.get('campaign')
        if campaign:
            references.append(f'Campaign: {campaign}')
        
        return references
    
    def _determine_logsource(self, indicators: List[Dict[str, Any]]) -> Dict[str, str]:
        """Determine appropriate log source based on indicators"""
        indicator_types = {ind.get('type') for ind in indicators}
        
        # Process-based detection
        if any(t in indicator_types for t in ['process_image', 'process_commandline']):
            return {
                'category': 'process_creation',
                'product': 'windows'
            }
        
        # Registry-based detection
        if 'registry_key' in indicator_types:
            return {
                'category': 'registry_event',
                'product': 'windows'
            }
        
        # Network-based detection
        if any(t in indicator_types for t in ['ip_address', 'domain']):
            return {
                'category': 'network_connection',
                'product': 'windows'
            }
        
        # File-based detection
        if 'file_path' in indicator_types:
            return {
                'category': 'file_event',
                'product': 'windows'
            }
        
        # Default
        return {
            'category': 'process_creation',
            'product': 'windows'
        }
    
    def _generate_false_positives(self, technique_name: str, metadata: Dict[str, Any]) -> List[str]:
        """Generate potential false positive scenarios"""
        false_positives = ['Legitimate administrative activity']
        
        if 'powershell' in technique_name.lower():
            false_positives.append('Legitimate PowerShell scripts')
            false_positives.append('Automated deployment tools')
        
        if 'credential' in technique_name.lower():
            false_positives.append('Password management tools')
            false_positives.append('Security scanning tools')
        
        if 'registry' in technique_name.lower():
            false_positives.append('Software installation and updates')
        
        return false_positives
    
    def _determine_level(self, metadata: Dict[str, Any]) -> str:
        """Determine rule severity level based on metadata"""
        confidence = metadata.get('confidence', 0.7)
        
        # High confidence and threat actor involvement = critical
        if confidence >= 0.9 and metadata.get('threat_actor'):
            return 'critical'
        
        # High confidence = high
        if confidence >= 0.8:
            return 'high'
        
        # Medium confidence = medium
        if confidence >= 0.6:
            return 'medium'
        
        # Low confidence = low
        return 'low'
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("SigmaConverter shutdown complete")