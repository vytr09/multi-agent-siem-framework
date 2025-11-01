# agents/attackgen/mitre/attack_mapper.py
"""
MITRE ATT&CK Integration for AttackGen Agent.
Maps TTPs to techniques and provides attack framework context.
"""

import json
import asyncio
import aiohttp
from typing import Dict, Any, List, Optional
from pathlib import Path

from agents.attackgen.exceptions import AttackGenException


class AttackMapper:
    """
    MITRE ATT&CK framework integration for attack command generation.
    """
    
    def __init__(self):
        self.techniques = {}
        self.tactics = {}
        self.software = {}
        self.groups = {}
        self.relationships = {}
        
        # Data sources
        self.mitre_data_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.local_data_path = Path("data/mitre_attack")
        
        self._loaded = False
    
    async def load_attack_data(self) -> None:
        """Load MITRE ATT&CK data from local files or download"""
        try:
            # Try loading from local files first
            if await self._load_local_data():
                self._loaded = True
                return
            
            # Download and cache data if local files not available
            await self._download_and_cache_data()
            self._loaded = True
            
        except Exception as e:
            raise AttackGenException(f"Failed to load MITRE ATT&CK data: {str(e)}")
    
    async def _load_local_data(self) -> bool:
        """Load data from local JSON files"""
        try:
            data_files = {
                'techniques': self.local_data_path / 'techniques.json',
                'tactics': self.local_data_path / 'tactics.json',
                'software': self.local_data_path / 'software.json',
                'groups': self.local_data_path / 'groups.json',
                'relationships': self.local_data_path / 'relationships.json'
            }
            
            # Check if all files exist
            for file_path in data_files.values():
                if not file_path.exists():
                    return False
            
            # Load all data
            for key, file_path in data_files.items():
                with open(file_path, 'r', encoding='utf-8') as f:
                    setattr(self, key, json.load(f))
            
            return True
            
        except Exception:
            return False
    
    async def _download_and_cache_data(self) -> None:
        """Download MITRE ATT&CK data and cache locally"""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.mitre_data_url) as response:
                    if response.status == 200:
                        # FIX: Use text() then parse JSON manually
                        text_content = await response.text()
                        try:
                            data = json.loads(text_content)
                            self._parse_and_cache_data(data)
                        except json.JSONDecodeError as e:
                            raise AttackGenException(f"Invalid JSON in MITRE data: {e}")
                    else:
                        raise AttackGenException(f"HTTP {response.status} from MITRE repository")
                        
        except asyncio.TimeoutError:
            raise AttackGenException("Timeout downloading MITRE data")
        except Exception as e:
            raise AttackGenException(f"Error downloading MITRE data: {str(e)}")

    
    def _parse_and_cache_data(self, data: Dict[str, Any]) -> None:
        """Parse downloaded STIX data and cache to local files"""
        objects = data.get('objects', [])
        
        # Parse different object types
        techniques_data = {}
        tactics_data = {}
        software_data = {}
        groups_data = {}
        relationships_data = {}
        
        for obj in objects:
            obj_type = obj.get('type')
            
            if obj_type == 'attack-pattern':
                # This is a technique
                technique_id = self._extract_technique_id(obj)
                if technique_id:
                    techniques_data[technique_id] = {
                        'id': technique_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactics': self._extract_tactics(obj),
                        'platforms': obj.get('x_mitre_platforms', []),
                        'data_sources': obj.get('x_mitre_data_sources', []),
                        'detection': obj.get('x_mitre_detection', ''),
                        'references': obj.get('external_references', [])
                    }
            
            elif obj_type == 'x-mitre-tactic':
                # This is a tactic
                tactic_id = self._extract_external_id(obj)
                if tactic_id:
                    tactics_data[tactic_id] = {
                        'id': tactic_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'short_name': obj.get('x_mitre_shortname', '')
                    }
            
            elif obj_type == 'malware' or obj_type == 'tool':
                # This is software
                software_id = self._extract_external_id(obj)
                if software_id:
                    software_data[software_id] = {
                        'id': software_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'type': obj_type,
                        'platforms': obj.get('x_mitre_platforms', []),
                        'aliases': obj.get('x_mitre_aliases', [])
                    }
            
            elif obj_type == 'intrusion-set':
                # This is a threat group
                group_id = self._extract_external_id(obj)
                if group_id:
                    groups_data[group_id] = {
                        'id': group_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'aliases': obj.get('aliases', [])
                    }
            
            elif obj_type == 'relationship':
                # This is a relationship
                relationships_data[obj.get('id', '')] = {
                    'source_ref': obj.get('source_ref', ''),
                    'target_ref': obj.get('target_ref', ''),
                    'relationship_type': obj.get('relationship_type', ''),
                    'description': obj.get('description', '')
                }
        
        # Cache to local files
        self._cache_to_files({
            'techniques': techniques_data,
            'tactics': tactics_data,
            'software': software_data,
            'groups': groups_data,
            'relationships': relationships_data
        })
        
        # Set instance variables
        self.techniques = techniques_data
        self.tactics = tactics_data
        self.software = software_data
        self.groups = groups_data
        self.relationships = relationships_data
    
    def _cache_to_files(self, data_dict: Dict[str, Dict]) -> None:
        """Cache parsed data to local JSON files"""
        try:
            # Create directory if it doesn't exist
            self.local_data_path.mkdir(parents=True, exist_ok=True)
            
            # Save each data type to separate files
            for key, data in data_dict.items():
                file_path = self.local_data_path / f'{key}.json'
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    
        except Exception as e:
            raise AttackGenException(f"Failed to cache MITRE data: {str(e)}")
    
    def _extract_technique_id(self, obj: Dict[str, Any]) -> Optional[str]:
        """Extract technique ID from STIX object"""
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def _extract_external_id(self, obj: Dict[str, Any]) -> Optional[str]:
        """Extract external ID from STIX object"""
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def _extract_tactics(self, obj: Dict[str, Any]) -> List[str]:
        """Extract tactics from technique object"""
        kill_chain_phases = obj.get('kill_chain_phases', [])
        tactics = []
        
        for phase in kill_chain_phases:
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))
        
        return tactics
    
    async def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """Get detailed information about a MITRE ATT&CK technique"""
        if not self._loaded:
            await self.load_attack_data()
        
        technique = self.techniques.get(technique_id, {})
        if not technique:
            return {
                'id': technique_id,
                'name': 'Unknown Technique',
                'description': 'No description available',
                'tactics': [],
                'platforms': [],
                'data_sources': [],
                'detection': '',
                'references': []
            }
        
        # Enhance with related information
        enhanced_technique = technique.copy()
        enhanced_technique['related_software'] = await self._get_related_software(technique_id)
        enhanced_technique['related_groups'] = await self._get_related_groups(technique_id)
        enhanced_technique['sub_techniques'] = await self._get_sub_techniques(technique_id)
        
        return enhanced_technique
    
    async def _get_related_software(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get software related to a technique"""
        related_software = []
        
        for rel_id, relationship in self.relationships.items():
            if (relationship['relationship_type'] == 'uses' and
                technique_id in relationship['target_ref']):
                
                software_id = self._extract_id_from_ref(relationship['source_ref'])
                software = self.software.get(software_id)
                if software:
                    related_software.append(software)
        
        return related_software
    
    async def _get_related_groups(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get threat groups that use a technique"""
        related_groups = []
        
        for rel_id, relationship in self.relationships.items():
            if (relationship['relationship_type'] == 'uses' and
                technique_id in relationship['target_ref']):
                
                group_id = self._extract_id_from_ref(relationship['source_ref'])
                group = self.groups.get(group_id)
                if group:
                    related_groups.append(group)
        
        return related_groups
    
    async def _get_sub_techniques(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get sub-techniques of a technique"""
        sub_techniques = []
        
        # Sub-techniques have IDs like T1234.001, T1234.002, etc.
        base_id = technique_id.split('.')[0]
        
        for tech_id, technique in self.techniques.items():
            if tech_id.startswith(f"{base_id}.") and tech_id != technique_id:
                sub_techniques.append(technique)
        
        return sub_techniques
    
    def _extract_id_from_ref(self, ref: str) -> str:
        """Extract ID from STIX reference"""
        # STIX refs look like: malware--abc123 or intrusion-set--def456
        return ref.split('--')[1] if '--' in ref else ref
    
    async def get_techniques_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """Get all techniques for a specific tactic"""
        if not self._loaded:
            await self.load_attack_data()
        
        matching_techniques = []
        
        for tech_id, technique in self.techniques.items():
            if tactic.lower() in [t.lower() for t in technique.get('tactics', [])]:
                matching_techniques.append(technique)
        
        return matching_techniques
    
    async def get_techniques_by_platform(self, platform: str) -> List[Dict[str, Any]]:
        """Get all techniques for a specific platform"""
        if not self._loaded:
            await self.load_attack_data()
        
        matching_techniques = []
        
        for tech_id, technique in self.techniques.items():
            platforms = [p.lower() for p in technique.get('platforms', [])]
            if platform.lower() in platforms:
                matching_techniques.append(technique)
        
        return matching_techniques