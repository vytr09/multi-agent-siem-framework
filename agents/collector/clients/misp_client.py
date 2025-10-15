# agents/collector/clients/misp_client.py
"""
Mock MISP client for development and testing.

This client simulates MISP API responses without requiring a real MISP instance.
Later this will be replaced with real MISP integration.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import random
from agents.base.exceptions import MISPConnectionException
from pymisp import PyMISP

class MockMISPClient:
    """
    Mock MISP client that generates realistic CTI data for development.
    
    Simulates the behavior of a real MISP client without external dependencies.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize mock MISP client.
        
        Args:
            config: Configuration dictionary with MISP settings
        """
        self.url = config.get("url", "http://mock-misp.local")
        self.api_key = config.get("api_key", "mock-api-key")
        self.verify_cert = config.get("verify_cert", True)
        self.days_back = config.get("days_back", 1)
        self.published_only = config.get("published_only", True)
        
        # Mock data templates
        self.threat_actors = [
            "APT29", "APT28", "Lazarus Group", "FIN7", "Carbanak", 
            "APT1", "Equation Group", "Shadow Brokers", "APT34", "APT40"
        ]
        
        self.malware_families = [
            "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Mimikatz",
            "PowerShell Empire", "Meterpreter", "RAT", "Banking Trojan", "Ransomware"
        ]
        
        self.attack_types = [
            "Spear Phishing", "Credential Harvesting", "Lateral Movement",
            "Data Exfiltration", "Persistence", "Privilege Escalation",
            "Command and Control", "Reconnaissance", "Initial Access"
        ]
    
    async def get_recent_events(self, days: int = None) -> List[Dict[str, Any]]:
        """
        Get recent MISP events (simulated).
        
        Args:
            days: Number of days back to fetch events
            
        Returns:
            List of mock MISP events
        """
        try:
            # Simulate network delay
            await asyncio.sleep(0.1)
            
            days = days or self.days_back
            mock_events = []
            
            # Generate 3-7 mock events
            num_events = random.randint(3, 7)
            
            for i in range(num_events):
                event = self._generate_mock_event(i)
                mock_events.append({"Event": event})
            
            return mock_events
            
        except Exception as e:
            raise MISPConnectionException(
                f"Failed to fetch MISP events: {str(e)}",
                source_type="MISP",
                source_url=self.url
            )
    
    def _generate_mock_event(self, event_index: int) -> Dict[str, Any]:
        """Generate a realistic mock MISP event"""
        
        # Random event data
        threat_actor = random.choice(self.threat_actors)
        malware = random.choice(self.malware_families)
        attack_type = random.choice(self.attack_types)
        
        # Generate timestamps
        created_time = datetime.utcnow() - timedelta(
            hours=random.randint(1, 48)
        )
        
        event_id = f"mock-event-{event_index + 1}"
        
        event = {
            "id": event_id,
            "uuid": f"event-uuid-{event_index + 1}",
            "info": f"{threat_actor} - {attack_type} Campaign Using {malware}",
            "date": created_time.strftime("%Y-%m-%d"),
            "timestamp": str(int(created_time.timestamp())),
            "published": random.choice([True, True, False]),  # 66% published
            "analysis": random.choice(["0", "1", "2"]),  # Initial, ongoing, complete
            "threat_level_id": str(random.randint(1, 4)),
            "org_id": "1",
            "orgc_id": "1",
            "distribution": str(random.randint(0, 3)),
            
            # Event description with CTI context
            "comment": f"""
            Threat Intelligence Report: {threat_actor} Campaign
            
            Overview: This campaign demonstrates {attack_type.lower()} techniques 
            attributed to {threat_actor}. The threat actor is leveraging {malware} 
            to establish persistence and exfiltrate sensitive data.
            
            TTPs Observed:
            - Initial Access: Spear phishing with malicious attachments
            - Execution: PowerShell script execution, WMI command execution
            - Persistence: Registry modification, scheduled task creation
            - Privilege Escalation: Token manipulation, UAC bypass
            - Defense Evasion: Process hollowing, code injection
            - Credential Access: LSASS dumping, credential harvesting
            - Discovery: Network enumeration, system information gathering
            - Lateral Movement: Remote desktop, Windows admin shares
            - Collection: Data staging, file compression
            - Exfiltration: Data transfer over C2 channel
            
            Indicators of Compromise:
            - Malicious domains used for C2 communication
            - File hashes of dropped malware samples
            - Registry keys created for persistence
            - Network signatures of C2 traffic
            """.strip(),
            
            # Attributes (IOCs)
            "Attribute": self._generate_mock_attributes(event_id),
            
            # Tags
            "Tag": [
                {"name": f"misp-galaxy:threat-actor=\"{threat_actor}\""},
                {"name": f"misp-galaxy:malware=\"{malware}\""},
                {"name": f"attack-pattern:\"{attack_type}\""},
                {"name": "tlp:amber"},
                {"name": "type:OSINT"}
            ],
            
            # Related events
            "RelatedEvent": [],
            
            # Objects (malware, attack patterns, etc.)
            "Object": self._generate_mock_objects(threat_actor, malware)
        }
        
        return event
    
    def _generate_mock_attributes(self, event_id: str) -> List[Dict[str, Any]]:
        """Generate mock IOCs/attributes for an event"""
        
        attributes = []
        
        # Domain IOCs
        domains = [
            f"malicious-{random.randint(1000, 9999)}.com",
            f"c2-{random.randint(100, 999)}.net", 
            f"phishing-{random.randint(10, 99)}.org"
        ]
        
        for domain in domains:
            attributes.append({
                "id": f"attr-{len(attributes) + 1}",
                "event_id": event_id,
                "type": "domain",
                "category": "Network activity", 
                "value": domain,
                "to_ids": True,
                "comment": f"C2 domain used by threat actor",
                "timestamp": str(int(datetime.utcnow().timestamp()))
            })
        
        # File hash IOCs
        hashes = [
            f"sha256:{self._generate_fake_hash(64)}",
            f"md5:{self._generate_fake_hash(32)}",
            f"sha1:{self._generate_fake_hash(40)}"
        ]
        
        for hash_val in hashes:
            hash_type, hash_value = hash_val.split(":", 1)
            attributes.append({
                "id": f"attr-{len(attributes) + 1}",
                "event_id": event_id,
                "type": hash_type,
                "category": "Payload delivery",
                "value": hash_value,
                "to_ids": True, 
                "comment": f"Hash of malicious payload",
                "timestamp": str(int(datetime.utcnow().timestamp()))
            })
        
        # IP address IOCs
        ips = [
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        ]
        
        for ip in ips:
            attributes.append({
                "id": f"attr-{len(attributes) + 1}",
                "event_id": event_id,
                "type": "ip-dst",
                "category": "Network activity",
                "value": ip,
                "to_ids": True,
                "comment": "C2 server IP address", 
                "timestamp": str(int(datetime.utcnow().timestamp()))
            })
        
        return attributes
    
    def _generate_mock_objects(self, threat_actor: str, malware: str) -> List[Dict[str, Any]]:
        """Generate mock MISP objects"""
        
        objects = []
        
        # Malware object
        malware_obj = {
            "id": "obj-1",
            "name": "malware",
            "template_uuid": "malware-template-uuid",
            "description": f"Malware sample: {malware}",
            "meta-category": "file",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name", 
                    "value": malware
                },
                {
                    "type": "text",
                    "object_relation": "family",
                    "value": malware.split()[0] if " " in malware else malware
                }
            ]
        }
        objects.append(malware_obj)
        
        # Attack pattern object
        attack_obj = {
            "id": "obj-2", 
            "name": "attack-pattern",
            "template_uuid": "attack-pattern-template-uuid",
            "description": "MITRE ATT&CK technique",
            "meta-category": "misc",
            "Attribute": [
                {
                    "type": "text",
                    "object_relation": "name",
                    "value": "Spearphishing Attachment"
                },
                {
                    "type": "text", 
                    "object_relation": "id",
                    "value": "T1566.001"
                }
            ]
        }
        objects.append(attack_obj)
        
        return objects
    
    def _generate_fake_hash(self, length: int) -> str:
        """Generate fake hash for testing"""
        import string
        chars = string.hexdigits.lower()[:16]  # 0-9a-f
        return ''.join(random.choice(chars) for _ in range(length))
    
    async def test_connection(self) -> bool:
        """Test connection to MISP (always succeeds for mock)"""
        await asyncio.sleep(0.1)  # Simulate network delay
        return True

class RealMISPClient:
    def __init__(self, config: Dict[str, Any]):
        self.url = config.get("url")
        self.api_key = config.get("api_key")
        self.verify_cert = config.get("verify_cert", True)
        self.published_only = config.get("published_only", True)
        self.days_back = int(config.get("days_back", 1))
        self.batch_size = int(config.get("batch_size", 1000))
        try:
            self.misp = PyMISP(self.url, self.api_key, ssl=self.verify_cert)
        except Exception as e:
            raise MISPConnectionException(f"PyMISP init failed: {e}", source_type="MISP", source_url=self.url)
    async def test_connection(self) -> bool:
        try:
            # minimal call: fetch server info or do a tiny search window
            _ = self.misp.search(controller="events", limit=1)
            return True
        except Exception:
            return False

    async def get_recent_events(self, days: int = None) -> List[Dict[str, Any]]:
        """Get recent MISP events using proper method"""
        try:
            days_back = days or self.days_back
            
            # Method 1: Use search_index (works better)
            try:
                since = (datetime.utcnow() - timedelta(days=self.days_back)).isoformat()
                events = self.misp.search_index(
                    published=self.published_only,
                    timestamp=since,
                    limit=self.batch_size,
                    pythonify=False
                )
                
                if events and isinstance(events, list):
                    print(f"Found {len(events)} events using search_index")
                    return events
                    
            except Exception as e:
                print(f"search_index failed: {e}")
            
            # Method 2: Try simple search without date filter
            try:
                events = self.misp.search(
                    published=self.published_only,
                    limit=1000,
                    pythonify=False
                )
                
                if isinstance(events, list):
                    print(f"Found {len(events)} events using simple search")
                    return events
                elif isinstance(events, dict) and "response" in events:
                    events_list = events["response"]
                    print(f"Found {len(events_list)} events from response")
                    return events_list
                    
            except Exception as e:
                print(f"Simple search failed: {e}")
            
            # Method 3: Get all events (fallback)
            try:
                all_events = self.misp.search(pythonify=False, limit=100)
                if isinstance(all_events, list):
                    print(f"Found {len(all_events)} events using fallback")
                    return all_events
                    
            except Exception as e:
                print(f"Fallback failed: {e}")
            
            print("All search methods failed")
            return []
            
        except Exception as e:
            print(f"MISP fetch error: {e}")
            return []


# Factory function to choose client type
def create_misp_client(config: Dict[str, Any], use_mock: bool = True):
    """
    Factory function to create MISP client.
    
    Args:
        config: MISP configuration
        use_mock: If True, use mock client; if False, use real client
        
    Returns:
        MISP client instance
    """
    if use_mock:
        return MockMISPClient(config)
    else:
        return RealMISPClient(config)
