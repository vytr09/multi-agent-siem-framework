# agents/collector/clients/misp_client.py
"""
MISP client for collecting threat intelligence from MISP instances.
"""

import asyncio
from typing import Dict, Any, List
from datetime import datetime, timedelta
from agents.base.exceptions import MISPConnectionException
from pymisp import PyMISP


class MISPClient:
    """
    MISP client that connects to a real MISP instance to fetch CTI data.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize MISP client.
        
        Args:
            config: Configuration dictionary with MISP settings
        """
        self.url = config.get("url")
        self.api_key = config.get("api_key")
        self.verify_cert = config.get("verify_cert", True)
        self.published_only = config.get("published_only", True)
        self.days_back = int(config.get("days_back", 1))
        self.batch_size = int(config.get("batch_size", 1000))
        
        if not self.url or not self.api_key:
            raise MISPConnectionException(
                "MISP URL and API key are required. Set MISP_URL and MISP_API_KEY in .env",
                source_type="MISP",
                source_url=self.url or "not configured"
            )
        
        try:
            self.misp = PyMISP(self.url, self.api_key, ssl=self.verify_cert)
        except Exception as e:
            raise MISPConnectionException(
                f"PyMISP init failed: {e}",
                source_type="MISP",
                source_url=self.url
            )
    
    async def test_connection(self) -> bool:
        """Test connection to MISP server"""
        try:
            # minimal call: fetch server info or do a tiny search window
            _ = self.misp.search(controller="events", limit=1)
            return True
        except Exception:
            return False

    async def get_recent_events(self, days: int = None) -> List[Dict[str, Any]]:
        """
        Get recent MISP events.
        
        Args:
            days: Number of days back to fetch events
            
        Returns:
            List of MISP events
        """
        try:
            days_back = days or self.days_back
            
            # Method 1: Use search_index (works better)
            try:
                since = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
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


def create_misp_client(config: Dict[str, Any]) -> MISPClient:
    """
    Factory function to create MISP client.
    
    Args:
        config: MISP configuration
        
    Returns:
        MISPClient instance
    """
    return MISPClient(config)
