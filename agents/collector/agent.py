"""
Collector Agent - Collects and normalizes CTI data from multiple sources.

This agent is responsible for:
1. Connecting to CTI sources (MISP, TAXII, OpenCTI)
2. Collecting threat intelligence reports
3. Normalizing data to standard format
4. Storing normalized data for processing by other agents
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from agents.base.agent import BaseAgent, AgentStatus
from agents.base.exceptions import CollectorException, MISPConnectionException
from agents.collector.clients.misp_client import create_misp_client
from agents.collector.normalizers.misp_normalizer import MISPNormalizer
from core.logging import get_agent_logger

class CollectorAgent(BaseAgent):
    """
    CTI Collector Agent for multi-source threat intelligence gathering.
    
    Collects threat intelligence from configured sources, normalizes the data,
    and prepares it for processing by downstream agents.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize the Collector Agent.
        
        Args:
            name: Agent name
            config: Configuration dictionary
        """
        super().__init__(name, config)
        
        # Initialize components
        self.misp_client = None
        self.misp_normalizer = MISPNormalizer()
        
        # Configuration
        self.sources_config = config.get("sources", {})
        self.collection_interval = config.get("interval", 300)  # 5 minutes
        self.batch_size = config.get("batch_size", 100)
        self.max_retries = config.get("max_retries", 3)
        
        # Statistics
        self.stats = {
            "total_reports_collected": 0,
            "total_reports_normalized": 0,
            "total_indicators_extracted": 0,
            "last_collection_time": None,
            "collection_errors": 0,
            "normalization_errors": 0
        }
        
        # Initialize logger
        self.logger = get_agent_logger(f"collector_{name}", self.id)
    
    async def start(self) -> None:
        """Start the collector agent"""
        await super().start()
        
        try:
            # Initialize CTI clients
            await self._initialize_clients()
            
            self.logger.info("Collector Agent started successfully", 
                           sources=list(self.sources_config.keys()),
                           interval=self.collection_interval)
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, f"Failed to start: {str(e)}")
            raise CollectorException(f"Failed to start Collector Agent: {str(e)}")
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute collection cycle.
        
        Args:
            input_data: Input parameters (can specify sources, filters, etc.)
            
        Returns:
            Collection results with statistics
        """
        try:
            self.set_status(AgentStatus.RUNNING)
            self.update_last_activity()
            
            # Parse input parameters
            requested_sources = input_data.get("sources", list(self.sources_config.keys()))
            force_collection = input_data.get("force", False)
            max_reports = input_data.get("max_reports", 100)
            
            self.logger.info("Starting collection cycle", 
                           sources=requested_sources,
                           force=force_collection,
                           max_reports=max_reports)
            
            # Collect from all requested sources
            all_collected_reports = []
            collection_errors = []
            
            for source in requested_sources:
                try:
                    if source == "misp" and source in self.sources_config:
                        reports = await self._collect_from_misp(max_reports)
                        all_collected_reports.extend(reports)
                        
                    elif source == "taxii" and source in self.sources_config:
                        # TODO: Implement TAXII collection
                        self.logger.warning("TAXII collection not implemented yet")
                        
                    else:
                        self.logger.warning(f"Unknown or unconfigured source: {source}")
                        
                except Exception as e:
                    error_msg = f"Collection from {source} failed: {str(e)}"
                    self.logger.error(error_msg, source=source, error=str(e))
                    collection_errors.append(error_msg)
                    self.stats["collection_errors"] += 1
            
            # Normalize collected reports
            normalized_reports = []
            if all_collected_reports:
                normalized_reports = await self._normalize_reports(all_collected_reports)
            
            # Update statistics
            self.stats["total_reports_collected"] += len(all_collected_reports)
            self.stats["total_reports_normalized"] += len(normalized_reports)
            self.stats["last_collection_time"] = datetime.utcnow().isoformat()
            
            # Calculate total indicators
            total_indicators = sum(
                len(report.get("indicators", [])) 
                for report in normalized_reports
            )
            self.stats["total_indicators_extracted"] += total_indicators
            
            # Prepare results
            result = {
                "agent_id": self.id,
                "status": "success",
                "timestamp": self.get_timestamp(),
                "collection_summary": {
                    "sources_processed": requested_sources,
                    "raw_reports_collected": len(all_collected_reports),
                    "normalized_reports": len(normalized_reports),
                    "total_indicators": total_indicators,
                    "collection_errors": len(collection_errors)
                },
                "normalized_reports": normalized_reports,
                "errors": collection_errors,
                "statistics": self.stats.copy()
            }
            
            self.set_status(AgentStatus.IDLE)
            
            self.logger.info("Collection cycle completed", 
                           raw_reports=len(all_collected_reports),
                           normalized_reports=len(normalized_reports),
                           indicators=total_indicators,
                           errors=len(collection_errors))
            
            return result
            
        except Exception as e:
            self.set_status(AgentStatus.ERROR, str(e))
            self.logger.error("Collection execution failed", error=str(e))
            raise CollectorException(f"Collection execution failed: {str(e)}")
    
    def validate_input(self, data: Dict[str, Any]) -> bool:
        """
        Validate input data for collection.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Collection can work with empty input (uses defaults)
        if not isinstance(data, dict):
            return False
        
        # Validate sources if specified
        if "sources" in data:
            requested_sources = data["sources"]
            if not isinstance(requested_sources, list):
                return False
            
            # Check if requested sources are configured
            for source in requested_sources:
                if source not in self.sources_config:
                    self.logger.warning(f"Requested source not configured: {source}")
        
        return True
    
    async def _initialize_clients(self) -> None:
        """Initialize CTI source clients"""
        
        # Initialize MISP client if configured
        if "misp" in self.sources_config:
            misp_config = self.sources_config["misp"]
            use_mock = misp_config.get("use_mock", True)  # Default to mock for development
            
            self.misp_client = create_misp_client(misp_config, use_mock=use_mock)
            
            # Test connection
            if hasattr(self.misp_client, "test_connection"):
                connection_ok = await self.misp_client.test_connection()
                if not connection_ok:
                    raise MISPConnectionException("Failed to connect to MISP")
            
            self.logger.info("MISP client initialized", 
                           url=misp_config.get("url", "mock"),
                           mock=use_mock)
        
        # TODO: Initialize TAXII client
        if "taxii" in self.sources_config:
            self.logger.info("TAXII client initialization not implemented yet")
        
        # TODO: Initialize OpenCTI client  
        if "opencti" in self.sources_config:
            self.logger.info("OpenCTI client initialization not implemented yet")
    
    async def _collect_from_misp(self, max_reports: int = 100) -> List[Dict[str, Any]]:
        """
        Collect reports from MISP source.
        
        Args:
            max_reports: Maximum number of reports to collect
            
        Returns:
            List of raw MISP events
        """
        if not self.misp_client:
            raise CollectorException("MISP client not initialized")
        
        try:
            misp_config = self.sources_config["misp"]
            days_back = misp_config.get("days_back", 1)
            
            self.logger.info("Collecting from MISP", 
                           days_back=days_back,
                           max_reports=max_reports)
            
            # Collect recent events
            events = await self.misp_client.get_recent_events(days=days_back)
            
            # Limit to max_reports
            if len(events) > max_reports:
                events = events[:max_reports]
                self.logger.info(f"Limited MISP results to {max_reports} events")
            
            self.logger.info(f"Collected {len(events)} events from MISP")
            return events
            
        except Exception as e:
            raise MISPConnectionException(f"MISP collection failed: {str(e)}")
    
    async def _normalize_reports(self, raw_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize raw reports to standard format.
        
        Args:
            raw_reports: List of raw reports from CTI sources
            
        Returns:
            List of normalized reports
        """
        normalized_reports = []
        
        for report in raw_reports:
            try:
                # Determine source type and use appropriate normalizer
                # For now, assume all reports are from MISP
                normalized = self.misp_normalizer.normalize_event(report)
                
                if normalized:
                    normalized_reports.append(normalized)
                    
            except Exception as e:
                self.logger.error(f"Failed to normalize report: {str(e)}", 
                                report_id=report.get("Event", {}).get("id", "unknown"))
                self.stats["normalization_errors"] += 1
                continue
        
        self.logger.info(f"Normalized {len(normalized_reports)} out of {len(raw_reports)} reports")
        return normalized_reports
    
    async def run_continuous(self) -> None:
        """
        Run collector in continuous mode.
        
        Collects data at regular intervals until stopped.
        """
        self.logger.info("Starting continuous collection mode", 
                        interval=self.collection_interval)
        
        while self._is_running:
            try:
                # Execute collection cycle
                result = await self.execute({})
                
                # Log summary
                summary = result.get("collection_summary", {})
                self.logger.info("Continuous collection cycle completed",
                               reports=summary.get("normalized_reports", 0),
                               indicators=summary.get("total_indicators", 0))
                
                # Wait for next cycle
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in continuous collection: {str(e)}")
                # Wait a bit before retrying
                await asyncio.sleep(60)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get collector statistics"""
        return {
            "agent_info": {
                "id": self.id,
                "name": self.name,
                "status": self.status.value,
                "uptime_seconds": (
                    (datetime.utcnow() - self.start_time).total_seconds()
                    if self.start_time else 0
                )
            },
            "configuration": {
                "sources": list(self.sources_config.keys()),
                "collection_interval": self.collection_interval,
                "batch_size": self.batch_size
            },
            "statistics": self.stats.copy()
        }
