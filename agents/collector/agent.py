# agents/collector/agent.py
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
from agents.collector.datasets.file_loader import FileDatasetLoader
from agents.collector.normalizers.pdf_normalizer import PDFDatasetNormalizer
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

        # Offline dataset loader (for PDF, JSON, CSV files)
        data_dir = config.get("offline_data_dir", "data/datasets")
        self.dataset_loader = FileDatasetLoader(data_dir)
        
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

            requested_sources = input_data.get("sources", list(self.sources_config.keys()))
            max_reports      = input_data.get("max_reports", 100)

            self.logger.info("Starting collection cycle",
                             sources=requested_sources,
                             max_reports=max_reports)

            all_raw_reports = []
            errors          = []

            # 1. Live CTI sources
            for source in requested_sources:
                try:
                    if source == "misp" and "misp" in self.sources_config:
                        reports = await self._collect_from_misp(max_reports)
                        all_raw_reports.extend(reports)

                    elif source == "taxii" and "taxii" in self.sources_config:
                        # TODO: implement TAXII client _collect_from_taxii
                        reports = await self._collect_from_taxii(max_reports)
                        all_raw_reports.extend(reports)

                    elif source == "opencti" and "opencti" in self.sources_config:
                        # TODO: implement OpenCTI client _collect_from_opencti
                        reports = await self._collect_from_opencti(max_reports)
                        all_raw_reports.extend(reports)

                except Exception as e:
                    msg = f"Collection from {source} failed: {e}"
                    self.logger.error(msg, source=source)
                    errors.append(msg)
                    self.stats["collection_errors"] += 1

            # 2. Offline datasets
            if self.sources_config.get("datasets", {}).get("enabled", False):
                try:
                    offline_raw = self.dataset_loader.load_pdf_events()
                    self.logger.info(f"Loaded {len(offline_raw)} offline PDF events")
                    all_raw_reports.extend(offline_raw)
                except Exception as e:
                    msg = f"Offline dataset load failed: {e}"
                    self.logger.error(msg)
                    errors.append(msg)
                    self.stats["collection_errors"] += 1

            # 3. Normalize all reports
            normalized_reports = []
            for raw in all_raw_reports:
                try:
                    # PDF-based events have 'content' key
                    if raw.get("content") is not None:
                        normalized = PDFDatasetNormalizer().normalize_event(raw)
                    else:
                        normalized = self.misp_normalizer.normalize_event(raw)
                    normalized_reports.append(normalized)

                except Exception as e:
                    msg = f"Normalization failed: {e}"
                    self.logger.error(msg)
                    errors.append(msg)
                    self.stats["normalization_errors"] += 1

            # 4. Update statistics
            self.stats["total_reports_collected"]   += len(all_raw_reports)
            self.stats["total_reports_normalized"]  += len(normalized_reports)
            indicators_count = sum(len(r.get("indicators", [])) for r in normalized_reports)
            self.stats["total_indicators_extracted"] += indicators_count
            self.stats["last_collection_time"]       = datetime.utcnow().isoformat()

            # 5. Prepare result
            result = {
                "agent_id": self.id,
                "status": "success",
                "timestamp": self.get_timestamp(),
                "collection_summary": {
                    "raw_reports_collected":   len(all_raw_reports),
                    "normalized_reports":      len(normalized_reports),
                    "total_indicators":        indicators_count,
                    "collection_errors":       len(errors)
                },
                "normalized_reports": normalized_reports,
                "errors": errors,
                "statistics": self.stats.copy()
            }

            self.set_status(AgentStatus.IDLE)
            self.logger.info("Collection cycle completed",
                             raw=len(all_raw_reports),
                             normalized=len(normalized_reports),
                             indicators=indicators_count,
                             errors=len(errors))
            return result

        except Exception as e:
            self.set_status(AgentStatus.ERROR, str(e))
            self.logger.error("Collection execution failed", error=str(e))
            raise CollectorException(f"Collection execution failed: {e}")
    
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
            List of raw MISP events (each with full Attributes, Tags, Objects)
        """
        if not self.misp_client:
            raise CollectorException("MISP client not initialized")
        
        try:
            misp_config = self.sources_config["misp"]
            days_back = misp_config.get("days_back", 1)
            
            self.logger.info("Collecting from MISP", 
                        days_back=days_back,
                        max_reports=max_reports)
            
            # 1. Get summary list (IDs) - synchronous call
            summary_list = self.misp_client.misp.search_index(
                published=True,
                timestamp=f"{days_back}d",
                limit=max_reports,
                pythonify=False
            )
            
            # 2. Fetch full event data for each ID
            full_events = []
            for ev in summary_list[:max_reports]:
                event_id = ev.get("Event", ev).get("id") or ev.get("id")
                full_resp = self.misp_client.misp.get_event(event_id, pythonify=False)
                full_events.append(full_resp)
            
            self.logger.info(f"Collected {len(full_events)} full events from MISP")
            return full_events
            
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
                ## PDF events from FileDatasetLoader have 'content' and 'metadata'
                if report.get("content") is not None:
                    normalized = PDFDatasetNormalizer().normalize_event(report)
                else:
                    # All other raw events go to the MISP normalizer
                    normalized = self.misp_normalizer.normalize_event(report)
                
                if normalized:
                    normalized_reports.append(normalized)
                    
            except Exception as e:
                self.logger.error(f"Failed to normalize report: {e}", 
                                report=report.get("metadata", report.get("Event", {})).get("id", "unknown"))
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
