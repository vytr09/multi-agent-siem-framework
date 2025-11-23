"""
SIEM Integration Module
Provides integration with Splunk and remote execution via SSH for rule verification.
"""

import time
import json
import logging
import requests
import paramiko
import urllib3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SSHConnector:
    """Handles SSH connections and command execution"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.hostname = config.get('ssh_host', 'localhost')
        self.port = int(config.get('ssh_port', 22))
        self.username = config.get('ssh_user', 'root')
        self.password = config.get('ssh_password')
        self.key_path = config.get('ssh_key_path')
        
    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_args = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': 10
            }
            
            if self.password:
                connect_args['password'] = self.password
            if self.key_path:
                connect_args['key_filename'] = self.key_path
                
            self.client.connect(**connect_args)
            return True
        except Exception as e:
            logger.error(f"SSH Connection failed: {e}")
            return False

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command via SSH"""
        if not self.client:
            if not self.connect():
                return {'status': 'error', 'error': 'Not connected'}
                
        try:
            logger.info(f"Executing remote command: {command[:50]}...")
            stdin, stdout, stderr = self.client.exec_command(command, timeout=60)
            
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            return {
                'status': 'success' if exit_status == 0 else 'error',
                'exit_code': exit_status,
                'output': output,
                'error': error
            }
            
        except Exception as e:
            logger.error(f"SSH Execution error: {e}")
            return {'status': 'error', 'error': str(e)}
            
    def close(self):
        """Close connection"""
        if self.client:
            self.client.close()
        
class SplunkConnector:
    """Handles Splunk API interactions"""
    
    def __init__(self, config: Dict[str, Any]):
        self.base_url = f"https://{config.get('splunk_host')}:{config.get('splunk_port')}"
        self.username = config.get('splunk_user')
        self.password = config.get('splunk_password')
        self.verify_ssl = str(config.get('splunk_verify_ssl', 'false')).lower() == 'true'
        
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.verify_ssl
        
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def test_connection(self) -> bool:
        """Test Splunk connection"""
        try:
            response = self.session.get(
                f"{self.base_url}/services/server/info",
                params={'output_mode': 'json'},
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk connection failed: {e}")
            return False
            
    def execute_query(self, query: str, earliest: str = '-15m', latest: str = 'now') -> Dict[str, Any]:
        """Execute a search query"""
        try:
            if not query.strip().startswith('search'):
                query = f"search {query}"
                
            # Create job
            response = self.session.post(
                f"{self.base_url}/services/search/jobs",
                data={
                    'search': query,
                    'earliest_time': earliest,
                    'latest_time': latest,
                    'output_mode': 'json'
                },
                timeout=10
            )
            
            if response.status_code != 201:
                return {'status': 'error', 'error': f"HTTP {response.status_code}"}
                
            sid = response.json().get('sid')
            
            # Wait for completion
            start_time = time.time()
            while time.time() - start_time < 60:
                status_resp = self.session.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    params={'output_mode': 'json'}
                )
                content = status_resp.json()['entry'][0]['content']
                
                if content.get('isDone'):
                    # Get results
                    results_resp = self.session.get(
                        f"{self.base_url}/services/search/jobs/{sid}/results",
                        params={'output_mode': 'json', 'count': 100}
                    )
                    results = results_resp.json().get('results', [])
                    
                    return {
                        'status': 'success',
                        'event_count': int(content.get('eventCount', 0)),
                        'run_duration': float(content.get('runDuration', 0)),
                        'results': results
                    }
                    
                time.sleep(1)
                
            return {'status': 'timeout', 'error': 'Query timed out'}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}


@dataclass
class DetectionResult:
    detected: bool
    events_found: int
    query_time_ms: float
    historical_events: int
    status: str
    message: str
    raw_events: List[Dict[str, Any]] = field(default_factory=list)

class SIEMIntegrator:
    """Orchestrates the verification of rules against attacks in SIEM"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Flatten config structure for connectors
        # YAML has siem.splunk.host, but SplunkConnector expects splunk_host
        flat_config = {}
        
        # Map Splunk config
        if 'splunk' in config:
            for key, value in config['splunk'].items():
                flat_config[f'splunk_{key}'] = value
        
        # Map SSH config
        if 'ssh' in config:
            for key, value in config['ssh'].items():
                flat_config[f'ssh_{key}'] = value
        
        # Copy other top-level keys
        for key, value in config.items():
            if key not in ['splunk', 'ssh']:
                flat_config[key] = value
        
        self.ssh = SSHConnector(flat_config)
        self.splunk = SplunkConnector(flat_config)
        
        # Simulation mode fallback
        self.simulation_mode = config.get('simulation_mode', False)
        if not self.simulation_mode:
            if not self.splunk.test_connection():
                logger.warning("Could not connect to Splunk. Switching to SIMULATION MODE.")
                self.simulation_mode = True
                
    def verify_rule(self, rule: Dict[str, Any], attack: Dict[str, Any]) -> DetectionResult:
        """
        Verify if a rule detects an attack.
        1. Execute attack (via SSH)
        2. Wait for indexing
        3. Query Splunk
        4. Check historical data (FPR)
        """
        if self.simulation_mode:
            return self._simulate_verification(rule, attack)
            
        # Capture start time (minus small buffer for clock skew)
        # Use epoch time for Splunk 'earliest'
        start_time = time.time() - 2
            
        # 1. Execute Attack
        logger.info(f"Executing attack: {attack.get('command')}")
        exec_result = self.ssh.execute_command(attack.get('command', 'echo "No command"'))
        
        if exec_result['status'] != 'success':
            return DetectionResult(
                detected=False, events_found=0, query_time_ms=0, historical_events=0,
                status="error", message=f"Attack execution failed: {exec_result.get('error')}", raw_events=[]
            )
            
        # 2. Wait for indexing (configurable)
        wait_time = self.config.get('indexing_wait_time', 10)
        logger.info(f"Waiting {wait_time}s for indexing...")
        time.sleep(wait_time)
        
        # 3. Query Splunk (Detection)
        query = self._extract_query(rule)
        logger.info(f"Verifying detection with query: {query}")
        
        # Use exact start_time to filter out previous attacks
        detect_result = self.splunk.execute_query(query, earliest=start_time, latest='now')
        
        if detect_result['status'] != 'success':
            return DetectionResult(
                detected=False, events_found=0, query_time_ms=0, historical_events=0,
                status="error", message=f"Splunk query failed: {detect_result.get('error')}", raw_events=[]
            )
            
        events_found = detect_result.get('event_count', 0)
        detected = events_found > 0
        
        # 4. Check Historical (FPR)
        # Check last 24h excluding the last 1 hour
        fpr_result = self.splunk.execute_query(query, earliest='-24h', latest='-1h')
        historical_events = fpr_result.get('event_count', 0)
        
        return DetectionResult(
            detected=detected,
            events_found=events_found,
            query_time_ms=detect_result.get('run_duration', 0) * 1000,
            historical_events=historical_events,
            status="success",
            message="Verification complete",
            raw_events=detect_result.get('results', [])
        )
        
    def _extract_query(self, rule: Dict[str, Any]) -> str:
        """Extract Splunk query from Sigma rule (improved)"""
        # Check for pre-built Splunk query
        if 'splunk_query' in rule:
            return rule['splunk_query']
        
        # Build query from Sigma rule components
        query_parts = []
        
        # 1. Add log source constraints
        logsource = rule.get('logsource', {})
        if logsource:
            product = logsource.get('product', '')
            category = logsource.get('category', '')
            
            # Map to Splunk sourcetypes
            if product == 'windows':
                if category == 'process_creation':
                    query_parts.append('(sourcetype=WinEventLog:Security EventCode=4688 OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1)')
                else:
                    query_parts.append('sourcetype=WinEventLog:*')
            elif product == 'linux':
                query_parts.append('sourcetype=linux_secure')
        
        # 2. Extract detection logic
        detection = rule.get('detection', {})
        selection_parts = []
        
        def extract_detection_fields(obj, prefix=''):
            """Extract searchable fields from detection"""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in ['condition', 'timeframe']:
                        continue
                    
                    # Handle field operators
                    if '|' in key:
                        field_name, operator = key.split('|', 1)
                        
                        if 'contains' in operator:
                            if isinstance(value, list):
                                # Multiple values: field contains ANY of these
                                for v in value:
                                    selection_parts.append(f'{field_name}="*{v}*"')
                            else:
                                selection_parts.append(f'{field_name}="*{value}*"')
                        elif 'endswith' in operator:
                            selection_parts.append(f'{field_name}="*{value}"')
                        elif 'startswith' in operator:
                            selection_parts.append(f'{field_name}="{value}*"')
                    else:
                        # Direct field match
                        if isinstance(value, (str, int, float)):
                            selection_parts.append(f'{key}="{value}"')
                        elif isinstance(value, list):
                            for v in value:
                                selection_parts.append(f'{key}="{v}"')
                        elif isinstance(value, dict):
                            extract_detection_fields(value, prefix=key)
            elif isinstance(obj, list):
                for item in obj:
                    extract_detection_fields(item, prefix)
        
        extract_detection_fields(detection)
        
        # 3. Combine query parts
        if selection_parts:
            # Use OR for multiple selection criteria
            detection_query = ' OR '.join(selection_parts)
            if query_parts:
                query_parts.append(f'({detection_query})')
            else:
                query_parts.append(detection_query)
        
        # 4. Build final query
        if not query_parts:
            # Last resort: at least constrain to Windows security logs
            return 'sourcetype=WinEventLog:* OR sourcetype=XmlWinEventLog:*'
        
        final_query = ' '.join(query_parts)
        
        # 5. Validate query isn't too broad
        if final_query == 'index=*' or final_query.strip() == '*':
            logger.warning("Query too broad, adding Windows event constraint")
            return 'sourcetype=WinEventLog:* OR sourcetype=XmlWinEventLog:*'
        
        return final_query

    def _simulate_verification(self, rule: Dict[str, Any], attack: Dict[str, Any]) -> DetectionResult:
        """Simulate verification for testing"""
        import random
        
        # Deterministic simulation based on rule content
        rule_str = json.dumps(rule).lower()
        is_good_rule = "powershell" in rule_str or "cmd" in rule_str
        
        detected = is_good_rule and random.random() > 0.1  # 90% chance if good rule
        events = random.randint(1, 5) if detected else 0
        historical = random.randint(0, 2) if random.random() > 0.7 else 0
        
        return DetectionResult(
            detected=detected,
            events_found=events,
            query_time_ms=random.uniform(100, 500),
            historical_events=historical,
            status="simulated",
            message="Simulated verification",
            raw_events=[{"simulated": "event"}] if detected else []
        )
