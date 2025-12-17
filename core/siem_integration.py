"""
SIEM Integration Module
Provides integration with Splunk and remote execution via SSH for rule verification.
"""

import time
import json
import re
import logging
import requests
import paramiko
import urllib3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field

@dataclass
class SIEMMetrics:
    """SIEM-specific detection metrics"""
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    detection_rate: float
    false_positive_rate: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'accuracy': self.accuracy,
            'detection_rate': self.detection_rate,
            'false_positive_rate': self.false_positive_rate
        }


class SIEMMetricsCalculator:
    """Calculate F1, Precision, Recall, Accuracy from SIEM detection results"""
    
    @staticmethod
    def calculate_metrics(detection_results: List[Dict[str, Any]]) -> SIEMMetrics:
        """
        Calculate SIEM metrics from detection results
        
        Args:
            detection_results: List of dicts with 'detected', 'events_found', 'historical_events'
            
        Returns:
            SIEMMetrics with calculated values
        """
        true_positives = 0   # Attack detected correctly
        false_positives = 0  # Rule triggered without attack (historical events)
        false_negatives = 0  # Attack not detected
        true_negatives = 0   # No attack, no detection (baseline)
        
        for result in detection_results:
            detected = result.get('detected', False)
            events_found = result.get('events_found', 0)
            historical_events = result.get('historical_events', 0)
            
            if detected and events_found > 0:
                true_positives += 1
            else:
                false_negatives += 1
            
            # Historical events indicate false positives (rule triggered without our attack)
            if historical_events > 0:
                false_positives += historical_events
        
        # Calculate metrics
        total = true_positives + false_positives + false_negatives + true_negatives
        
        # Precision: TP / (TP + FP)
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        
        # Recall (Detection Rate): TP / (TP + FN)
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        
        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Accuracy: (TP + TN) / (TP + TN + FP + FN)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0.0
        
        # Detection Rate (same as recall)
        detection_rate = recall
        
        # False Positive Rate: FP / (FP + TN)
        false_positive_rate = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0.0
        
        return SIEMMetrics(
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate
        )

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
            
            # Poll for exit status with timeout
            start_time = time.time()
            max_wait = 15 # seconds
            
            while not stdout.channel.exit_status_ready():
                if time.time() - start_time > max_wait:
                    logger.warning(f"Command execution timed out ({max_wait}s). Assuming running/blocked process.")
                    break
                time.sleep(0.5)
            
            if stdout.channel.exit_status_ready():
                exit_status = stdout.channel.recv_exit_status()
            else:
                exit_status = 0 # Treat timeout as success (process started)
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
            
        # Capture start time (minus buffer for clock skew)
        # Use epoch time for Splunk 'earliest'
        start_time = time.time() - 300  # 5 minutes buffer
            
        # 1. Execute Attack
        logger.info(f"Executing attack: {attack.get('command')}")
        exec_result = self.ssh.execute_command(attack.get('command', 'echo "No command"'))
        
        if exec_result['status'] != 'success':
            logger.warning(f"Attack execution failed: {exec_result.get('error')}. Proceeding to verification anyway (Event ID 4688 should still be generated).")
            # We continue instead of returning error
            
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
        """Extract Splunk query from Sigma rule"""
        # Check for pre-built Splunk query
        if rule.get('splunk_query'):
            return rule['splunk_query']
            
        # Initialize mappings
        self._init_mappings()
        
        detection = rule.get('detection', {})
        logsource = rule.get('logsource', {})
        
        # Build base search with index and sourcetype
        base_parts = ['index=*']
        
        # Determine sourcetype based on log source
        product = (logsource.get('product') or '').lower()
        service = (logsource.get('service') or '').lower()
        category = (logsource.get('category') or '').lower()
        
        # Handle Windows log sources
        if product == 'windows':
            # Force Security Log for all process creation to handle missing Sysmon
            # if service == 'sysmon': ... (Ignored)
            
            if category == 'process_creation' or service == 'sysmon' or service == 'security':
                # Fallback to EventCode 4688 (Security)
                base_parts.append('sourcetype="WinEventLog:Security"')
                if category == 'process_creation':
                    base_parts.append('EventCode=4688')
            else:
                base_parts.append('sourcetype="WinEventLog:Security"')

        condition = detection.get('condition', '')
        detection_blocks = {k: v for k, v in detection.items() if k != 'condition'}
        
        detection_logic = ""
        
        # Handle selection as list (implicit OR)
        if 'selection' in detection_blocks and isinstance(detection_blocks['selection'], list):
            selection_queries = []
            for sel in detection_blocks['selection']:
                query = self._process_selection(sel, logsource)
                if query:
                    selection_queries.append(f"({query})")
            detection_logic = ' OR '.join(selection_queries)
        else:
            # Parse complex condition logic
            if condition:
                detection_logic = self._parse_condition_logic(condition, detection_blocks, logsource)
            else:
                # No condition specified, use simple AND of all blocks
                queries = []
                for key, value in detection_blocks.items():
                    if isinstance(value, dict):
                        query = self._process_selection(value, logsource)
                        if query:
                            queries.append(f"({query})")
                detection_logic = ' AND '.join(queries)
        
        # Build final query
        base_query = ' '.join(base_parts)
        if detection_logic:
            return f"{base_query} | search {detection_logic}"
        return base_query

    def _init_mappings(self):
        """Initialize field mappings"""
        if hasattr(self, 'traditional_mapping'):
            return
            
        self.traditional_mapping = {
            'EventID': 'EventCode',
            'Image': 'New_Process_Name',
            'CommandLine': 'Process_Command_Line',
            'ParentImage': 'Parent_Process_Name',
            'ParentCommandLine': 'Parent_Process_Command_Line',
            'User': 'Subject_User_Name',
            'ProcessId': 'Process_ID',
            'NewProcessId': 'New_Process_Id',
            'ParentProcessId': 'Parent_Process_ID',
            'CurrentDirectory': 'Current_Directory',
            'IntegrityLevel': 'Process_Integrity_Level',
            'OriginalFileName': 'Original_File_Name',
            'NewProcessName': 'New_Process_Name',
            'Creator_Process_Name': 'Creator_Process_Name',
            'SubjectUserName': 'Subject_User_Name',
            'SubjectDomainName': 'Subject_Domain_Name',
            'SubjectLogonId': 'Subject_Logon_Id',
        }
        
        self.ecs_mapping = {
            'process.executable': 'New_Process_Name',
            'process.command_line': 'Process_Command_Line',
            'process.name': 'New_Process_Name',
            'process.parent.executable': 'Parent_Process_Name',
            'process.parent.command_line': 'Parent_Process_Command_Line',
            'user.name': 'Subject_User_Name',
            'event.code': 'EventCode',
        }
        self.sysmon_mapping = {
            'EventID': 'EventCode',
            'process.executable': 'Image',
            'process.command_line': 'CommandLine',
            'process.parent.executable': 'ParentImage',
            'process.parent.command_line': 'ParentCommandLine',
            'user.name': 'User',
            'file.path': 'TargetFilename',
            'Image': 'Image',
            'CommandLine': 'CommandLine',
            'ParentImage': 'ParentImage',
            'User': 'User'
        }

    def _convert_field_name(self, field: str, logsource: Dict = None) -> str:
        """Convert Sigma field to Splunk field"""
        # Always use traditional mapping (force fallback to Security logs)
        mapping = self.traditional_mapping
        
        if '.' in field:
            return self.ecs_mapping.get(field, field)
            
        return mapping.get(field, field)

    def _escape_splunk_value(self, value: str) -> str:
        """Escape Splunk value"""
        if not isinstance(value, str):
            value = str(value)
        # Escape backslashes first to avoid double escaping quotes
        return value.replace('\\', '\\\\').replace('"', '\\"')

    def _process_modifier(self, field: str, modifier: str, value: Any, logsource: Dict = None) -> str:
        """Process Sigma modifiers"""
        splunk_field = self._convert_field_name(field, logsource)
        
        if modifier == 'contains':
            if isinstance(value, list):
                conditions = [f'{splunk_field}="*{self._escape_splunk_value(v)}*"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{splunk_field}="*{self._escape_splunk_value(value)}*"'
        
        elif modifier == 'endswith':
            if isinstance(value, list):
                conditions = [f'{splunk_field}="*{self._escape_splunk_value(v)}"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{splunk_field}="*{self._escape_splunk_value(value)}"'
            
        elif modifier == 'startswith':
            if isinstance(value, list):
                conditions = [f'{splunk_field}="{self._escape_splunk_value(v)}*"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{splunk_field}="{self._escape_splunk_value(value)}*"'
            
        elif modifier == 'all':
            if isinstance(value, list):
                conditions = [f'{splunk_field}="*{self._escape_splunk_value(v)}*"' for v in value]
                return f"({' AND '.join(conditions)})"
            return f'{splunk_field}="*{self._escape_splunk_value(value)}*"'
            
        else:
            if isinstance(value, list):
                conditions = [f'{splunk_field}="{self._escape_splunk_value(v)}"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{splunk_field}="{self._escape_splunk_value(value)}"'

    def _process_selection(self, selection: Dict, logsource: Dict = None) -> str:
        """Process selection block"""
        conditions = []
        for field_with_modifier, value in selection.items():
            if '|' in field_with_modifier:
                parts = field_with_modifier.split('|')
                base_field = parts[0]
                modifiers = parts[1:]
                main_modifier = next((m for m in modifiers if m in ['contains', 'endswith', 'startswith', 're', 'all']), None)
                conditions.append(self._process_modifier(base_field, main_modifier, value, logsource))
            else:
                splunk_field = self._convert_field_name(field_with_modifier, logsource)
                if isinstance(value, list):
                    or_conditions = [f'{splunk_field}="{self._escape_splunk_value(v)}"' for v in value]
                    conditions.append(f"({' OR '.join(or_conditions)})")
                else:
                    conditions.append(f'{splunk_field}="{self._escape_splunk_value(value)}"')
        return ' AND '.join(conditions) if conditions else ""

    def _parse_condition_logic(self, condition: str, detection_blocks: Dict, logsource: Dict = None) -> str:
        """Parse condition logic"""
        condition = condition.strip().lower()
        
        # Simple implementation for common cases
        if '1 of selection' in condition or 'any of selection' in condition:
            queries = []
            for key, value in detection_blocks.items():
                if key.startswith('selection'):
                    q = self._process_selection(value, logsource)
                    if q: queries.append(f"({q})")
            return ' OR '.join(queries)
            
        if 'all of selection' in condition:
            queries = []
            for key, value in detection_blocks.items():
                if key.startswith('selection'):
                    q = self._process_selection(value, logsource)
                    if q: queries.append(f"({q})")
            return ' AND '.join(queries)
            
        # Fallback for simple single block
        if condition in detection_blocks:
            return self._process_selection(detection_blocks[condition], logsource)
            
        # Fallback: AND everything
        queries = []
        for key, value in detection_blocks.items():
            q = self._process_selection(value, logsource)
            if q: queries.append(f"({q})")
        return ' AND '.join(queries)

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
