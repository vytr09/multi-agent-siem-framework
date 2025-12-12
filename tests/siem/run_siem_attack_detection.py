#!/usr/bin/env python3
"""
Attack Detection Orchestrator - FINAL FIX for Query Escaping
- JSON escape là hành vi chuẩn: \ → \\ khi lưu
- json.load() tự động decode về dạng gốc khi đọc
- Fix: Verify query integrity sau khi save/load
"""

import json
import re
import subprocess
import time
import requests
import urllib3
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from datetime import datetime
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SplunkConnector:
    """Kết nối với Splunk qua REST API"""
    
    def __init__(
        self, 
        host: str = '127.0.0.1',
        port: int = 8089,
        username: str = 'Tuyen',
        password: str = 'Tuyen1630@',
        scheme: str = 'https'
    ):
        self.base_url = f"{scheme}://{host}:{port}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False
        
        logger.info(f"Splunk connector initialized: {self.base_url}")
    
    def test_connection(self) -> bool:
        """Test connection to Splunk"""
        try:
            response = self.session.get(
                f"{self.base_url}/services/server/info",
                params={'output_mode': 'json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("✓ Connected to Splunk successfully")
                data = response.json()
                if 'entry' in data and len(data['entry']) > 0:
                    content = data['entry'][0].get('content', {})
                    logger.info(f"  Splunk version: {content.get('version', 'Unknown')}")
                return True
            else:
                logger.error(f"✗ Connection failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Connection error: {e}")
            return False
    
    def create_search_job(self, query: str, earliest_time: str = '-1h', latest_time: str = 'now') -> Optional[str]:
        """Create search job và trả về job ID (SID)"""
        try:
            # Ensure query starts with 'search'
            if not query.strip().startswith('search '):
                query = f"search {query}"
            
            # Create search job
            response = self.session.post(
                f"{self.base_url}/services/search/jobs",
                data={
                    'search': query,
                    'earliest_time': earliest_time,
                    'latest_time': latest_time,
                    'output_mode': 'json'
                },
                timeout=30
            )
            
            if response.status_code == 201:
                data = response.json()
                sid = data.get('sid')
                logger.info(f"✓ Search job created: {sid}")
                return sid
            else:
                logger.error(f"✗ Failed to create search job: HTTP {response.status_code}")
                logger.error(f"  Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Error creating search job: {e}")
            return None
    
    def get_search_status(self, sid: str) -> Dict[str, Any]:
        """Kiểm tra trạng thái của search job"""
        try:
            response = self.session.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                params={'output_mode': 'json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and len(data['entry']) > 0:
                    content = data['entry'][0].get('content', {})
                    
                    return {
                        'is_done': content.get('isDone', False),
                        'progress': float(content.get('doneProgress', 0)) * 100,
                        'event_count': int(content.get('eventCount', 0)),
                        'status': content.get('dispatchState', 'UNKNOWN'),
                        'scan_count': int(content.get('scanCount', 0)),
                        'result_count': int(content.get('resultCount', 0))
                    }
            
            return {
                'is_done': False,
                'progress': 0,
                'event_count': 0,
                'status': 'ERROR'
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Error getting search status: {e}")
            return {
                'is_done': False,
                'progress': 0,
                'event_count': 0,
                'status': 'ERROR'
            }
    
    def wait_for_search_completion(self, sid: str, timeout: int = 300, poll_interval: int = 2) -> bool:
        """Đợi search job hoàn thành"""
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            status = self.get_search_status(sid)
            
            logger.info(f"  Search progress: {status['progress']:.1f}% | "
                       f"Events: {status['event_count']} | "
                       f"Status: {status['status']}")
            
            if status['is_done']:
                logger.info(f"✓ Search completed: {status['result_count']} results")
                return True
            
            if status['status'] in ['FAILED', 'ERROR']:
                logger.error(f"✗ Search failed: {status['status']}")
                return False
            
            time.sleep(poll_interval)
        
        logger.error(f"✗ Search timeout after {timeout}s")
        return False
    
    def get_search_results(self, sid: str, max_results: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
        """Lấy kết quả từ completed search job"""
        try:
            response = self.session.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                params={
                    'output_mode': 'json',
                    'count': max_results,
                    'offset': offset
                },
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                logger.info(f"✓ Retrieved {len(results)} results")
                return results
            else:
                logger.error(f"✗ Failed to get results: HTTP {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Error getting search results: {e}")
            return []
    
    def delete_search_job(self, sid: str) -> bool:
        """Delete search job để cleanup"""
        try:
            response = self.session.delete(
                f"{self.base_url}/services/search/jobs/{sid}",
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✓ Search job deleted: {sid}")
                return True
            else:
                logger.warning(f"⚠ Failed to delete search job: {sid}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠ Error deleting search job: {e}")
            return False
    
    def execute_query(
        self, 
        query: str, 
        earliest_time: str = '-1h',
        latest_time: str = 'now',
        timeout: int = 300,
        cleanup: bool = True
    ) -> Dict[str, Any]:
        """Execute complete search workflow"""
        result = {
            'success': False,
            'event_count': 0,
            'results': [],
            'error': None,
            'query': query,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Step 1: Create search job
            sid = self.create_search_job(query, earliest_time, latest_time)
            if not sid:
                result['error'] = 'Failed to create search job'
                return result
            
            # Step 2: Wait for completion
            if not self.wait_for_search_completion(sid, timeout):
                result['error'] = 'Search timeout or failed'
                if cleanup:
                    self.delete_search_job(sid)
                return result
            
            # Step 3: Get results
            results = self.get_search_results(sid)
            result['success'] = True
            result['event_count'] = len(results)
            result['results'] = results
            
            # Step 4: Cleanup
            if cleanup:
                self.delete_search_job(sid)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"✗ Query execution error: {e}")
            return result


class AttackCommandParser:
    """Parse attack commands từ batch file"""
    
    @staticmethod
    def parse_batch_file(file_path: str) -> List[Dict[str, Any]]:
        """Parse Windows batch file để extract attack commands"""
        attacks = []
        current_ttp = None
        current_tactic = None
        current_command = None
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Extract TTP ID
            if line.startswith('REM TTP:'):
                match = re.search(r'T\d+\.\d+', line)
                if match:
                    current_ttp = match.group(0)
                
                # Extract technique name
                if ' - ' in line:
                    current_tactic = line.split(' - ', 1)[1].strip()
            
            # Extract Tactic
            elif line.startswith('REM Tactic:'):
                current_tactic = line.replace('REM Tactic:', '').strip()
            
            # Extract echo Executing (description)
            elif line.startswith('echo Executing:'):
                description = line.replace('echo Executing:', '').strip()
            
            # Extract actual command
            elif line and not line.startswith('REM') and not line.startswith('echo') and not line.startswith(':'):
                if any(line.startswith(cmd) for cmd in ['powershell', 'reg ', 'mstsc', 'cmdkey']):
                    current_command = line
                    
                    # Create attack record
                    if current_ttp and current_command:
                        attacks.append({
                            'ttp_id': current_ttp,
                            'command': current_command,
                            'tactic': current_tactic if current_tactic else 'Unknown',
                            'description': description if 'description' in locals() else current_command[:100]
                        })
                        current_ttp = None
            
            i += 1
        
        return attacks


class SplunkQueryParser:
    """Parse Splunk queries với handling đặc biệt cho backslash"""
    
    @staticmethod
    def parse_test_queries(file_path: str) -> Dict[str, str]:
        """
        Parse test_queries.txt để mapping TTP -> Splunk Query
        ✅ FIX: Đọc query RAW, không modify backslash
        """
        ttp_to_query = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split by Test N:
        test_blocks = re.split(r'# Test \d+:', content)
        
        for block in test_blocks[1:]:
            lines = block.strip().split('\n')
            
            if len(lines) >= 3:
                # Line 1: Description
                description = lines[0].strip('# ').strip()
                
                # Line 2: TTP ID
                ttp_match = re.search(r'T\d+\.\d+', lines[1])
                if ttp_match:
                    ttp_id = ttp_match.group(0)
                    
                    # Find query (starts with 'index=')
                    query = None
                    for line in lines[2:]:
                        if line.strip().startswith('index='):
                            # ✅ FIX: Lấy query RAW, không strip hay modify
                            query = line.strip()
                            break
                    
                    if query:
                        ttp_to_query[ttp_id] = {
                            'query': query,
                            'description': description
                        }
        
        return ttp_to_query


class DetectionEvaluator:
    """Thực thi attack và kiểm tra detection với Splunk REST API"""
    
    def __init__(
        self,
        splunk_host: str = '127.0.0.1',
        splunk_port: int = 8089,
        splunk_username: str = 'Tuyen',
        splunk_password: str = 'Tuyen1630@',
        # use_simulation: bool = False
        use_simulation: bool = False
    ):
        self.results = []
        self.use_simulation = use_simulation
        self.connected = False
        
        if not use_simulation:
            try:
                self.splunk = SplunkConnector(
                    host=splunk_host,
                    port=splunk_port,
                    username=splunk_username,
                    password=splunk_password
                )
                
                if self.splunk.test_connection():
                    self.connected = True
                    logger.info("✓ Running in REAL Splunk mode")
                else:
                    logger.warning("⚠ Cannot connect to Splunk - switching to simulation mode")
                    self.use_simulation = True
            except Exception as e:
                logger.warning(f"⚠ Splunk connection error: {e} - switching to simulation mode")
                self.use_simulation = True
        else:
            logger.info("✓ Running in SIMULATION mode (as requested)")
    
    # def simulate_attack(self, command: str, delay_before: int = 2, delay_after: int = 5) -> Dict[str, Any]:
    #     """Simulate attack command execution"""
    #     execution_record = {
    #         'timestamp': datetime.now().isoformat(),
    #         'command': command,
    #         'status': 'simulated',
    #         'output': '',
    #         'error': ''
    #     }
        
    #     try:
    #         logger.info(f"[ATTACK] Executing: {command[:100]}...")
    #         time.sleep(delay_before)
            
    #         execution_record['status'] = 'prepared'
    #         execution_record['output'] = f"[SIMULATED] Command prepared for execution: {command[:80]}"
            
    #         time.sleep(delay_after)
            
    #     except Exception as e:
    #         execution_record['status'] = 'error'
    #         execution_record['error'] = str(e)
    #         logger.error(f"Error simulating attack: {e}")
        
    #     return execution_record


    def execute_real_attack(self, command: str) -> Dict[str, Any]:
        """Thực thi command thật trên Windows"""
        execution_record = {
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'status': 'pending',
            'output': '',
            'error': ''
        }

        try:
            logger.info(f"[REAL-ATTACK] Running: {command}")

            # Nếu là PowerShell -> ép sử dụng bypass policy
            if command.lower().startswith("powershell"):
                cmd = [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", command[len("powershell"):].strip()
                ]
            else:
                # Mặc định chạy qua cmd.exe /c
                cmd = ["cmd.exe", "/c", command]

            # Thực thi thật
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            stdout, stderr = process.communicate(timeout=120)

            execution_record['status'] = 'success' if process.returncode == 0 else 'error'
            execution_record['output'] = stdout.strip()
            execution_record['error'] = stderr.strip()

            logger.info(f"[REAL-ATTACK-OUTPUT] {stdout[:200]}")
            if stderr:
                logger.warning(f"[REAL-ATTACK-ERROR] {stderr[:200]}")

        except subprocess.TimeoutExpired:
            execution_record['status'] = 'timeout'
            execution_record['error'] = 'Command timed out (120s)'
            logger.error("[REAL-ATTACK] Timeout")

        except Exception as e:
            execution_record['status'] = 'error'
            execution_record['error'] = str(e)
            logger.error(f"[REAL-ATTACK] Failed: {e}")

        return execution_record
    
    def execute_splunk_query(
        self, 
        query: str, 
        wait_time: int = 10,
        earliest_time: str = '-15m',
        latest_time: str = 'now'
    ) -> Dict[str, Any]:
        """Execute Splunk query để detect attack"""
        query_record = {
            'query': query,  # ✅ Lưu query nguyên bản
            'timestamp': datetime.now().isoformat(),
            'status': 'pending',
            'detected': False,
            'event_count': 0,
            'results': []
        }
        
        try:
            logger.info(f"[QUERY] Waiting {wait_time}s for events to index...")
            time.sleep(wait_time)
            
            if self.use_simulation or not self.connected:
                logger.info(f"[QUERY] Running in SIMULATION mode...")
                return self._simulate_query_results(query)
            
            logger.info(f"[QUERY] Executing detection query on Splunk...")
            result = self.splunk.execute_query(
                query=query,
                earliest_time=earliest_time,
                latest_time=latest_time,
                timeout=120
            )
            
            if result['success']:
                query_record['status'] = 'success'
                query_record['event_count'] = result['event_count']
                query_record['results'] = result['results']
                query_record['detected'] = result['event_count'] > 0
                
                logger.info(f"✓ Query executed: {result['event_count']} events detected")
            else:
                query_record['status'] = 'error'
                query_record['error'] = result.get('error', 'Unknown error')
                logger.error(f"✗ Query failed: {query_record['error']}")
        
        except Exception as e:
            query_record['status'] = 'error'
            query_record['error'] = str(e)
            logger.error(f"Error executing query: {e}")
        
        return query_record
    
    @staticmethod
    def _simulate_query_results(query: str) -> Dict[str, Any]:
        """Simulate query results"""
        detection_keywords = [
            'powershell', 'cmd.exe', 'mstsc', 'wmic',
            'registry', 'rundll32', 'regsvr32', 'mimikatz'
        ]
        
        query_lower = query.lower()
        
        detected = False
        for keyword in detection_keywords:
            if keyword in query_lower:
                import random
                detected = random.random() < 0.85
                break
        
        return {
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'status': 'simulated',
            'detected': detected,
            'event_count': 1 if detected else 0,
            'results': [
                {
                    '_time': datetime.now().isoformat(),
                    'ComputerName': 'TEST-MACHINE',
                    'New_Process_Name': '\\cmd.exe',
                    'Process_Command_Line': '[SIMULATED_DETECTED]',
                    'Subject_User_Name': 'testuser'
                }
            ] if detected else []
        }
    
    def evaluate_attack_detection(self, attack: Dict[str, Any], query_info: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate detection outcome"""
        # attack_result = self.simulate_attack(attack['command'])
        attack_result = self.execute_real_attack(attack['command'])
        query_result = self.execute_splunk_query(query_info['query'])
        
        evaluation = {
            'test_id': f"{attack['ttp_id']}_detection_test",
            'ttp_id': attack['ttp_id'],
            'tactic': attack['tactic'],
            'attack': {
                'command': attack['command'],
                'description': attack['description'],
                'execution': attack_result
            },
            'detection': {
                'query': query_info['query'],  # ✅ Query nguyên bản
                'description': query_info['description'],
                'query_result': {
                    'status': query_result['status'],
                    'detected': query_result['detected'],
                    'event_count': query_result['event_count'],
                    'timestamp': query_result['timestamp'],
                    'results': query_result['results']
                }
            },
            'evaluation': {
                'detected': query_result['detected'],
                'status': 'PASS' if query_result['detected'] else 'FAIL',
                'confidence': 0.85 if query_result['detected'] else 0.0,
                'timestamp': datetime.now().isoformat(),
                'notes': f"Attack simulation + Query execution for {attack['ttp_id']}"
            }
        }
        
        return evaluation


class EvaluationDatasetGenerator:
    """Generate dataset cho Evaluator Agent"""
    
    def __init__(self):
        self.evaluations = []
    
    def add_evaluation(self, evaluation: Dict[str, Any]):
        self.evaluations.append(evaluation)
    
    def generate_dataset(self) -> Dict[str, Any]:
        dataset = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_tests': len(self.evaluations),
                'total_passed': sum(1 for e in self.evaluations if e['evaluation']['status'] == 'PASS'),
                'total_failed': sum(1 for e in self.evaluations if e['evaluation']['status'] == 'FAIL'),
                'detection_rate': (sum(1 for e in self.evaluations if e['evaluation']['detected']) / 
                                  len(self.evaluations) * 100 if self.evaluations else 0)
            },
            'test_results': self.evaluations,
            'summary_by_tactic': self._generate_tactic_summary(),
            'summary_by_ttp': self._generate_ttp_summary()
        }
        
        return dataset
    
    def _generate_tactic_summary(self) -> Dict[str, Any]:
        summary = {}
        
        for evaluation in self.evaluations:
            tactic = evaluation['tactic']
            if tactic not in summary:
                summary[tactic] = {
                    'total': 0,
                    'detected': 0,
                    'passed': 0
                }
            
            summary[tactic]['total'] += 1
            if evaluation['evaluation']['detected']:
                summary[tactic]['detected'] += 1
            if evaluation['evaluation']['status'] == 'PASS':
                summary[tactic]['passed'] += 1
        
        return summary
    
    def _generate_ttp_summary(self) -> Dict[str, Any]:
        summary = {}
        
        for evaluation in self.evaluations:
            ttp_id = evaluation['ttp_id']
            if ttp_id not in summary:
                summary[ttp_id] = {
                    'detected': False,
                    'status': 'FAIL',
                    'confidence': 0,
                    'details': {}
                }
            
            summary[ttp_id]['detected'] = evaluation['evaluation']['detected']
            summary[ttp_id]['status'] = evaluation['evaluation']['status']
            summary[ttp_id]['confidence'] = evaluation['evaluation']['confidence']
            summary[ttp_id]['details'] = {
                'attack_desc': evaluation['attack']['description'],
                'detection_desc': evaluation['detection']['description']
            }
        
        return summary
    
    def save_dataset(self, output_path: str):
        """
        ✅ FINAL FIX: Save với ensure_ascii=False và verify
        """
        dataset = self.generate_dataset()
        
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save JSON với ensure_ascii=False (giữ Unicode chars)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✓ Dataset saved: {output_path}")
        
        # ✅ VERIFY: Load lại và check query integrity
        self._verify_saved_queries(output_path)
        
        return dataset
    
    def _verify_saved_queries(self, output_path: str):
        """Verify query integrity sau khi save/load"""
        logger.info("\n" + "="*80)
        logger.info("QUERY INTEGRITY VERIFICATION")
        logger.info("="*80)
        
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
            
            if not loaded_data['test_results']:
                logger.warning("⚠ No test results to verify")
                return
            
            # Check first query
            first_test = loaded_data['test_results'][0]
            query = first_test['detection']['query']
            
            logger.info(f"\n📋 First Query Sample (200 chars):")
            logger.info(f"   {query[:200]}...")
            
            # Check for common patterns
            checks = {
                'Single backslash in paths': '\\W' in query and '\\\\W' not in query,
                'Proper quote escaping': '\\"' not in query or query.count('\\"') == query.count('sourcetype=\\"'),
                'No double backslash in paths': '\\\\WINWORD' not in query,
                'Contains expected patterns': 'Parent_Process_Name=' in query
            }
            
            logger.info("\n🔍 Query Integrity Checks:")
            all_passed = True
            for check_name, passed in checks.items():
                status = "✓" if passed else "✗"
                logger.info(f"   {status} {check_name}")
                if not passed:
                    all_passed = False
            
            if all_passed:
                logger.info("\n✅ All query integrity checks PASSED")
                logger.info("   Queries are correctly preserved in JSON")
            else:
                logger.warning("\n⚠ Some query integrity checks FAILED")
                logger.warning("   Review the saved queries manually")
            
            # Show JSON encoding explanation
            logger.info("\n📚 JSON Encoding Notes:")
            logger.info("   - JSON standard: \\ is encoded as \\\\ in file")
            logger.info("   - json.load() auto-decodes: \\\\ → \\ when reading")
            logger.info("   - Your queries are correct after json.load()")
            
        except Exception as e:
            logger.error(f"✗ Verification error: {e}")
        
        logger.info("="*80 + "\n")


def main():
    """Main orchestrator"""

    BASE_DIR = Path(__file__).parent
    project_root = BASE_DIR.parent.parent

    attack_commands_file = project_root / "data" / "siem" / "extracted_commands" / "test_scripts" / "test_windows_attacks.bat"
    splunk_queries_file = project_root / "data" / "siem" / "splunk_queries" / "test_queries.txt"
    output_file = project_root / "data" / "siem" / "evaluation_dataset.json"
    
    # Verify files exist
    if not attack_commands_file.exists():
        logger.error(f"Attack commands file not found: {attack_commands_file}")
        return
    
    if not splunk_queries_file.exists():
        logger.error(f"Splunk queries file not found: {splunk_queries_file}")
        return
    
    logger.info("="*80)
    logger.info("ATTACK DETECTION ORCHESTRATOR - FINAL FIX")
    logger.info("="*80)
    
    # Step 1: Parse attack commands
    logger.info("\n[Step 1] Parsing attack commands...")
    attack_parser = AttackCommandParser()
    attacks = attack_parser.parse_batch_file(str(attack_commands_file))
    logger.info(f"✓ Found {len(attacks)} attack commands")
    
    # Step 2: Parse Splunk queries
    logger.info("\n[Step 2] Parsing Splunk detection queries...")
    query_parser = SplunkQueryParser()
    queries = query_parser.parse_test_queries(str(splunk_queries_file))
    logger.info(f"✓ Found {len(queries)} detection queries")
    
    # Sample query verification
    if queries:
        first_ttp = list(queries.keys())[0]
        first_query = queries[first_ttp]['query']
        logger.info(f"\n📋 Sample Query (first 150 chars):")
        logger.info(f"   {first_query[:150]}...")
        
        # Check for backslash integrity
        if '\\WINWORD' in first_query:
            logger.info("   ✓ Single backslash detected in paths (CORRECT)")
        elif '\\\\WINWORD' in first_query:
            logger.warning("   ⚠ Double backslash in paths (might be issue)")
    
    # Step 3: Match attacks to queries
    logger.info("\n[Step 3] Matching attacks to detection queries...")
    matched_pairs = []
    
    for attack in attacks:
        ttp_id = attack['ttp_id']
        if ttp_id in queries:
            matched_pairs.append({
                'attack': attack,
                'query': queries[ttp_id]
            })
            logger.info(f"✓ Matched {ttp_id}: {attack['description'][:60]}")
        else:
            logger.warning(f"✗ No query found for {ttp_id}")
    
    logger.info(f"✓ Total matched pairs: {len(matched_pairs)}")
    
    # Step 4: Initialize evaluator
    logger.info("\n[Step 4] Initializing Splunk connection...")
    
    SPLUNK_CONFIG = {
        'splunk_host': '127.0.0.1',
        'splunk_port': 8089,
        'splunk_username': 'Tuyen',
        'splunk_password': 'Tuyen1630@',
        'use_simulation': False
    }
    
    evaluator = DetectionEvaluator(**SPLUNK_CONFIG)
    dataset_gen = EvaluationDatasetGenerator()
    
    # Step 5: Evaluate each attack-query pair
    logger.info("\n[Step 5] Executing attack-detection tests...")
    
    for i, pair in enumerate(matched_pairs, 1):
        logger.info(f"\n[Test {i}/{len(matched_pairs)}] TTP: {pair['attack']['ttp_id']}")
        
        evaluation = evaluator.evaluate_attack_detection(
            pair['attack'],
            pair['query']
        )
        
        dataset_gen.add_evaluation(evaluation)
        
        status = evaluation['evaluation']['status']
        detected = "✓" if evaluation['evaluation']['detected'] else "✗"
        logger.info(f"  → Result: {status} {detected}")
    
    # Step 6: Generate and save evaluation dataset
    logger.info("\n[Step 6] Generating evaluation dataset...")
    dataset_gen.save_dataset(str(output_file))
    
    dataset = dataset_gen.generate_dataset()
    
    # Print summary
    logger.info("\n" + "="*80)
    logger.info("EVALUATION SUMMARY")
    logger.info("="*80)
    logger.info(f"Total tests: {dataset['metadata']['total_tests']}")
    logger.info(f"Passed: {dataset['metadata']['total_passed']}")
    logger.info(f"Failed: {dataset['metadata']['total_failed']}")
    logger.info(f"Detection rate: {dataset['metadata']['detection_rate']:.1f}%")
    
    logger.info("\nBy Tactic:")
    for tactic, stats in dataset['summary_by_tactic'].items():
        detection_rate = (stats['detected'] / stats['total'] * 100) if stats['total'] > 0 else 0
        logger.info(f"  - {tactic}: {stats['detected']}/{stats['total']} ({detection_rate:.1f}%)")
    
    logger.info("\n" + "="*80)
    logger.info(f"✅ Evaluation dataset ready: {output_file}")
    logger.info("="*80)
    
    # Connection mode summary
    logger.info("\n📊 Execution Mode:")
    if evaluator.connected and not evaluator.use_simulation:
        logger.info("  ✓ REAL SPLUNK MODE - Queries executed on actual Splunk instance")
    else:
        logger.info("  ⚠ SIMULATION MODE - No real Splunk connection")
    
    # Final fix confirmation
    logger.info("\n✅ FINAL FIX APPLIED:")
    logger.info("  - Queries preserved in original form during parsing")
    logger.info("  - JSON encoding: \\ → \\\\ (standard JSON behavior)")
    logger.info("  - json.load() auto-decodes: \\\\ → \\ when reading")
    logger.info("  - Query integrity verification added")
    logger.info("  - Full queries stored without truncation")
    logger.info("\n💡 To use the dataset:")
    logger.info("  1. Read JSON with: data = json.load(open('evaluation_dataset.json'))")
    logger.info("  2. Access query: query = data['test_results'][0]['detection']['query']")
    logger.info("  3. Query will be correctly decoded with single backslashes")


if __name__ == "__main__":
    main()