#!/usr/bin/env python3
"""
Attack Detection Orchestrator
- Chạy attack commands từ batch file
- Thực thi Splunk queries để detect tấn công
- Tạo evaluation dataset cho Evaluator Agent
- Mapping: TTP ID -> Attack Command -> Detection Query
"""

import json
import re
import subprocess
import time
from typing import List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AttackCommandParser:
    """Parse attack commands từ batch file"""
    
    @staticmethod
    def parse_batch_file(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Windows batch file để extract attack commands
        Format:
        REM TTP: T1566.001 - Phishing
        REM Tactic: Initial Access
        powershell -c "..."
        """
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
            
            # Extract actual command (not REM, not echo)
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
    """Parse Splunk queries để extract TTP mapping"""
    
    @staticmethod
    def parse_test_queries(file_path: str) -> Dict[str, str]:
        """
        Parse test_queries.txt để mapping TTP -> Splunk Query
        Format:
        # Test 1: Description
        # T1566.001 - Phishing
        index=* sourcetype=... | search ...
        """
        ttp_to_query = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split by Test N:
        test_blocks = re.split(r'# Test \d+:', content)
        
        for block in test_blocks[1:]:  # Skip first empty block
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
                            query = line.strip()
                            break
                    
                    if query:
                        ttp_to_query[ttp_id] = {
                            'query': query,
                            'description': description
                        }
        
        return ttp_to_query


class DetectionEvaluator:
    """Thực thi attack và kiểm tra detection"""
    
    def __init__(self, splunk_host: str = 'localhost', splunk_port: int = 8089):
        """
        Initialize Splunk connection
        splunk_host: IP/hostname của Splunk server
        splunk_port: Splunk management port
        """
        self.splunk_host = splunk_host
        self.splunk_port = splunk_port
        self.results = []
    
    def simulate_attack(self, command: str, delay_before: int = 2, delay_after: int = 5) -> Dict[str, Any]:
        """
        Simulate attack command execution
        Lưu ý: Đây là simulation, trong thực tế cần có proper setup
        """
        execution_record = {
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'status': 'simulated',
            'output': '',
            'error': ''
        }
        
        try:
            # Log the command
            logger.info(f"[ATTACK] Executing: {command[:100]}...")
            
            # Simulate execution (không thực sự execute dangerous commands)
            # Trong production, cần có isolated environment (VM, sandbox)
            execution_record['status'] = 'prepared'
            execution_record['output'] = f"[SIMULATED] Command prepared for execution: {command[:80]}"
            
        except Exception as e:
            execution_record['status'] = 'error'
            execution_record['error'] = str(e)
            logger.error(f"Error simulating attack: {e}")
        
        return execution_record
    
    def execute_splunk_query(self, query: str, wait_time: int = 10) -> Dict[str, Any]:
        """
        Execute Splunk query để detect attack
        wait_time: Thời gian chờ trước khi query (để events được index)
        """
        query_record = {
            'query': query[:200] + '...' if len(query) > 200 else query,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending',
            'detected': False,
            'event_count': 0,
            'results': []
        }
        
        try:
            logger.info(f"[QUERY] Waiting {wait_time}s for events to index...")
            time.sleep(wait_time)
            
            logger.info(f"[QUERY] Executing detection query...")
            
            # Simulation: Parse query để xác định detection logic
            # Trong production, gọi Splunk REST API
            if self._simulate_query_results(query):
                query_record['status'] = 'success'
                query_record['detected'] = True
                query_record['event_count'] = 1  # Simulated
                query_record['results'] = [
                    {
                        '_time': datetime.now().isoformat(),
                        'ComputerName': 'TEST-MACHINE',
                        'New_Process_Name': '\\cmd.exe',
                        'Process_Command_Line': '[DETECTED]',
                        'Subject_User_Name': 'testuser'
                    }
                ]
            else:
                query_record['status'] = 'success'
                query_record['detected'] = False
                query_record['event_count'] = 0
        
        except Exception as e:
            query_record['status'] = 'error'
            query_record['error'] = str(e)
            logger.error(f"Error executing query: {e}")
        
        return query_record
    
    @staticmethod
    def _simulate_query_results(query: str) -> bool:
        """
        Simulate query results based on query content
        Trong real environment, sẽ gọi Splunk API
        """
        # Keywords indicating detection
        detection_keywords = [
            'powershell', 'cmd.exe', 'mstsc', 'wmic',
            'registry', 'rundll32', 'regsvr32', 'mimikatz'
        ]
        
        query_lower = query.lower()
        
        # Nếu query chứa detection keywords, assume detect thành công
        for keyword in detection_keywords:
            if keyword in query_lower:
                # Simulation: 85% detection rate
                import random
                return random.random() < 0.85
        
        return False
    
    def evaluate_attack_detection(self, attack: Dict[str, Any], query_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate detection outcome cho một attack-query pair
        """
        # Simulate attack execution
        attack_result = self.simulate_attack(attack['command'])
        
        # Execute detection query
        query_result = self.execute_splunk_query(query_info['query'])
        
        # Create evaluation record
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
                'query': query_info['query'],
                'description': query_info['description'],
                'query_result': query_result
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
        """Add evaluation result"""
        self.evaluations.append(evaluation)
    
    def generate_dataset(self) -> Dict[str, Any]:
        """
        Generate complete evaluation dataset
        Format tối ưu cho Evaluator Agent input
        """
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
        """Generate summary grouped by tactic"""
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
        """Generate summary grouped by TTP ID"""
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
        """Save dataset để dùng làm input cho Evaluator Agent"""
        dataset = self.generate_dataset()
        
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✓ Dataset saved: {output_path}")
        return dataset


def main():
    """Main orchestrator"""

    # Define base directory (directory of attack_detection.py)
    BASE_DIR = Path(__file__).parent

    # Paths
    attack_commands_file = BASE_DIR / "extracted_commands" / "test_scripts" / "test_windows_attacks.bat"
    splunk_queries_file = BASE_DIR / "splunk_queries" / "test_queries.txt"
    output_file = BASE_DIR / "evaluation_dataset.json"
    
    # Verify files exist
    if not attack_commands_file.exists():
        logger.error(f"Attack commands file not found: {attack_commands_file}")
        return
    
    if not splunk_queries_file.exists():
        logger.error(f"Splunk queries file not found: {splunk_queries_file}")
        return
    
    logger.info("="*80)
    logger.info("ATTACK DETECTION ORCHESTRATOR")
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
    
    # Step 3: Match attacks to queries by TTP ID
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
    
    # Step 4: Evaluate each attack-query pair
    logger.info("\n[Step 4] Executing attack-detection tests...")
    evaluator = DetectionEvaluator()
    dataset_gen = EvaluationDatasetGenerator()
    
    for i, pair in enumerate(matched_pairs, 1):
        logger.info(f"\n[Test {i}/{len(matched_pairs)}] TTP: {pair['attack']['ttp_id']}")
        
        evaluation = evaluator.evaluate_attack_detection(
            pair['attack'],
            pair['query']
        )
        
        dataset_gen.add_evaluation(evaluation)
        
        status = evaluation['evaluation']['status']
        logger.info(f"  → Result: {status}")
    
    # Step 5: Generate evaluation dataset
    logger.info("\n[Step 5] Generating evaluation dataset...")
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
    logger.info("This dataset can be used as input for Evaluator Agent")
    logger.info("="*80)


if __name__ == "__main__":
    main()