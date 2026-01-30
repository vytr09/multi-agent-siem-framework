import asyncio
import os
import sys
import time
import logging
import uuid
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from core.siem_integration import SIEMIntegrator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("test_siem_isolation")

def load_config():
    load_dotenv()
    return {
        'splunk_host': os.getenv('SPLUNK_HOST', 'localhost'),
        'splunk_port': os.getenv('SPLUNK_PORT', '8089'),
        'splunk_user': os.getenv('SPLUNK_USER', 'admin'),
        'splunk_password': os.getenv('SPLUNK_PASSWORD'),
        'splunk_verify_ssl': False,
        
        'ssh_host': os.getenv('SSH_HOST', 'localhost'),
        'ssh_port': os.getenv('SSH_PORT', '22'),
        'ssh_user': os.getenv('SSH_USER'),
        'ssh_password': os.getenv('SSH_PASSWORD'),
        'ssh_key_path': os.getenv('SSH_KEY_PATH'),
        
        'indexing_wait_time': 15, # Reduced from 45s - checkpoint reset makes indexing faster
        'simulation_mode': False
    }

def test_siem_integration():
    logger.info("Starting SIEM Isolation Test...")
    config = load_config()
    
    if not config['splunk_password']:
         logger.error("SPLUNK_PASSWORD not found in env")
         return
         
    siem = SIEMIntegrator(config)
    
    # 1. Define Test Case (Simple Process Creation)
    # Using 'whoami' as it's standard and low noise/risk
    rule = {
        'id': str(uuid.uuid4()),
        'title': 'Test Rule - Whoami Execution',
        'description': 'Detects execution of whoami.exe',
        'logsource': {
            'category': 'process_creation',
            'product': 'windows'
        },
        'detection': {
            'selection': {
                'Image|endswith': '\\whoami.exe'
            },
            'condition': 'selection'
        },
        'tags': ['attack.t1033'],
        'level': 'low'
    }
    
    # 1. Health Check: Is Splunk receiving ANY data?
    logger.info("--- Health Check: Querying Splunk for ANY recent data ---")
    health_res = siem.splunk.execute_query("search index!=_internal | head 3", earliest='-15m')
    if health_res.get('status') == 'success':
        count = health_res.get('event_count', 0)
        results = health_res.get('results', [])
        if count > 0:
            logger.info(f"Splunk USER Data OK. Found {count} events.")
            for ev in results:
                logger.info(f"Sample Event Sourcetype: {ev.get('sourcetype')}, Index: {ev.get('index')}")
                logger.info(f"Event Keys: {list(ev.keys())}")
                if 'EventCode' in ev:
                    logger.info(f"EventCode: {ev['EventCode']}")
                if 'EventID' in ev:
                     logger.info(f"EventID: {ev['EventID']}")
        else:
            logger.warning("Splunk Health Warning: NO USER DATA found (only _internal logs likely). Check Forwarder.")
    else:
        logger.error(f"Splunk Health Check Failed: {health_res}")

    attack = {
        'id': 'test_attack_01',
        # Wrap in cmd.exe to force a proper child process spawn (SSH might optimize direct commands)
        'command': 'cmd.exe /c whoami /all',
        'description': 'Run whoami to trigger detection'
    }
    
    # Check Privileges
    logger.info("--- Checking Privileges ---")
    res_priv = siem.ssh.execute_command('whoami /priv')
    logger.info(f"Privileges:\n{res_priv.get('output', '')}")

    # Attempt to Enable Audit Policy
    logger.info("--- Attempting to Enable Process Creation Auditing ---")
    audit_cmd = 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable'
    res_audit = siem.ssh.execute_command(audit_cmd)
    logger.info(f"Enable Audit Result: {res_audit.get('output', '')}")
    if res_audit.get('error'):
        logger.error(f"Enable Audit Error: {res_audit.get('error')}")

    # Check Audit Policy Again
    logger.info("--- Checking Audit Policy ---")
    res = siem.ssh.execute_command('auditpol /get /category:"Detailed Tracking"')
    logger.info(f"Audit Policy:\n{res.get('output', '')}")
    
    # 2. Test Conversion Logic Explicitly
    logger.info("--- Testing Sigma to SPL Conversion ---")
    try:
        spl_query = siem._convert_sigma_to_spl(rule)
        logger.info(f"Generated SPL: {spl_query}")
        
        if not spl_query:
            logger.error("SPL conversion returned empty string!")
        elif "EventCode=4688" not in spl_query and "index=" not in spl_query:
             logger.warning("SPL query looks suspicious (missing EventCode or index)")
             
    except Exception as e:
        logger.error(f"Conversion failed: {e}")
        
    # 3. Test Full Verification (Attack -> Detection)
    logger.info("--- Testing Full Verification Loop ---")
    try:
        result = siem.verify_rule(rule, attack)
        
        logger.info(f"Verification Result Payload: {result}")
        if result.detected:
            logger.info("✅ SUCCESS: Attack detected!")
            logger.info(f"Events found: {result.events_found}")
        else:
            logger.error("❌ FAILURE: Attack NOT detected.")
            logger.info(f"Message: {result.message}")
            
            # DEBUG: Dump recent events to see what's happening
            logger.info("--- DEBUG: Fetching recent raw events (last 5 mins) ---")
            debug_query = 'search index=* sourcetype="WinEventLog:Security" EventCode=4688 | head 5'
            debug_res = siem.splunk.execute_query(debug_query, earliest='-5m')
            if debug_res.get('status') == 'success':
                 events = debug_res.get('results', [])
                 logger.info(f"Found {len(events)} recent 4688 events.")
                 for i, ev in enumerate(events):
                     # Print key fields
                     raw = ev.get('_raw', '')
                     image = ev.get('NewProcessName') or ev.get('Image') or 'N/A'
                     cmd = ev.get('ProcessCommandLine') or ev.get('CommandLine') or 'N/A'
                     logger.info(f"Event {i+1}: Image={image} Cmd={cmd}")
                     logger.info(f"Raw: {raw[:200]}...")
            else:
                 logger.error(f"Debug query failed: {debug_res}")

            # DEBUG: Check LOCAL Event Logs via SSH
            logger.info("--- DEBUG: Checking LOCAL Windows Event Logs ---")
            # Get last 3 events ID 4688
            local_evt_cmd = "wevtutil qe Security /q:\"*[System[(EventID=4688)]]\" /c:3 /f:text /rd:true"
            local_res = siem.ssh.execute_command(local_evt_cmd)
            logger.info(f"Local Event Log Output:\n{local_res.get('output', '')}")
            if local_res.get('error'):
                 logger.error(f"Local Event Log Error: {local_res.get('error')}")


            
    except Exception as e:
        logger.error(f"Verification loop execution failed: {e}")

if __name__ == "__main__":
    test_siem_integration()
