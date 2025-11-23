import os
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).resolve().parents[1] / '.env'
load_dotenv(env_path)

class Settings:
    """Centralized configuration settings"""
    
    # Project Paths
    BASE_DIR = Path(__file__).resolve().parents[1]
    DATA_DIR = BASE_DIR / "data"
    LOG_DIR = BASE_DIR / "logs"
    
    # Splunk Configuration
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "127.0.0.1")
    SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
    SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
    SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
    SPLUNK_VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"
    
    # SSH Configuration
    SSH_HOST = os.getenv("SSH_HOST", "127.0.0.1")
    SSH_PORT = int(os.getenv("SSH_PORT", "22"))
    SSH_USER = os.getenv("SSH_USER", "user")
    SSH_PASSWORD = os.getenv("SSH_PASSWORD", "")
    SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "")
    
    @classmethod
    def get_splunk_config(cls) -> Dict[str, Any]:
        return {
            'splunk_host': cls.SPLUNK_HOST,
            'splunk_port': cls.SPLUNK_PORT,
            'splunk_user': cls.SPLUNK_USER,
            'splunk_password': cls.SPLUNK_PASSWORD,
            'verify_ssl': cls.SPLUNK_VERIFY_SSL
        }
        
    @classmethod
    def get_ssh_config(cls) -> Dict[str, Any]:
        return {
            'ssh_host': cls.SSH_HOST,
            'ssh_port': cls.SSH_PORT,
            'ssh_user': cls.SSH_USER,
            'ssh_password': cls.SSH_PASSWORD,
            'ssh_key_path': cls.SSH_KEY_PATH
        }

settings = Settings()
