
import os
import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre_downloader")

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_DIR = "data/mitre_attack"
OUTPUT_FILE = "enterprise-attack.json"

def download_mitre_data():
    """Download MITRE Enterprise ATT&CK STIX data"""
    
    # Create directory if not exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created directory: {OUTPUT_DIR}")
        
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    
    logger.info(f"Downloading MITRE data from {MITRE_URL}...")
    
    try:
        response = requests.get(MITRE_URL, stream=True)
        response.raise_for_status()
        
        total_size = 0
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)
        
        logger.info(f"Download complete! Saved to {output_path} ({total_size / 1024 / 1024:.2f} MB)")
        
        # Verify JSON
        logger.info("Verifying JSON structure...")
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            objects = data.get("objects", [])
            techniques = [o for o in objects if o.get("type") == "attack-pattern"]
            logger.info(f"Verification successful: Found {len(techniques)} attack techniques in the dataset.")
            
    except Exception as e:
        logger.error(f"Failed to download MITRE data: {str(e)}")
        raise

if __name__ == "__main__":
    download_mitre_data()
